use aes;
use rand::{prelude::*, distributions::Alphanumeric};

#[derive(Debug)]
struct Cookie {
    email: String,
    uid: u32,
    role: String,
}

fn main() {
    // "email=" is 6 bytes => 10 more bytes for first block
    // "&uid=10&role=" is 13 bytes => 3 more bytes for last block
    // "admin" is 5, because AES ECB uses PKCS#7 padding 
    // => create cipher with padding "admin"+"0xB" for second block
    let mut input = String::from("linhnguyen");
    input.push_str("admin");
    let mut input_vec = input.into_bytes();
    input_vec.append(&mut vec![11u8; 11]);
    input_vec.append(&mut vec![0x31u8; 3]);
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();
    let cipher = encrypt_profile(
        &profile_for(&String::from_utf8_lossy(&input_vec)), 
        key.as_bytes());
    let mut cipher_iter = cipher.into_iter();
    let mut rearranged_cipher = Vec::new();
    let mut cipher_block1 = cipher_iter.by_ref().take(16).collect::<Vec<u8>>();
    let mut cipher_block2 = cipher_iter.by_ref().take(16).collect::<Vec<u8>>();
    let mut cipher_block3 = cipher_iter.by_ref().take(16).collect::<Vec<u8>>();
    rearranged_cipher.append(&mut cipher_block1);
    rearranged_cipher.append(&mut cipher_block3);
    rearranged_cipher.append(&mut cipher_block2);
    let cookie = Cookie {
        email: "linhnguyen111".to_string(),
        uid: 10,
        role: "admin".to_string(),
    };
    assert_eq!(cookie, decrypt_profile(&rearranged_cipher, key.as_bytes()));
    println!("{:?}", cookie);
}

fn parse(s: &str) -> Cookie {
    let v = s.split("&").collect::<Vec<&str>>();
    assert_eq!(3, v.len());
    let email = (v[0].split("=").collect::<Vec<&str>>())[1].to_string();
    let uid = u32::from_str_radix((v[1].split("=").collect::<Vec<&str>>())[1], 10).unwrap();
    let role = (v[2].split("=").collect::<Vec<&str>>())[1].to_string();
    Cookie {
        email,
        uid,
        role,
    }
}

fn profile_for(s: &str) -> String {
    if s.find("&").is_some() || s.find("=").is_some()  {
        panic!("input contains & or =");
    }
    let cookie = Cookie {
        email: s.to_string(),
        uid: 10,
        role: "user".to_string(),
    };        
    let mut s = String::new();
    s += "email=";
    s += cookie.email.as_str();
    s += "&uid=";
    s += cookie.uid.to_string().as_str();
    s += "&role=";
    s += cookie.role.as_str();
    s
}

impl PartialEq for Cookie {
    fn eq(&self, other: &Self) -> bool {
        return (&self.email == &other.email)
            && (&self.uid == &other.uid)
            && (&self.role == &other.role);
    }
}

fn encrypt_profile(input: &str, key: &[u8]) -> Vec<u8> {
    let padded_input = aes::padding(input.as_bytes().to_vec(), 16);
    aes::ecb_encrypt(&padded_input, key, &aes::AESKIND::AES128)
}

fn decrypt_profile(cipher: &[u8], key: &[u8]) -> Cookie {
    let mut cipher = aes::ecb_decrypt(cipher, key, &aes::AESKIND::AES128);
    cipher = aes::remove_padding(cipher);
    parse(&String::from_utf8(cipher).unwrap()) 
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let cookie = Cookie {
            email: "foo@bar.com".to_string(),
            uid: 10,
            role: "user".to_string(),
        };
        assert_eq!(cookie, parse("email=foo@bar.com&uid=10&role=user"));
    }

    #[test]
    fn test_profile_for() {
        assert_eq!("email=foo@bar.com&uid=10&role=user", profile_for("foo@bar.com"));   
    }
}