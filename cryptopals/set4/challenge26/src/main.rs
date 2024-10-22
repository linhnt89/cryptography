use aes;
use rand::{prelude::*, distributions::Alphanumeric};

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();
    let iv = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();
    let cipher = encrypt("<admin>true<", key.as_bytes(), iv.as_bytes());
    // 3 positions which need to be modified : 0, 6, 11
    for i in 0..cipher.len()-11 {
        let mut modified_cipher = cipher.clone();
        modified_cipher[i+0] ^= b'<' ^ b';';
        modified_cipher[i+6] ^= b'>' ^ b'=';
        modified_cipher[i+11] ^= b'<' ^ b';';
        if decrypt(&modified_cipher, key.as_bytes(), iv.as_bytes()) {
            println!("offset = {}", i);
            println!("logged in as admin");
            break;
        }                  
    }
}

fn encrypt(input: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
    if input.find(";").is_some() || input.find("=").is_some() {
        panic!("input contains wrong value");
    }
    let mut pt = "comment1=cooking%20MCs;userdata=".as_bytes().to_vec();
    pt.append(&mut input.clone().as_bytes().to_vec());
    pt.append(&mut ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes().to_vec());
    pt = aes::padding(pt, 16);
    aes::ctr_encrypt(&pt, key, iv, 64, 
        aes::ENDIAN::BIG, &aes::AESKIND::AES128)
}

fn decrypt(cipher: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let mut ret = false;
    let mut pt = aes::ctr_encrypt(cipher, key, iv, 64, 
        aes::ENDIAN::BIG, &aes::AESKIND::AES128);
    pt = aes::remove_padding(pt);
    let pt = String::from_utf8_lossy(&pt);
    if pt.find(";admin=true;").is_some() {
        ret = true;
    }
    ret
}