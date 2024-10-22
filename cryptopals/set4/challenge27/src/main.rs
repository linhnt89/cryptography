use aes;
use rand::{prelude::*, distributions::Alphanumeric};

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();
    let iv = key.clone();
    let pt = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16*3)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let cipher = encrypt(pt, key.as_bytes(), iv.as_bytes());
    let mut edited_cipher = cipher.iter().take(16).cloned().collect::<Vec<u8>>();
    edited_cipher.append(&mut vec![0u8; 16]);
    edited_cipher.append(&mut cipher.iter().take(16).cloned().collect::<Vec<u8>>());
    let error_pt = decrypt(&edited_cipher, key.as_bytes(), iv.as_bytes());
    let block_1 = error_pt.iter().by_ref().take(16).collect::<Vec<&u8>>();
    let block_3 = error_pt.iter().by_ref().skip(32).take(16).collect::<Vec<&u8>>();
    let break_key = block_1.iter().zip(block_3.iter())
        .map(|(&&a, &&b)| a^b).collect::<Vec<u8>>();
    assert_eq!(key.as_bytes(), break_key);
}

fn encrypt(input: Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let pt = aes::padding(input, 16);
    aes::cbc_encrypt(&pt, key, iv, &aes::AESKIND::AES128)
}

fn decrypt(cipher: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let pt = aes::cbc_decrypt(cipher, key, iv, &aes::AESKIND::AES128);
    aes::remove_padding(pt)
}
