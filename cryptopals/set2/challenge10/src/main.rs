use std::fs;
use base64;
use aes;

fn main() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = vec![0u8; 16];
    let decrypted_str = String::from_utf8(
    aes::cbc_decrypt(&read_file_decoded_base64(), key, &iv, &aes::AESKIND::AES128)
        ).unwrap();
    println!("{}", decrypted_str);
}

fn read_file_decoded_base64() -> Vec<u8> {
    let s = fs::read_to_string(
        "C:/Programming/workspace/rust/cryptography/cryptopals/set2/challenge10/src/file.txt")
            .expect("read the file won't fail");
    base64::decode(s).unwrap()
}
