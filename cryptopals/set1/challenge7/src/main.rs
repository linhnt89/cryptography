use std::fs;
use base64;
use aes;

fn main() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let decrypted_str = String::from_utf8(
    aes::ecb_decrypt(&read_file_decoded_base64(), key, &aes::AESKIND::AES128)
        ).unwrap();
    println!("{}", decrypted_str);
}

fn read_file_decoded_base64() -> Vec<u8> {
    let s = fs::read_to_string(
        "C:/Programming/workspace/rust/cryptography/cryptopals/set1/challenge7/src/file.txt")
            .expect("read the file won't fail");
    base64::decode(s).unwrap()
}
