use aes;
use base64;

fn main() {
    let cipher = base64::decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    ).unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0u8; 16];
    let pt = aes::ctr_decrypt(&cipher, key, &iv, 64, 
        aes::ENDIAN::LITTLE, &aes::AESKIND::AES128);
    println!("{}", String::from_utf8(pt).unwrap());
}
