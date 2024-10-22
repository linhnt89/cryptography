use rand::{thread_rng, Rng, distributions::Alphanumeric, prelude::SliceRandom};
use aes;
use base64;

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let mut cnt = 0;
    (0..100).into_iter().for_each(|_| {
        let (cipher, iv) = encrypt(&key);
        if decrypt(&cipher, &key, &iv) {
            cnt += 1;
        }
    });
    assert_eq!(100, cnt);
}

fn encrypt(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let strs = [
            base64::decode("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=").unwrap(),
            base64::decode("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=").unwrap(),
            base64::decode("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==").unwrap(),
            base64::decode("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==").unwrap(),
            base64::decode("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl").unwrap(),
            base64::decode("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==").unwrap(),
            base64::decode("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==").unwrap(),
            base64::decode("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=").unwrap(),
            base64::decode("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=").unwrap(),
            base64::decode("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93").unwrap(),
    ];
    let iv = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let mut pt = strs.choose(&mut thread_rng()).unwrap().clone();
    pt = aes::padding(pt, 16);
    let cipher = aes::cbc_encrypt(&pt, key, &iv, &aes::AESKIND::AES128);
    (cipher, iv)
}

fn decrypt(cipher: &[u8], key: &[u8], iv: &[u8]) -> bool {
    let mut ret = true;
    let pt = aes::cbc_decrypt(cipher, key, iv, &aes::AESKIND::AES128);
    let last_byte = pt[pt.len() - 1];
    let checked_vec = pt.iter().rev().by_ref()
                            .take(last_byte as usize).cloned().collect::<Vec<u8>>();
    if checked_vec != vec![last_byte; last_byte as usize] {
        ret = false;
    }
    ret
}