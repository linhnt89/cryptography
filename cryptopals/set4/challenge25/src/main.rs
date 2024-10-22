use std::io::{BufReader, BufRead};
use std::fs::File;
use base64;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use aes;

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let iv = vec![0u8; 16];
    let pt = read_file_decoded_base64();
    let cipher = aes::ctr_encrypt(&pt, &key, &iv, 128, 
        aes::ENDIAN::BIG, &aes::AESKIND::AES128);
    let num_blocks = cipher.len() / 16;
    let mut break_pt = Vec::new();
    for i in 0..num_blocks {
        let offset = i * 16;
        let newtext = vec![b'A'; 16];
        let cipher_block = edit(&newtext, &cipher, &key, offset)
            .into_iter().skip(offset).take(16).collect::<Vec<u8>>();
        let ks = cipher_block.into_iter()
            .zip(newtext.into_iter())
            .map(|(a,b)| a^b)
            .collect::<Vec<u8>>();
        cipher.iter().by_ref().skip(offset).take(16).cloned()
            .zip(ks.into_iter())
            .for_each(|(a,b)| break_pt.push(a^b));
    }
    assert_eq!(pt, break_pt);
}

fn read_file_decoded_base64() -> Vec<u8> {
    let f = File::open("C:/Programming/workspace/rust/cryptography/cryptopals/set4/challenge25/src/file.txt")
                        .expect("open the file won't fail");
    let reader = BufReader::new(f);
    reader.lines().flat_map(|l| base64::decode(l.unwrap()).unwrap())
        .collect::<Vec<u8>>()
}

fn edit(newtext: &[u8], cipher: &[u8], key: &[u8], offset: usize) -> Vec<u8> {
    let iv = vec![0u8; 16];
    let mut pt = aes::ctr_decrypt(cipher, key, &iv, 128, 
        aes::ENDIAN::BIG, &aes::AESKIND::AES128);
    for i in 0..newtext.len() {
        pt.insert(offset+i, newtext[i]);
    }
    aes::ctr_encrypt(&pt, key, &iv, 128, 
        aes::ENDIAN::BIG, &aes::AESKIND::AES128)
}