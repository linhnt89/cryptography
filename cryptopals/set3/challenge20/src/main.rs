use std::io::{BufReader, BufRead};
use std::fs::File;
use std::collections::HashMap;
use base64;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use aes;

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let iv = [0u8; 16];
    let pts = read_file_decoded_base64();
    let ciphers = pts.iter()
        .map(|pt| aes::ctr_encrypt(pt, &key, &iv, 128, 
            aes::ENDIAN::BIG, &aes::AESKIND::AES128))
        .collect::<Vec<Vec<u8>>>();
    let mut arranged_ciphers = Vec::new();
    for i in 0.. {
        let mut tmp = Vec::new();
        ciphers.iter().for_each(|cipher| {
            match cipher.get(i) {
                Some(x) => tmp.push(*x),
                None => (),
            }
        });
        if tmp.is_empty() {
            break;
        } else {
            arranged_ciphers.push(tmp);
        }
    }
    let keystream = arranged_ciphers.iter()
        .map(|block| find_xored_char(block))
        .collect::<Vec<u8>>();
    ciphers.iter().for_each(|cipher| {
        let pt = cipher.iter().zip(keystream.iter())
            .map(|(&a, &b)| a^b)
            .collect::<Vec<u8>>();
        println!("{}", String::from_utf8(pt).unwrap());
    });
}

fn read_file_decoded_base64() -> Vec<Vec<u8>> {
    let f = File::open("C:/Programming/workspace/rust/cryptography/cryptopals/set3/challenge20/src/file.txt")
                        .expect("open the file won't fail");
    let reader = BufReader::new(f);
    reader.lines().map(|l| base64::decode(l.unwrap()).unwrap())
        .collect::<Vec<Vec<u8>>>()
}

fn find_xored_char(input_v: &[u8]) -> u8 {
    let mut coefficient = 0.0;
    let mut xored_char: u8 = 0;
    (0..=255 as u8).into_iter().for_each(|i| {
        let xored_v = input_v.iter().map(|b| b ^ i).collect::<Vec<u8>>();
        let new_coefficient = englishness(xored_v);
        if new_coefficient > coefficient {
            coefficient = new_coefficient;
            xored_char = i;
        }
    });
    xored_char
}

fn englishness(decrypted_u8_vec: Vec<u8>) -> f64 {
    let eng_expected_frq = HashMap::from([
        (0x45 as u8, 13.0), // E
        (0x54 as u8, 9.6), // T
        (0x41 as u8, 8.2), // A
        (0x4F as u8, 7.8), // O
        (0x49 as u8, 6.9), // I
        (0x4E as u8, 6.7), // N
        (0x48 as u8, 6.2), // H
        (0x53 as u8, 6.2), // S
        (0x52 as u8, 5.9), // R
        (0x44 as u8, 4.7), // D
        (0x4C as u8, 4.0), // L
        (0x43 as u8, 2.7), // C
        (0x4D as u8, 2.7), // M
        (0x55 as u8, 2.7), // U
        (0x57 as u8, 2.4), // W
        (0x46 as u8, 2.2), // F
        (0x47 as u8, 2.0), // G
        (0x59 as u8, 2.0), // Y
        (0x50 as u8, 1.9), // P
        (0x42 as u8, 1.5), // B
        (0x56 as u8, 0.97), // V
        (0x4B as u8, 0.81), // K
        (0x4A as u8, 0.16), // J
        (0x58 as u8, 0.15), // X
        (0x51 as u8, 0.11), // Q
        (0x5A as u8, 0.078), // Z
        (0x20 as u8, 0.01), // Space (additional to remove the wrong similar result)
    ]);

    // The Bhattacharyya coefficient is a fairly intuitive measure of
    // overlap of two different distributions: for each point in the distribution,
    // multiply the probability for each distribution together, then take the
    // square root. Sum all the probabilities together, and you get your
    // coefficient.
    let mut chr_cnt = HashMap::new();
    decrypted_u8_vec.iter().for_each(|&c| {
        let counter = chr_cnt.entry(c).or_insert(0.0);
        *counter += 1.0;
    });
    let mut coefficient = 0.0;
    for (c, cnt) in &chr_cnt {
        let expected_frq = match eng_expected_frq.get(&c.to_ascii_uppercase()) {
            Some(&f)   => f,
            None            => 0.0, 
        };
        coefficient += (expected_frq * cnt / decrypted_u8_vec.len() as f64).sqrt();
    }
    coefficient
}

