use std::io::{BufReader, BufRead};
use std::fs::File;
use base64;
use std::collections::HashMap;

fn main() {
    let keys = find_key();
    decrypt_file(keys.get(2).unwrap());
}

fn hamming_distance(s1: &[u8], s2: &[u8]) -> u32 {
    let v = s1.iter().zip(s2.iter())
        .map(|(&b1,&b2)| b1 ^ b2)
        .collect::<Vec<u8>>();
    let d = v.into_iter()
                        .map(|b| b.count_ones()).collect::<Vec<u32>>();
    d.into_iter().sum()
}

fn read_file_decoded_base64() -> Vec<Vec<u8>> {
    let f = File::open("C:/Programming/workspace/rust/cryptography/cryptopals/set1/challenge6/src/file.txt")
                        .expect("open the file won't fail");
    let reader = BufReader::new(f);
    reader.lines().map(|l| base64::decode(l.unwrap()).unwrap())
        .collect::<Vec<Vec<u8>>>()
}

fn find_keysize() -> Vec<u8> {
    let input_v = read_file_decoded_base64().into_iter()
                                .flatten().collect::<Vec<u8>>();
    let input_bytes = input_v.as_slice();
    let mut distances = (2..=40).into_iter().map(|i| {
        let mut j = i;
        let mut v = Vec::new();
        loop {
            let s1 = match input_bytes.get(..j) {
                Some(s) => s,
                None => break,
            };
            let s2 = match input_bytes.get(j..j*2) {
                Some(s) => s,
                None => break,
            };
            j *= 2;
            let normalized_distance =  hamming_distance(s1, s2) as f64 / i as f64;
            v.push(normalized_distance);
        }
        let sum_distance: f64 = v.iter().sum();
        let normalized_distance = sum_distance / v.len() as f64;
        (i as u8, normalized_distance)
    }).collect::<Vec<(u8, f64)>>();
    // distances.iter().for_each(|d| println!("{:?}", d));
    distances.sort_by(|a,b| b.1.partial_cmp(&a.1).unwrap());
    // distances.iter().for_each(|d| println!("{:?}", d));
    // get keysize of 3 smallest distance value
    let length = distances.len();
    distances.into_iter().skip(length-3).map(|d| d.0).collect::<Vec<u8>>()
}

fn find_key() -> Vec<String> {
    let input_v = read_file_decoded_base64().into_iter()
                                .flatten().collect::<Vec<u8>>();
    let input_bytes = input_v.as_slice();
    let keys = find_keysize().into_iter().map(|ks| {
            let chunks = (0..ks as usize).into_iter()
                .map(|i| (0..ks as usize).into_iter()
                        .map(|j| input_bytes.get((j*ks as usize)+i).unwrap())
                        .collect::<Vec<&u8>>()
                        .into_iter().cloned().collect())
                .collect::<Vec<Vec<u8>>>();
            // println!("{:?}", chunks);
            let key = chunks.into_iter()
                .map(|v| find_xored_char(&v)).collect::<Vec<u8>>();
            String::from_utf8(key).unwrap()
        }).collect::<Vec<String>>();
    keys
}

fn find_xored_char(input_v: &[u8]) -> u8 {
    let mut coefficient = 0.0;
    let mut xored_char: u8 = 0;
    (1..=127 as u8).into_iter().for_each(|i| {
        let xored_v = input_v.iter().map(|b| b ^ i).collect::<Vec<u8>>();
        let new_coefficient = englishness(xored_v);
        if new_coefficient > coefficient {
            coefficient = new_coefficient;
            xored_char = i;
        }
    });
    xored_char
}

fn decrypt_file(key: &str) {
    let mut key_iter = key.bytes().cycle();
    let mut decrypted_str = String::new();
    read_file_decoded_base64().into_iter().for_each(|v| {
        let s = String::from_utf8(v.into_iter()
            .map(|b| b ^ key_iter.next().unwrap()).collect::<Vec<u8>>()).unwrap();
        decrypted_str.push_str(&s);
    });
    println!("{}", decrypted_str);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        let s1 = "this is a test".as_bytes();
        let s2 = "wokka wokka!!!".as_bytes();
        assert_eq!(37, hamming_distance(s1, s2));
    }

    #[test]
    fn test_read_file_decoded_base64() {
        let bytes = read_file_decoded_base64().into_iter().nth(0).unwrap()
                                            .into_iter().take(3).collect::<Vec<u8>>();
        assert_eq!(bytes, base64::decode("HUIf").unwrap());
        assert_eq!(bytes, vec![29, 66, 31]);
    }

    #[test]
    fn test_find_keysize() {
        println!("{:?}", find_keysize());
    }

    #[test]
    fn test_find_xored_char() {
        use hex;
        let s = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        assert_eq!(88, find_xored_char(&s));
    }

    #[test]
    fn test_find_key() {
        println!("{:?}", find_key());
    }

    #[test]
    fn test_decrypt_file() {
        // let k = String::from_utf8(vec![92, 85, 89, 12, 43]).unwrap() ;
        let k = String::from("Terminator X: Bring the noise");
        decrypt_file(&k);
    }

}