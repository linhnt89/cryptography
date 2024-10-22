use std::{fs::File, io::{self, BufRead}, path::Path};
use std::collections::HashMap;

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

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() {
    // match read_lines("C:/Programming/workspace/rust/cryptography/cryptopals/s1_c4/src/file.txt") {
    //     Ok(_) => println!("OK"),
    //     Err(e) => println!("{}", e),
    // }
    if let Ok(lines) = read_lines("C:/Programming/workspace/rust/cryptography/cryptopals/set1/challenge4/src/file.txt") {
        let mut coefficient = 0.0;
        let mut xor_val: u8 = 0;
        // let mut encrypted_str = String::new();
        // let mut decrypted_str = String::new();
        let mut hex_u8_vec_final: Vec<u8> = Vec::new();
        let mut xored_u8_vec_final: Vec<u8> = Vec::new();
        for line in lines {
            if let Ok(hex_str) = line {
                let mut hex_str_chars = hex_str.chars();
                let hex_str_vec = (0..)
                    .map(|_| hex_str_chars.by_ref().take(2).collect::<String>())
                    .take_while(|s| !s.is_empty())
                    .collect::<Vec<String>>();
                let hex_u8_vec = hex_str_vec.iter()
                    .map(|s| u8::from_str_radix(s, 16).unwrap())
                    .collect::<Vec<u8>>();
                for i in 1..=127 as u8 {
                    let xored_u8_vec = hex_u8_vec.iter()
                        .map(|&n| n ^ i)
                        .collect::<Vec<u8>>();
                    let new_coefficient = englishness(xored_u8_vec.to_owned());
                    if new_coefficient > coefficient {
                        // encrypted_str = String::from_utf8_lossy(&hex_u8_vec);
                        // decrypted_str = tmp_str.to_owned();
                        hex_u8_vec_final = hex_u8_vec.to_owned();
                        xored_u8_vec_final = xored_u8_vec;
                        coefficient = new_coefficient;
                        xor_val = i;
                    }
                }
            }
        }
        println!("Encrypted string : {}", String::from_utf8_lossy(&hex_u8_vec_final));
        println!("Decrypted string : {} - coefficient : {} - xor value : {}", 
                    String::from_utf8_lossy(&xored_u8_vec_final), coefficient, xor_val as char);
    } else {
        println!("Cannot open the file!");
    }
}
