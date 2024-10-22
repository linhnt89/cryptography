use std::collections::HashMap;
use rand::{prelude::*, distributions::Alphanumeric};
use aes;

fn main() {
    let mut input = String::new();
    (0..3).into_iter().for_each(|_| input.push_str("YELLOW SUBMARINE"));
    let mut cnt = 0;
    for _ in 0..1000 {
        let (cipher, dice) = oracle_encryption(input.as_bytes());
        if dice == guess_ecb_or_cbc(cipher)  {
            cnt += 1;
        }          
    }
    println!("Number of pass = {}", cnt);
}

fn append(input: &[u8]) -> Vec<u8> {
    let append_len = thread_rng().gen_range(5u8..=10u8);
    let mut append_vec = vec![append_len; append_len as usize];
    let mut new_vec = append_vec.clone();
    new_vec.append(&mut input.clone().to_vec());
    new_vec.append(&mut append_vec);
    new_vec
}

fn oracle_encryption(input: &[u8]) -> (Vec<u8>, u8) {
    let cipher;
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();
    let t = aes::AESKIND::AES128;
    let append_input = append(input);
    let padded_input = aes::padding(append_input, 16);
    // println!("append input = {:02x?}", &append_input);
    // println!("key = {:02x?}", &key);
    let dice = thread_rng().gen_range(0u8..2u8);
    if dice == 1 {
        println!("ECB encryption");
        cipher = aes::ecb_encrypt(&padded_input, key.as_bytes(), &t);
    } else {
        let iv = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect::<String>();    
        // println!("iv = {:02x?}", &iv);
        println!("CBC encryption");
        cipher = aes::cbc_encrypt(&padded_input, key.as_bytes(), iv.as_bytes(), &t);
    }
    // println!("cipher = {:02x?}", cipher);
    (cipher, dice)
}

fn guess_ecb_or_cbc(cipher: Vec<u8>) -> u8 {
    let mut is_ecb = 0u8;
    let mut cipher_iter = cipher.into_iter();
    let mut blocks = HashMap::new();
    (0..).into_iter()
        .map(|_| cipher_iter.by_ref().take(16).collect::<Vec<u8>>())
        .take_while(|block| !block.is_empty())
        .for_each(|block| {
            let cnt = blocks.entry(block).or_insert(0u8);
            *cnt += 1;
            if *cnt > 1u8 {
                is_ecb = 1;
            }
        });
    is_ecb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append() {
        let input = vec![1, 2, 3, 4];
        println!("appended vec = {:?}", append(&input));
    }

    #[test]
    fn test_oracle_encryption() {
        oracle_encryption("YELLOW SUBMARINE".as_bytes());
    }
}