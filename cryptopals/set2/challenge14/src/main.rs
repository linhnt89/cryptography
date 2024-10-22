use std::collections::BTreeMap;
use rand::{prelude::*, distributions::Alphanumeric};
use aes;
use base64;

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect::<String>();
    let prefix_bytes: u32 = thread_rng().gen_range(0..255);
    let prefix = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(prefix_bytes as usize)
            .map(char::from)
            .collect::<String>();   
    let unknown_vec = base64::decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        ).unwrap();
    let block_size = find_block_size(key.as_bytes(), &unknown_vec, prefix.as_bytes());
    assert_eq!(16, block_size);
    assert_eq!(true, is_ecb(key.as_bytes(), &block_size, &unknown_vec, prefix.as_bytes()));
    let prefix_size = find_prefix_size(key.as_bytes(), &block_size, &unknown_vec, prefix.as_bytes());
    assert_eq!(prefix_bytes, prefix_size);
    let unknown_block = find_unknown_block(key.as_bytes(), &block_size, &prefix_size, &unknown_vec, prefix.as_bytes());
    assert_eq!(unknown_vec, unknown_block);
    println!("unknown block = {}", String::from_utf8(unknown_block).unwrap());
}

fn oracle_encryption(input: &[u8], key: &[u8], unknown_vec: &[u8], prefix: &[u8]) -> Vec<u8> {
    let mut append_input = prefix.clone().to_vec();
    append_input.append(&mut input.clone().to_vec());
    append_input.append(&mut unknown_vec.clone().to_vec());
    let padded_input = aes::padding(append_input, 16);
    aes::ecb_encrypt(&padded_input, key, &aes::AESKIND::AES128)
}

fn find_prefix_size(key: &[u8], block_size: &u32, unknown_vec: &[u8], prefix: &[u8]) -> u32 {
    let mut prefix_size = 0;
    'outer: for cnt in 1.. {
        let input = vec![b'A'; 2 * *block_size as usize + cnt as usize];
        let mut cipher = oracle_encryption(&input, key, unknown_vec, prefix).into_iter();
        let cipher_blocks = (0..).into_iter().map(|_| {
            cipher.by_ref().take(*block_size as usize).collect::<Vec<u8>>()
        }).take_while(|v| !v.is_empty())
        .collect::<Vec<Vec<u8>>>();
        for i in 1..cipher_blocks.len() {
            if cipher_blocks[i] == cipher_blocks[i-1] {
                prefix_size = (block_size * (i as u32 - 1)) - cnt;
                break 'outer;
            }
        }
    }
    prefix_size
}

fn find_block_size(key: &[u8], unknown_vec: &[u8], prefix: &[u8]) -> u32 {
    let mut m = BTreeMap::new();
    let mut block_size = 0u8;
    'outer: for cnt in 1u8.. {
        let input = vec![b'A'; cnt as usize];
        let val = m.entry(oracle_encryption(&input, key, unknown_vec, prefix).len()).or_insert(0u8);
        *val += 1;
        let mut prev_val = 0u8;
        for v in m.values() {
            if *v == prev_val && m.len() >= 3 {
                block_size = *v;
                break 'outer;
            }
            prev_val = *v;
        }
    }
    block_size as u32
}

fn is_ecb(key: &[u8], block_size: &u32, unknown_vec: &[u8], prefix: &[u8]) -> bool {
    let mut is_ecb = false;
    let mut m = BTreeMap::new();
    for cnt in 1u8.. {
        let input = vec![b'A'; cnt as usize];
        let cipher = oracle_encryption(&input, key, unknown_vec, prefix);
        let mut cipher_iter = cipher.into_iter();
        (0..).into_iter().map(|_| {
            cipher_iter.by_ref().take(*block_size as usize).collect::<Vec<u8>>()
        }).take_while(|block| !block.is_empty())
        .for_each(|block| {
            let val = m.entry(block).or_insert(0u8);
            *val += 1;
            if *val > 1u8 {
                is_ecb = true;
            }        
        });
        if is_ecb {
            break;
        }
    }
    is_ecb
}

fn find_unknown_block(key: &[u8], block_size: &u32, prefix_size: &u32, unknown_vec: &[u8], prefix: &[u8]) -> Vec<u8> {
    let mut all_unknown_blocks: Vec<u8> = Vec::new();
    let mut prev_known_block: Vec<u8> = Vec::new();
    let mut num_skipped_blocks = *prefix_size / *block_size;
    let added_for_prefix = *block_size - (*prefix_size % *block_size);
    if added_for_prefix != 0 {
        num_skipped_blocks += 1;
    }
    let default_skipped_blocks = num_skipped_blocks;
    while unknown_vec.len() > all_unknown_blocks.len() {
        // println!("prev_known_block = {}", String::from_utf8(prev_known_block.clone()).unwrap());
        // println!("block size * num blocks = {}", (*block_size*num_skipped_blocks) as usize);
        let mut cur_known_block: Vec<u8> = Vec::new();
        for i in (0..*block_size).rev() {
            let mut controlled_input: Vec<u8> = Vec::new();
            controlled_input.append(&mut vec![b'A'; added_for_prefix as usize]);
            if prev_known_block.is_empty() {
                controlled_input.append(&mut vec![b'A'; i as usize]);                
            } else {
                prev_known_block.iter().skip((*block_size-i) as usize)
                .for_each(|x| controlled_input.push(*x));                
            }
            // println!("controlled_input = {}", String::from_utf8(controlled_input.clone()).unwrap());
            let cipher_block = oracle_encryption(&controlled_input, key, unknown_vec, prefix)
                .into_iter().skip((*block_size*num_skipped_blocks) as usize)
                .take(*block_size as usize).collect::<Vec<u8>>();
            // println!("cipher = {:?}", oracle_encryption(&controlled_input, key, unknown_vec));
            // println!("cipher_block = {:?}", &cipher_block);
            for c in 0u8..=255u8 {
                let mut try_input = controlled_input.clone().to_vec();
                if !cur_known_block.is_empty() {
                    for x in cur_known_block.iter() {
                        try_input.push(*x);
                    }
                }
                try_input.push(c);
                // println!("try_input = {:?}", &try_input);
                // println!("try_input = {}", String::from_utf8(try_input.clone()).unwrap());
                let try_cipher_block = oracle_encryption(&try_input, key, unknown_vec, prefix)
                    .into_iter().skip((*block_size*default_skipped_blocks) as usize)
                    .take(*block_size as usize).collect::<Vec<u8>>();
                if try_cipher_block == cipher_block {
                    println!("{}", c);
                    cur_known_block.push(c);
                    break;
                }            
            }
        }
        num_skipped_blocks += 1;
        println!("cur_known_block = {}", String::from_utf8(cur_known_block.clone()).unwrap());
        prev_known_block = cur_known_block.clone();
        cur_known_block.iter().for_each(|x| all_unknown_blocks.push(*x));
        // println!("all blocks len = {}", all_unknown_blocks.len());
    }
    all_unknown_blocks = all_unknown_blocks.into_iter().take(unknown_vec.len()).collect::<Vec<u8>>();
    all_unknown_blocks
}