use std::collections::HashMap;
use std::io::{BufReader, BufRead};
use std::fs::File;
use hex;

fn main() {
    let block_len = 8;
    let f = File::open(
        "C:/Programming/workspace/rust/cryptography/cryptopals/set1/challenge8/src/file.txt")
        .expect("open file won't fail");
    let reader = BufReader::new(f);
    let strings = reader.lines().map(|l| {
        hex::decode(l.unwrap()).unwrap()
    }).collect::<Vec<Vec<u8>>>();
    for s in strings {
        let mut s_iter = s.clone().into_iter();
        let s_blocks = (0..)
            .map(|_| s_iter.by_ref().take(block_len).collect::<Vec<u8>>())
            .take_while(|block| !block.is_empty())
            .collect::<Vec<Vec<u8>>>();
        let mut h: HashMap<Vec<u8>, u8> = HashMap::new();
        s_blocks.into_iter().for_each(|block| {
            let counter = h.entry(block).or_insert(0);
            *counter += 1;
        });
        h.iter().for_each(|(block, cnt)| {
            if *cnt > 1 {
                println!("best cnt = {}", &cnt);
                println!("best block = {:02x?}", &block);
                println!("best string = {:02x?}", &s);
            }
        });
    }
}
