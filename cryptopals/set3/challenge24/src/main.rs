use std::time::{SystemTime, UNIX_EPOCH};

use mt19937;
use rand::{thread_rng, Rng, distributions::Alphanumeric};

fn main() {
    let mut pt = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(thread_rng().gen_range(1..1000))
        .map(u8::from)
        .collect::<Vec<u8>>();
    pt.append(&mut vec![b'A'; 14]);
    let seed: u16 = thread_rng().gen();
    let cipher = oracle(&pt, seed);
    for i in 0..u16::MAX {
        let break_pt = oracle(&cipher, i);
        let known_pt = break_pt.into_iter().rev().take(14).collect::<Vec<u8>>();
        if known_pt == vec![b'A'; 14] && i == seed {
            println!("seed = {}", i);
            break;
        }
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u16;
    let token = gen_token(now);
    assert_eq!(true, is_token_generated_by_mt19937(&token));
}

fn gen_token(seed: u16) -> Vec<u8> {
    let mut mt = mt19937::MT19937::seed(seed as u32);
    let token = (0..16).into_iter()
        .flat_map(|_| mt.rand().to_le_bytes().into_iter().collect::<Vec<u8>>())
        .collect::<Vec<u8>>();
    token
}

fn is_token_generated_by_mt19937(token: &[u8]) -> bool {
    let mut is_generated = false;
    for i in 0..u16::MAX {
        let mut mt = mt19937::MT19937::seed(i as u32);
        let checked_token = (0..16).into_iter()
        .flat_map(|_| mt.rand().to_le_bytes().into_iter().collect::<Vec<u8>>())
        .collect::<Vec<u8>>();
        if token == checked_token {
            is_generated = true;
            break;
        }
    }
    is_generated
}

fn oracle(pt: &[u8], seed: u16) -> Vec<u8> {
    let mut mt = mt19937::MT19937::seed(seed as u32);
    let mut ks = mt.rand().to_le_bytes();
    let mut idx = 0;
    let cipher = pt.iter().map(|b| {
        let x = b ^ ks[idx];
        if idx < 3 {
            idx += 1;
        } else {
            ks = mt.rand().to_le_bytes();
            idx = 0;
        }
        x
    }).collect::<Vec<u8>>();
    cipher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle() {
        let seed = 0x1234u16;
        let pt = vec![b'A'; 14];
        let cipher = oracle(&pt, seed);
        assert_eq!(pt, oracle(&cipher, seed));
    }
}