use std::env;
use core::fmt::Write;

const UPPER_CASE_OFFSET:u8  = 65; // ASCII A = 65, BASE64 A = 0
const LOWER_CASE_OFFSET:u8  = 71; // ASCII a = 97, BASE64 a = 26
const NUMBER_OFFSET:u8      = 4; // ASCII 0 = 48, BASE64 0 = 52
// ASCII + = 43, BASE64 + = 62
// ASCII / = 47, BASE64 / = 63
// ASCII = = 61, BASE64 = = padding

fn get_char_from_index(n: u8) -> Option<u8> {
    let ascii_index = match n {
        0..=25   => n + UPPER_CASE_OFFSET,
        26..=51  => n + LOWER_CASE_OFFSET,
        52..=61  => n - NUMBER_OFFSET,
        62      => 43,
        63      => 47,
        _       => return None,
    };
    Some(ascii_index)
}

fn get_index_from_char(n: u8) -> Option<u8> {
    let index = match n {
        65..=90   => n - UPPER_CASE_OFFSET,
        97..=122  => n - LOWER_CASE_OFFSET,
        48..=57   => n + NUMBER_OFFSET,
        43      => 62,
        47      => 63,
        _       => return None,
    };
    Some(index)
}

fn split(chunk: Vec<u8>) -> Vec<u8> {
    match chunk.len() {
        1 => vec![
            &chunk[0] >> 2,
            (&chunk[0] & 0x3) << 4,
        ],
        2 => vec![
            &chunk[0] >> 2,
            ((&chunk[0] & 0x3) << 4) | ((&chunk[1] & 0xF0) >> 4),
            (&chunk[1] & 0xF) << 2,
        ],
        3 => vec![
            &chunk[0] >> 2,
            ((&chunk[0] & 0x3) << 4) | ((&chunk[1] & 0xF0) >> 4),
            ((&chunk[1] & 0xF) << 2) | ((&chunk[2] & 0xC0) >> 6),
            &chunk[2] & 0x3F,
        ],
        _ => unreachable!(),
    }
}

fn join(chunk: Vec<u8>) -> Vec<u8> {
    match chunk.len() {
        2 => vec![
            ((&chunk[0] & 0x3F) << 2) | ((&chunk[1] & 0x30) >> 4),
        ],
        3 => vec![
            ((&chunk[0] & 0x3F) << 2) | ((&chunk[1] & 0x30) >> 4),
            ((&chunk[1] & 0x0F) << 4) | ((&chunk[2] & 0x3C) >> 2),
        ],
        4 => vec![
            ((&chunk[0] & 0x3F) << 2) | ((&chunk[1] & 0x30) >> 4),
            ((&chunk[1] & 0x0F) << 4) | ((&chunk[2] & 0x3C) >> 2),
            ((&chunk[2] & 0x03) << 6) | (&chunk[3] & 0x3F),
        ],
        _ => unreachable!(),
    }
}

fn encode(input_str: String) -> String {
    let mut hex_str_chars = input_str.chars();
    let sub_strs: Vec<String> = (0..)
        .map(|_| hex_str_chars.by_ref().take(2).collect::<String>())
        .take_while(|s| !s.is_empty())
        .collect();
    let nums_vec: Vec<u8> = sub_strs.into_iter()
        .map(|s| u8::from_str_radix(&s, 16).unwrap())
        .collect();
    let mut nums_vec_iter = nums_vec.into_iter();
    let nums_splitted_vec: Vec<u8> = (0..)
        .map(|_| nums_vec_iter.by_ref().take(3).collect::<Vec<u8>>())
        .take_while(|v| !v.is_empty())
        .flat_map(|v| split(v))
        .collect();
    let encoded_vec: Vec<u8> = nums_splitted_vec.into_iter()
        .map(|n| get_char_from_index(n).unwrap())
        .collect();
    String::from_utf8(encoded_vec).unwrap()
}

fn decode(input_str: String) -> String {
    let mut encoded_str_chars = input_str.chars()
        .map(|c| get_index_from_char(c as u8).unwrap())
        .collect::<Vec<u8>>()
        .into_iter();
    let encoded_sub_strs: Vec<Vec<u8>> = (0..)
        .map(|_| encoded_str_chars.by_ref().take(4).collect::<Vec<u8>>())
        .take_while(|v| !v.is_empty())
        .collect();
    let decoded_vec: Vec<u8> = encoded_sub_strs.into_iter()
        .flat_map(|v| join(v))
        .collect();
    let mut decoded_str = String::with_capacity(2*decoded_vec.len());
    for byte in decoded_vec {
        write!(decoded_str, "{:02x}", byte).unwrap();
    }
    decoded_str
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("No input! Exit program!!!");
        return;
    }
    let encoded_str = encode(args.pop().unwrap());
    println!("{:?}", encoded_str);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        let input_str = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let encoded_str = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(encode(input_str), encoded_str);
    }

    #[test]
    fn test_decode() {
        let decoded_str = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let input_str = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(decode(input_str), decoded_str);        
    }
}