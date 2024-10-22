use std::env;
use core::fmt::Write;

fn hex_decode(s: String) -> Vec<u8> {
    let mut str_chars = s.chars();
    let chars_vec = (0..)
        .map(|_| str_chars.by_ref().take(2).collect::<String>())
        .take_while(|s| !s.is_empty())
        .collect::<Vec<String>>();
    let hex_vec = chars_vec.iter()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect::<Vec<u8>>();
    hex_vec
}

fn hex_xor(mut v1: Vec<u8>, mut v2: Vec<u8>) -> Vec<u8> {
    let mut vec_len = v1.len();
    if v1.len() < v2.len() {
        vec_len = v2.len();
    }
    let mut ret_vec: Vec<u8> = Vec::with_capacity(vec_len);
    while (v1.len() > 0) && (v2.len() > 0) {
        ret_vec.push(v1.pop().unwrap() ^ v2.pop().unwrap());
    }
    while v1.len() > 0 {
        ret_vec.push(v1.pop().unwrap() ^ 0);
    }
    while v2.len() > 0 {
        ret_vec.push(v2.pop().unwrap() ^ 0);
    }
    ret_vec.reverse();
    ret_vec
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Not enough arguments! Exit program!!!");
        return;
    }
    let v1 = hex_decode(args.pop().unwrap());
    let v2 = hex_decode(args.pop().unwrap());
    let hex_vec = hex_xor(v1, v2);
    let mut hex_str = String::with_capacity(2*hex_vec.len());
    for byte in hex_vec {
        write!(hex_str, "{:02x}", byte).unwrap();
    }
    println!("{:?}", hex_str);
    // println!("{:?}", String::from_utf8(hex_xor(v1, v2)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_xor() {
        let s1 = String::from("1c0111001f010100061a024b53535009181c");
        let s2 = String::from("686974207468652062756c6c277320657965");
        let ret = String::from("746865206b696420646f6e277420706c6179");
        assert_eq!(hex_xor(hex_decode(s1), hex_decode(s2)), hex_decode(ret));
    } 
}