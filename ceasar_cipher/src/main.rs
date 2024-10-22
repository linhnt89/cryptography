// Support A-Z only

use std::env;

fn convert(n: u8, s: u8) -> u8 {
    // 90 = Z
    if (n + s) > 90 {
        n + s - 26
    } else {
        n + s
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("No input text!!! Exit program!");
        return;
    }
    for i in 1..25 {
        let ct_bytes_vec: Vec<Vec<u8>> = args.iter().skip(1)
            .map(|s| s.as_bytes().iter()
            .map(|&n| convert(n, i))
            .collect())
            .collect();
        let cipher_text_vec: Vec<String> = ct_bytes_vec.into_iter()
            .map(|x| String::from_utf8(x).unwrap())
            .collect();
        println!("{:?}", cipher_text_vec);            
    }
}
