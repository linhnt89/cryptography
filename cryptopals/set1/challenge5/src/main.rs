// use core::fmt::Write;
use hex;

fn main() {
    println!("Hello, world!");
}

fn repeat_xor(pt: &str, k: &str) -> String {
    let mut k_it = k.bytes().cycle();
    let enc_v = pt.as_bytes().iter()
            .map(|b| b ^ k_it.next().unwrap())
            .collect::<Vec<u8>>();
    // let mut enc_str = String::with_capacity(2*enc_v.len());
    // for byte in enc_v {
    //     write!(enc_str, "{:02x}", byte).unwrap();
    // }
    // enc_str
    hex::encode(enc_v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repeat_xor() {
        let pt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let k = "ICE";
        let enc_str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(enc_str, repeat_xor(pt, k))
    }
}