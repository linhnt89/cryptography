
pub struct MD4;

impl MD4 {
    fn padding(msg: &[u8], original_len: usize) -> Vec<u8> {
        let mut padded_msg = msg.clone().to_vec();
        let msg_len = padded_msg.len() * 8;
        let mut padded_msg_len = 512;
        if msg_len > 512 - 64 - 1 {
            padded_msg_len *= ((msg_len - (512 - 64 - 1)) / 512) + 2;
        }
        let zero_bytes_len = (padded_msg_len - msg_len - 64 - 8) / 8;
        padded_msg.push(0x80);
        padded_msg.append(&mut vec![0u8; zero_bytes_len]);
        let mut padded_l = ((msg_len + original_len*8) as u64).to_le_bytes().to_vec();
        padded_msg.append(&mut padded_l);
        padded_msg
    }

    fn parsing(msg: Vec<u8>) -> Vec<u32> {
        let mut parsed_msg = Vec::new();
        let mut i = 0;
        while i < msg.len() {
            let n = ((msg[i+3] as u32) << 24) 
                | ((msg[i+2] as u32) << 16) 
                | ((msg[i+1] as u32) << 8) 
                | msg[i] as u32;
            parsed_msg.push(n);
            i += 4;
        }
        parsed_msg
    }

    fn preprocessing(msg: &[u8], original_len: usize) -> Vec<u32> {
        MD4::parsing(MD4::padding(msg, original_len))
    }

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.overflowing_add(
            MD4::f(b, c, d).overflowing_add(
                k
            ).0
        ).0.rotate_left(s)
    }

    fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.overflowing_add(
            MD4::g(b, c, d).overflowing_add(
                k.overflowing_add(
                    0x5a827999
                ).0
            ).0
        ).0.rotate_left(s)
    }

    fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
        a.overflowing_add(
            MD4::h(b, c, d).overflowing_add(
                k.overflowing_add(
                    0x6ed9eba1
                ).0
            ).0
        ).0.rotate_left(s)
    }

    pub fn hash(msg: &[u8], intermediate_hash: &[u32], original_len: usize) -> Vec<u8> {
        let preprocessed_msg = MD4::preprocessing(msg, original_len);
        let len = preprocessed_msg.len() / 16;
        let mut preprocessed_msg_iter = preprocessed_msg.into_iter();
        let mut h = vec![
            0x67452301u32,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
        ];
        if !intermediate_hash.is_empty() {
            h = intermediate_hash.clone().to_vec();
        }
        for _ in 0..len {
            let w = preprocessed_msg_iter.by_ref().take(16).collect::<Vec<u32>>();
            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            // Round 1
            for i in [0, 4, 8, 12] {
                a = MD4::op1(a, b, c, d, w[i], 3);
                d = MD4::op1(d, a, b, c, w[i+1], 7);
                c = MD4::op1(c, d, a, b, w[i+2], 11);
                b = MD4::op1(b, c, d, a, w[i+3], 19);
            }
            // Round 2
            for i in [0, 1, 2, 3] {
                a = MD4::op2(a, b, c, d, w[i], 3);
                d = MD4::op2(d, a, b, c, w[i+4], 5);
                c = MD4::op2(c, d, a, b, w[i+8], 9);
                b = MD4::op2(b, c, d, a, w[i+12], 13);
            }
            // Round 3
            for i in [0, 2, 1, 3] {
                a = MD4::op3(a, b, c, d, w[i], 3);
                d = MD4::op3(d, a, b, c, w[i+8], 9);
                c = MD4::op3(c, d, a, b, w[i+4], 11);
                b = MD4::op3(b, c, d, a, w[i+12], 15);
            }
            h[0] = h[0].overflowing_add(a).0;                
            h[1] = h[1].overflowing_add(b).0;           
            h[2] = h[2].overflowing_add(c).0;              
            h[3] = h[3].overflowing_add(d).0;             
        }
        let ret = h.into_iter()
            .flat_map(|n| n.to_le_bytes().to_vec())
            .collect::<Vec<u8>>();
        ret
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hash() {
        let msg = "abc".as_bytes();
        let result = hex::decode("a448017aaf21d8525fc10ae87aa6729d").unwrap();
        let hash = MD4::hash(msg, &Vec::new(), 0);
        assert_eq!(result, hash);
        let msg = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();
        let result = hex::decode("e33b4ddc9c38f2199c3e7b164fcc0536").unwrap();
        let hash = MD4::hash(msg, &Vec::new(), 0);
        assert_eq!(result, hash);
    }
}
