
pub struct SHA1;

impl SHA1 {
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
        let mut padded_l = ((msg_len + original_len*8) as u64).to_be_bytes().to_vec();
        padded_msg.append(&mut padded_l);
        padded_msg
    }

    fn parsing(msg: Vec<u8>) -> Vec<u32> {
        let mut parsed_msg = Vec::new();
        let mut i = 0;
        while i < msg.len() {
            let n = ((msg[i] as u32) << 24) 
                | ((msg[i+1] as u32) << 16) 
                | ((msg[i+2] as u32) << 8) 
                | msg[i+3] as u32;
            parsed_msg.push(n);
            i += 4;
        }
        parsed_msg
    }

    fn preprocessing(msg: &[u8], original_len: usize) -> Vec<u32> {
        SHA1::parsing(SHA1::padding(msg, original_len))
    }

    fn calculate_schedule(msg: Vec<u32>) -> Vec<u32> {
        let mut w = msg;
        for i in 16..=79 {
            let x = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
            w.push(x.rotate_left(1));
        }
        w
    }

    pub fn hash(msg: &[u8], intermediate_hash: &[u32], original_len: usize) -> Vec<u32> {
        let preprocessed_msg = SHA1::preprocessing(msg, original_len);
        let len = preprocessed_msg.len() / 16;
        let mut preprocessed_msg_iter = preprocessed_msg.into_iter();
        let mut h = vec![
            0x67452301u32,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        ];
        if !intermediate_hash.is_empty() {
            h = intermediate_hash.clone().to_vec();
        }
        for _ in 0..len {
            let w = SHA1::calculate_schedule(
                preprocessed_msg_iter.by_ref().take(16).collect::<Vec<u32>>()
            );
            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            for j in 0..=79 {
                let (f, k) = match j {
                    0..=19  => ((b & c) ^ (!b & d), 0x5a827999u32),
                    20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                    40..=59 => ((b & c) ^ (b & d) ^ (c & d), 0x8f1bbcdc),
                    _ => (b ^ c ^ d, 0xca62c1d6),
                };
                let t = a.rotate_left(5).overflowing_add(
                    f.overflowing_add(
                        e.overflowing_add(
                            k.overflowing_add(w[j]).0
                        ).0
                    ).0
                ).0;
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }
            h[0] = h[0].overflowing_add(a).0;                
            h[1] = h[1].overflowing_add(b).0;           
            h[2] = h[2].overflowing_add(c).0;              
            h[3] = h[3].overflowing_add(d).0;               
            h[4] = h[4].overflowing_add(e).0;                  
        }
        h
    }
}


#[cfg(test)]
mod tests {
    use crate::SHA1;

    #[test]
    fn test_preprocessing() {
        let msg = "abc".as_bytes();
        let result = [
            0x61626380u32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x00000018,
        ];
        assert_eq!(result.to_vec(), SHA1::preprocessing(msg, 0));
        let msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        let result = [
            0x61626364u32, 0x62636465, 0x63646566, 0x64656667, 0x65666768, 0x66676869, 0x6768696A, 0x68696A6B,
            0x696A6B6C, 0x6A6B6C6D, 0x6B6C6D6E, 0x6C6D6E6F, 0x6D6E6F70, 0x6E6F7071, 0x80000000, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000001C0,
        ];
        assert_eq!(result.to_vec(), SHA1::preprocessing(msg, 0));
    }

    #[test]
    fn test_hash() {
        let msg = "abc".as_bytes();
        let result = vec![
            0xA9993E36u32,
            0x4706816A,
            0xBA3E2571,
            0x7850C26C,
            0x9CD0D89D,
        ];
        assert_eq!(result, SHA1::hash(msg, &Vec::new(), 0));
        let msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        let result = vec![
            0x84983E44u32,
            0x1C3BD26E,
            0xBAAE4AA1,
            0xF95129E5,
            0xE54670F1,
        ];
        assert_eq!(result, SHA1::hash(msg, &Vec::new(), 0));
        use sha1::{self, Digest};
        let msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
            .as_bytes();
        let mut hasher = sha1::Sha1::new();
        hasher.update(msg);
        let mac = hasher.finalize().to_vec();
        let mac2 = SHA1::hash(msg, &Vec::new(), 0);
        let mac3 = mac2.into_iter()
            .flat_map(|x| x.to_be_bytes().to_vec())
            .collect::<Vec<u8>>();
        assert_eq!(mac, mac3);
    }
}
