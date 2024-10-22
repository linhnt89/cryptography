mod core;

pub enum AESKIND {
    AES128,
    AES192,
    AES256,
}

pub enum ENDIAN {
    BIG,
    LITTLE,
}

fn get_internal_info(t: &AESKIND) -> (u8, u8) {
    match t {
        AESKIND::AES128 => (4u8, 10u8),
        AESKIND::AES192 => (6u8, 12u8),
        AESKIND::AES256 => (8u8, 14u8),
    }
}

const AES_BLOCK_LEN: usize = 16;

fn ecb(input: &[u8], key: &[u8], t: &AESKIND, enc: bool) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut block_num = 1;
    let (nk, nr) = get_internal_info(t);
    let w = core::key_expansion(key, &nk, &nr);
    let mut input_iter = input.iter();
    while block_num * AES_BLOCK_LEN <= input.len() {
        if enc {
            core::aes_encrypt(
                &input_iter
                    .by_ref()
                    .take(AES_BLOCK_LEN)
                    .cloned()
                    .collect::<Vec<u8>>(),
                &w,
                &nr,
            )
            .into_iter()
            .for_each(|b| output.push(b));
        } else {
            core::aes_decrypt(
                &input_iter
                    .by_ref()
                    .take(AES_BLOCK_LEN)
                    .cloned()
                    .collect::<Vec<u8>>(),
                &w,
                &nr,
            )
            .into_iter()
            .for_each(|b| output.push(b));
        }
        block_num += 1;
    }
    output
}

pub fn ecb_encrypt(pt: &[u8], key: &[u8], t: &AESKIND) -> Vec<u8> {
    ecb(pt, key, t, true)
}

pub fn ecb_decrypt(pt: &[u8], key: &[u8], t: &AESKIND) -> Vec<u8> {
    ecb(pt, key, t, false)
}

pub fn padding(input: Vec<u8>, bs: u8) -> Vec<u8> {
    let mut pad_value = bs - (input.len() as u32 % bs as u32) as u8;
    if pad_value == 0 {
        pad_value = bs;
    }
    let mut padded_vec = input.clone();
    let additional = vec![pad_value; pad_value as usize];
    additional.iter().for_each(|&b| padded_vec.push(b));
    padded_vec
}

pub fn remove_padding(input: Vec<u8>) -> Vec<u8> {
    let mut output = input;
    let last_byte = output[output.len() - 1];
    let padded_vec = output
        .iter()
        .rev()
        .by_ref()
        .take(last_byte as usize)
        .cloned()
        .collect::<Vec<u8>>();
    if padded_vec != vec![last_byte; last_byte as usize] {
        return output;
    }
    output.resize(output.len() - last_byte as usize, 0);
    output
}

fn cbc(input: &[u8], key: &[u8], iv: &[u8], t: &AESKIND, enc: bool) -> Vec<u8> {
    let (nk, nr) = get_internal_info(t);
    let w = core::key_expansion(key, &nk, &nr);
    let mut input_iter = input.iter();
    let mut cipher = iv.to_vec();
    let mut output = Vec::new();
    (0..)
        .into_iter()
        .map(|_| {
            input_iter
                .by_ref()
                .take(AES_BLOCK_LEN)
                .cloned()
                .collect::<Vec<u8>>()
        })
        .take_while(|block| !block.is_empty())
        .for_each(|block| {
            if enc {
                let state = cipher
                    .iter()
                    .zip(block.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<u8>>();
                cipher = core::aes_encrypt(&state, &w, &nr);
                cipher.iter().for_each(|&b| output.push(b));
            } else {
                let state = core::aes_decrypt(&block, &w, &nr);
                cipher
                    .iter()
                    .zip(state.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<u8>>()
                    .into_iter()
                    .for_each(|b| output.push(b));
                cipher = block;
            }
        });
    output
}

pub fn cbc_encrypt(pt: &[u8], key: &[u8], iv: &[u8], t: &AESKIND) -> Vec<u8> {
    cbc(pt, key, iv, t, true)
}

pub fn cbc_decrypt(pt: &[u8], key: &[u8], iv: &[u8], t: &AESKIND) -> Vec<u8> {
    cbc(pt, key, iv, t, false)
}

macro_rules! increase_counter {
    ($iter:expr) => {
        for v in $iter {
            if *v == 0xFF {
                *v = 0;
            } else {
                *v += 1;
                break;
            }
        }
    };
}

fn ctr(input: &[u8], key: &[u8], iv: &[u8], ctrbits: u8, endian: ENDIAN, t: &AESKIND) -> Vec<u8> {
    let (nk, nr) = get_internal_info(t);
    let w = core::key_expansion(key, &nk, &nr);
    let mut input_iter = input.iter();
    let mut output = Vec::new();
    let mut iv_iter = iv.iter();
    let nonce = iv_iter
        .by_ref()
        .take(((128 - ctrbits) / 8) as usize)
        .cloned()
        .collect::<Vec<u8>>();
    let mut ctr = iv_iter.cloned().collect::<Vec<u8>>();
    (0..)
        .into_iter()
        .map(|_| {
            input_iter
                .by_ref()
                .take(AES_BLOCK_LEN)
                .cloned()
                .collect::<Vec<u8>>()
        })
        .take_while(|block| !block.is_empty())
        .for_each(|block| {
            let mut ctr_block = nonce.clone();
            ctr.iter().for_each(|v| ctr_block.push(*v));
            let stream = core::aes_encrypt(&ctr_block, &w, &nr);
            stream
                .iter()
                .zip(block.iter())
                .for_each(|(a, b)| output.push(a ^ b));
            match endian {
                ENDIAN::BIG => increase_counter!(ctr.iter_mut().rev()),
                ENDIAN::LITTLE => increase_counter!(ctr.iter_mut()),
            };
        });
    output
}

pub fn ctr_encrypt(
    pt: &[u8],
    key: &[u8],
    iv: &[u8],
    ctrbits: u8,
    endian: ENDIAN,
    t: &AESKIND,
) -> Vec<u8> {
    ctr(pt, key, iv, ctrbits, endian, t)
}

pub fn ctr_decrypt(
    pt: &[u8],
    key: &[u8],
    iv: &[u8],
    ctrbits: u8,
    endian: ENDIAN,
    t: &AESKIND,
) -> Vec<u8> {
    ctr(pt, key, iv, ctrbits, endian, t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_ecb() {
        let pt = hex::decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        ).unwrap();
        let cipher = hex::decode(
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
        ).unwrap();
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        assert_eq!(cipher, ecb_encrypt(&pt, &key, &AESKIND::AES128));
        assert_eq!(pt, ecb_decrypt(&cipher, &key, &AESKIND::AES128));
    }

    #[test]
    fn test_ecb_with_padding() {
        let pt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let padded_pt = padding(pt.clone(), AES_BLOCK_LEN as u8);
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let cipher = ecb_encrypt(&padded_pt, &key, &AESKIND::AES128);
        assert_eq!(
            pt,
            remove_padding(ecb_decrypt(&cipher, &key, &AESKIND::AES128))
        );
    }

    #[test]
    fn test_cbc() {
        let pt = hex::decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        ).unwrap();
        let cipher = hex::decode(
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
        ).unwrap();
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(cipher, cbc_encrypt(&pt, &key, &iv, &AESKIND::AES128));
        assert_eq!(pt, cbc_decrypt(&cipher, &key, &iv, &AESKIND::AES128));
    }
}

#[test]
fn test_ctr() {
    let pt = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        ).unwrap();
    let cipher = hex::decode(
            "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
        ).unwrap();
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    assert_eq!(
        cipher,
        ctr_encrypt(&pt, &key, &iv, 128, ENDIAN::BIG, &AESKIND::AES128)
    );
    assert_eq!(
        pt,
        ctr_decrypt(&cipher, &key, &iv, 128, ENDIAN::BIG, &AESKIND::AES128)
    );
}

#[test]
fn test_increase_counter() {
    let mut ctr = [0u8; 16];
    let ctr_iter = ctr.iter_mut().rev();
    increase_counter!(ctr_iter);
    println!("{:?}", ctr);
}

