use rsa;
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use hex;

fn main() {
    let msg = "test".to_string();

    // Encrypt 1st
    let mut keys0 = rsa::gen_keypair();
    let prk0 = keys0.pop().unwrap();
    let puk0 = keys0.pop().unwrap();
    let n0 = puk0.1.clone();
    let cipher0 = rsa::encrypt(&msg, puk0);
    assert_eq!(rsa::decrypt(&cipher0, prk0), msg.clone());
    let cipher0 = BigInt::from_bytes_be(Sign::Plus, &hex::decode(cipher0).unwrap());

    // Encrypt 2nd
    let mut keys1 = rsa::gen_keypair();
    let prk1 = keys1.pop().unwrap();
    let puk1 = keys1.pop().unwrap();
    let n1 = puk1.1.clone();
    let cipher1 = rsa::encrypt(&msg, puk1);
    assert_eq!(rsa::decrypt(&cipher1, prk1), msg.clone());
    let cipher1 = BigInt::from_bytes_be(Sign::Plus, &hex::decode(cipher1).unwrap());

    // Encrypt 3rd
    let mut keys2 = rsa::gen_keypair();
    let prk2 = keys2.pop().unwrap();
    let puk2 = keys2.pop().unwrap();
    let n2 = puk2.1.clone();
    let cipher2 = rsa::encrypt(&msg, puk2);
    assert_eq!(rsa::decrypt(&cipher2, prk2), msg.clone());
    let cipher2 = BigInt::from_bytes_be(Sign::Plus, &hex::decode(cipher2).unwrap());

    // CRT
    let c0 = cipher0.div_mod_floor(&n0).1;
    let c1 = cipher1.div_mod_floor(&n1).1;
    let c2 = cipher2.div_mod_floor(&n2).1;
    let ms0 = &n1 * &n2;
    let ms1 = &n0 * &n2;
    let ms2 = &n0 * &n1;
    let p = &n0 * &n1 * &n2;
    let m = (((&c0 * &ms0 * rsa::invmod(ms0, n0).unwrap()) +
        (&c1 * &ms1 * rsa::invmod(ms1, n1).unwrap()) +
        (&c2 * &ms2 * rsa::invmod(ms2, n2).unwrap())).div_mod_floor(&p).1).cbrt();
    
    // Compare
    assert_eq!(msg, String::from_utf8(m.to_bytes_be().1).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crt() {
        let n0 = BigInt::from(3u32);
        let n1 = BigInt::from(4u32);
        let n2 = BigInt::from(5u32);
        let cipher0 = BigInt::from(2u32);
        let cipher1 = BigInt::from(3u32);
        let cipher2 = BigInt::from(1u32);
        let c0 = cipher0.div_mod_floor(&n0).1;
        let c1 = cipher1.div_mod_floor(&n1).1;
        let c2 = cipher2.div_mod_floor(&n2).1;
        let ms0 = &n1 * &n2;
        let ms1 = &n0 * &n2;
        let ms2 = &n0 * &n1;
        let p = &n0 * &n1 * &n2;
        let m = ((&c0 * &ms0 * rsa::invmod(ms0, n0).unwrap()) +
            (&c1 * &ms1 * rsa::invmod(ms1, n1).unwrap()) +
            (&c2 * &ms2 * rsa::invmod(ms2, n2).unwrap())) % p;
        assert_eq!(BigInt::from(11u32), m);
    }
}