use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_primes::Generator;
use hex;

#[derive(Debug)]
pub enum Error {
    InverseError
}

pub fn encrypt(msg: &str, key: (BigInt, BigInt)) -> String {
    let m = BigInt::from_bytes_be(Sign::Plus, msg.as_bytes());
    let c = hex::encode(m.modpow(&key.0, &key.1).to_bytes_be().1);
    c
}

pub fn decrypt(cipher: &str, key: (BigInt, BigInt)) -> String {
    let c = BigInt::from_bytes_be(Sign::Plus, &hex::decode(cipher).unwrap());
    let m = c.modpow(&key.0, &key.1);
    String::from_utf8(m.to_bytes_be().1).unwrap()
}

pub fn gen_keypair() -> Vec<(BigInt, BigInt)> {
    let mut cont = true;
    let e = BigInt::from(3u32);
    let mut n = BigInt::from(0u32);
    let mut d = BigInt::from(0u32);
    while cont {
        let p = BigInt::from_biguint(Sign::Plus, Generator::new_prime(512));
        let q = BigInt::from_biguint(Sign::Plus, Generator::new_prime(512));
        n = &p * &q;
        let et = (&p - BigInt::from(1u32)) * (&q - BigInt::from(1u32));
        match invmod(e.clone(), et.clone()) {
            Err(_) => cont = true,
            Ok(x) => {
                cont = false;
                d = x;
            }
        }    
    }
    vec![(e, n.clone()), (d, n)]
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a == BigInt::from(0u32) {
        return (b, BigInt::from(0u32), BigInt::from(1u32));
    } else {
        let (g, x, y) = egcd(b.div_mod_floor(&a).1, a.clone());
        return (g, &y - BigInt::from((b.div_mod_floor(&a).0) * &x), x);
    }
}

pub fn invmod(e: BigInt, et: BigInt) -> Result<BigInt, Error> {
    let ret;
    let (g, x, _) = egcd(e, et.clone());
    if g != BigInt::from(1u32) {
        return Err(Error::InverseError);
    } else {
        ret = x.div_mod_floor(&et).1;
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invmod() {
        assert_eq!(BigInt::from(2753u32), invmod(BigInt::from(17u32), BigInt::from(3120u32)).unwrap());
    }

    #[test]
    fn test_rsa() {
        let mut keys = gen_keypair();
        let prk = keys.pop().unwrap();
        let puk = keys.pop().unwrap();
        let msg = "test".to_string();
        assert_eq!(msg, decrypt(&encrypt(&msg, puk), prk));
    }
}
