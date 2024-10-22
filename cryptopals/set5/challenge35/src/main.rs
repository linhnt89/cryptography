use dh;
use aes;
use sha;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use ibig::{ubig, UBig};

fn main() {
    // A
    let (p, _) = dh::get_p_g(dh::DHMODE::FFDHE2048);
    let (prka, _) = dh::get_keypair(dh::DHMODE::FFDHE2048);
    
    // A -> B (M knows p, g and puka)

    // B
    let (prkb, _) = dh::get_keypair(dh::DHMODE::FFDHE2048);

    // B -> A (M knows pukb)

    // A
    let iva = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let msga = "Hello, I'm A    ";

    // A -> B (M knows ciphera, iva)

    // B
    let ivb = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let msgb = "Hello, I'm B    ";

    // B -> A (M knows cipherb, ivb)

    // case 1 : M sends g = 1 to B
    // => pukb = 1 => secreta = 1
    // => g = 1 => secretb = 1
    let g = ubig!(1); 
    let secret = ubig!(1);
    if m_mimt(&g, &p, &secret, &prka, &prkb, msga, msgb, &iva, &ivb) {
        println!("case 1 (g = 1) : secret = 1");
    }

    // case 2 : M sends g = p to B
    // => pukb = 0 => secreta = 0
    // => g = p => secretb = 0
    let g = ubig!(0); 
    let secret = ubig!(0);
    m_mimt(&g, &p, &secret, &prka, &prkb, msga, msgb, &iva, &ivb);
    if m_mimt(&g, &p, &secret, &prka, &prkb, msga, msgb, &iva, &ivb) {
        println!("case 2 (g = p) : secret = p");
    }

    // case 3 : M sends g = p - 1 to B
    // if prkb*prka is even => secreta = secretb = 1
    // else                 => secreta = secretb = p - 1
    let g = &p - ubig!(1); 
    let secret = ubig!(1);
    if m_mimt(&g, &p, &secret, &prka, &prkb, msga, msgb, &iva, &ivb) {
        println!("case 3 (g = p - 1) : secret = 1");
    } else {
        let secret = &p - ubig!(1);
        if m_mimt(&g, &p, &secret, &prka, &prkb, msga, msgb, &iva, &ivb) {
            println!("case 3 (g = p - 1) : secret = p - 1");
        }    
    }

}

fn m_decrypt_cipher(cipher: Vec<u8>, iv: &[u8], secret: &UBig) -> Vec<u8> {
    let key = sha::SHA1::hash(&secret.to_be_bytes(), &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    let pt = aes::cbc_decrypt(&cipher, &key[0..16], &iv, &aes::AESKIND::AES128);
    pt
}

fn m_mimt(g: &UBig, p: &UBig, secret: &UBig, prka: &UBig, prkb: &UBig, msga: &str, msgb: &str, iva: &[u8], ivb: &[u8]) -> bool {
    let sa = dh::modular_pow(g.clone(), prka * prkb, p.clone());
    let keya = sha::SHA1::hash(&sa.to_be_bytes(), &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    let ciphera = aes::cbc_encrypt(msga.as_bytes(), &keya[0..16], &iva, &aes::AESKIND::AES128);
    let sb = dh::modular_pow(g.clone(), prkb * prka, p.clone());
    let keyb = sha::SHA1::hash(&sb.to_be_bytes(), &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    let cipherb = aes::cbc_encrypt(msgb.as_bytes(), &keyb[0..16], &ivb, &aes::AESKIND::AES128);
    // M decrypts cipher of A
    let pta = m_decrypt_cipher(ciphera, iva, &secret);
    // M decrypts cipher of B
    let ptb = m_decrypt_cipher(cipherb, ivb, &secret);
    // compare
    let mut ret = false;
    if msga.as_bytes() == pta && msgb.as_bytes() == ptb {
        ret = true;
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiply_mod() {
        let (p, _) = dh::get_p_g(dh::DHMODE::FFDHE2048);
        for _ in 0..1000 {
            let g = &p - ubig!(1);
            let e = thread_rng().gen_range(ubig!(2)..(&g - ubig!(1)));
            let a = dh::modular_pow(g.clone(), e.clone(), p.clone());
            let mut b = ubig!(1);
            if e.bit(0) == true {
                b = g;
            }
            assert_eq!(b, a);                
        }
   }
}