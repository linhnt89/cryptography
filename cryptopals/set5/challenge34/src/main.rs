use dh;
use aes;
use sha;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use ibig::ubig;

fn main() {
    // A
    let (p, _) = dh::get_p_g(dh::DHMODE::FFDHE2048);
    let (prka, _) = dh::get_keypair(dh::DHMODE::FFDHE2048);
    
    // A -> M (M knows p, g and puka)

    // M -> B (p, g, p)

    // B
    let (prkb, _) = dh::get_keypair(dh::DHMODE::FFDHE2048);

    // B -> M (M knows pukb)

    // M -> A (p)

    // A
    let iva = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let sa = dh::modular_pow(p.clone(), prka.clone(), p.clone());
    let msga = "Hello, I'm A    ";
    let keya = sha::SHA1::hash(&sa.to_be_bytes(), &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    let ciphera = aes::cbc_encrypt(msga.as_bytes(), &keya[0..16], &iva, &aes::AESKIND::AES128);

    // A -> M (M knows ciphera, iva)
    
    // M -> B (B knows ciphera, iva)

    // B
    let ivb = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let sb = dh::modular_pow(p.clone(), prkb.clone(), p.clone());
    let msgb = "Hello, I'm B    ";
    let keyb = sha::SHA1::hash(&sb.to_be_bytes(), &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    let cipherb = aes::cbc_encrypt(msgb.as_bytes(), &keyb[0..16], &ivb, &aes::AESKIND::AES128);

    // B -> M (M knows cipherb, ivb)

    // M -> A (A knows cipherb, ivb)

    // M decrypts cipher of A
    let pta = String::from_utf8(m_decrypt_cipher(ciphera, iva)).unwrap();
    assert_eq!(msga, pta);

    // M decrypts cipher of B
    let ptb = String::from_utf8(m_decrypt_cipher(cipherb, ivb)).unwrap();
    assert_eq!(msgb, ptb);
}

fn m_decrypt_cipher(cipher: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    // The shared secret of A and B is 0
    // since p^prka/prkb mod p = 0
    let secret = ubig!(0);
    let key = sha::SHA1::hash(&secret.to_be_bytes(), &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    let pt = aes::cbc_decrypt(&cipher, &key[0..16], &iv, &aes::AESKIND::AES128);
    pt
}