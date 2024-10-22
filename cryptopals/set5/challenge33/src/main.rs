use dh;

fn main() {
    let (prka, puka) = dh::get_keypair(dh::DHMODE::FFDHE2048);
    println!("private key A = {}", &prka);
    println!("public key A = {}", &puka);
    let (prkb, pukb) = dh::get_keypair(dh::DHMODE::FFDHE2048);
    println!("private key B = {}", &prkb);
    println!("public key B = {}", &pukb);
    let (p, _) = dh::get_p_g(dh::DHMODE::FFDHE2048);
    let sa = dh::modular_pow(pukb, prka, p.clone());
    let sb = dh::modular_pow(puka, prkb, p);
    println!("secret A = {}", &sa);
    println!("secret B = {}", &sb);
    assert_eq!(sa, sb);
}

