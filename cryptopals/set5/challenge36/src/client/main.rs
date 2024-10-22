use dh;
use ibig::{UBig, ubig};
use clap::Parser;
use serde::{Serialize, Deserialize};

/// SRP client
#[derive(Parser, Debug, Serialize, Deserialize)]
struct Args {
    #[clap(short, long, default_value = "linhnt")]
    email: String,
    #[clap(short, long, default_value = "1234")]
    password: String
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientInfo {
    email: String,
    pub_key: Vec<u8>
}

#[derive(Debug, Serialize, Deserialize)]
struct ServerInfo {
    salt: Vec<u8>,
    pub_key: Vec<u8>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserMac {
    pub email: String,
    pub mac: [u8; 32],
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let k = ubig!(3);
    let client = reqwest::Client::new();
    let baseurl = String::from("http://localhost:9000/");
    let args = Args::parse();

    // Send email, password to server
    let url = baseurl.clone() + "user";
    client.post(&url)
        .json(&args)
        .send()
        .await?;

    let (p, g) = dh::get_p_g(dh::DHMODE::FFDHE2048);
    let (prkc, pukc) = dh::get_keypair(dh::DHMODE::FFDHE2048);
    // println!("user public key = {:?}", &pukc);
    let cinf = ClientInfo {
        email: args.email.clone(),
        pub_key: pukc.to_be_bytes()
    };
    // Send email, public key to server
    let url = baseurl.clone() + "key";
    let sinf = client.get(&url)
        .json(&cinf)
        .send()
        .await?
        .json::<ServerInfo>()
        .await?;
    // Receive salt, public key from server
    let salt = UBig::from_be_bytes(&sinf.salt);
    // println!("salt = {:02x?}", &salt);
    let puks = UBig::from_be_bytes(&sinf.pub_key);
    // println!("server public key = {:?}", &puks);

    // let mut pukcs = pukc.to_string();
    // pukcs.push_str(&puks.to_string());
    let pukcs = [pukc.clone().to_be_bytes(), puks.clone().to_be_bytes()].concat();
    let u = UBig::from_str_radix(&sha256::digest_bytes(&pukcs), 16).unwrap();
    // println!("u = {:?}", &u);

    // let mut saltpass = salt.to_string();
    // saltpass.push_str(&args.password);
    let saltpass = [&salt.to_be_bytes(), args.password.clone().as_bytes()].concat();
    let x = UBig::from_str_radix(&sha256::digest_bytes(&saltpass), 16).unwrap();
    // println!("x = {:?}", &x);

    // println!("k * mod = {:?}", &k * dh::modular_pow(g.clone(), x.clone(), p.clone()));
    assert!(puks > &k * dh::modular_pow(g.clone(), x.clone(), p.clone()));
    let base = puks - k * dh::modular_pow(g.clone(), x.clone(), p.clone());
    let exponent = prkc + u * x;
    let s = dh::modular_pow(base, exponent, p);
    // println!("s = {}", &s);
    let k = sha256::digest(s.to_string());
    // println!("k = {}", &k);

    // Send mac to server
    let mac = hmac_sha256::HMAC::mac(k, &salt.to_be_bytes());
    let user_mac = UserMac {
        email: args.email.clone(),
        mac,
    };
    let url = baseurl.clone() + "mac";
    let res = client.get(url)
        .json(&user_mac)
        .send()
        .await?;
    
    if res.status() == reqwest::StatusCode::OK {
        println!("OK");
    } else if res.status() == reqwest::StatusCode::NOT_ACCEPTABLE {
        println!("Not acceptable");
    }

    Ok(())
}