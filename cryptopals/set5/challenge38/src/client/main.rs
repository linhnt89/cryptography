use std::{fs::File, io::{BufReader, BufRead}};
use dh;
use ibig::UBig;
use clap::Parser;
use rand::prelude::IteratorRandom;
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
    pub_key: Vec<u8>,
    u: Vec<u8>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserMac {
    pub email: String,
    pub mac: [u8; 32],
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let baseurl = String::from("http://localhost:9000/");
    let mut args = Args::parse();

    // Choose random password
    args.password = get_random_password();
    // Send email, password to server
    let url = baseurl.clone() + "user";
    client.post(&url)
        .json(&args)
        .send()
        .await?;

    let (p, _) = dh::get_p_g(dh::DHMODE::FFDHE2048);
    let (prkc, pukc) = dh::get_keypair(dh::DHMODE::FFDHE2048);
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
    let puks = UBig::from_be_bytes(&sinf.pub_key);
    let u = UBig::from_be_bytes(&sinf.u);

    let saltpass = [&salt.to_be_bytes(), args.password.clone().as_bytes()].concat();
    let x = UBig::from_str_radix(&sha256::digest_bytes(&saltpass), 16).unwrap();

    let base = puks;
    let exponent = prkc + u * x;
    let s = dh::modular_pow(base, exponent, p);
    let k = sha256::digest(s.to_string());

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
        println!("password = {}", args.password);
    } else if res.status() == reqwest::StatusCode::NOT_ACCEPTABLE {
        println!("Not acceptable");
    }

    Ok(())
}

fn get_random_password() -> String {
    const FILENAME: &str = "C:\\Programming\\workspace\\rust\\cryptography\\cryptopals\\set5\\challenge38\\10k-most-commons.txt";

    let f = File::open(FILENAME)
        .unwrap_or_else(|e| panic!("(;_;) file not found: {}: {}", FILENAME, e));
    let f = BufReader::new(f);

    let lines = f.lines().map(|l| l.expect("Couldn't read line"));
    lines.choose(&mut rand::thread_rng()).expect("File has no lines")
}