use ibig::{UBig, ubig};
use clap::Parser;
use reqwest::Client;
use serde::{Serialize, Deserialize};

/// SRP client
#[derive(Parser, Debug, Serialize, Deserialize, Clone)]
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
async fn main() {
    let client = reqwest::Client::new();
    let baseurl = String::from("http://localhost:9000/");
    let args = Args::parse();

    let (p, _) = dh::get_p_g(dh::DHMODE::FFDHE2048);

    // Send email, password to server
    let url = baseurl.clone() + "user";
    let _ = client.post(&url)
        .json(&args)
        .send()
        .await;

    // Test with pub_key = 0
    let _ = login_without_password(args.clone(), baseurl.clone(), client.clone(), ubig!(0)).await;
    
    // Test with pub_key = p
    let _ = login_without_password(args.clone(), baseurl.clone(), client.clone(), p.clone()).await;
    
    // Test with pub_key = p * 2
    let _ = login_without_password(args.clone(), baseurl.clone(), client.clone(), p*ubig!(2)).await;
}

async fn login_without_password(args: Args, baseurl: String, client: Client, pukc: UBig) -> Result<(), reqwest::Error> {
    // Test with pub_key = 0
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

    // pub_key of client = 0 => s of server = 0 => s of client = 0
    let s = ubig!(0);
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
        println!("public key = {:?} - OK", &pukc);
    } else if res.status() == reqwest::StatusCode::NOT_ACCEPTABLE {
        println!("public key = {:?} - Not acceptable", &pukc);
    }

    Ok(())
}