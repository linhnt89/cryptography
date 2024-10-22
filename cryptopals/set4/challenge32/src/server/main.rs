
use std::convert::Infallible;
use std::{thread, time};
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use sha;
use hex;
use warp::Filter;
use serde::Deserialize;

#[derive(Deserialize)]
struct Auth {
    file: String,
    signature: String,
}

#[tokio::main]
async fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(u8::from)
        .collect::<Vec<u8>>();
    // Match a query 
    // e.g: http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
    let test = 
        warp::get()
        .and(warp::path("test"))
        .and(warp::query::<Auth>())
        .and(with_key(key))
        .and_then(insecure_compare);

    warp::serve(test).run(([127, 0, 0, 1], 9000)).await;
}

fn with_key(key: Vec<u8>) -> impl Filter<Extract = (Vec<u8>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || key.clone())
}

async fn insecure_compare(info: Auth, key: Vec<u8>) -> Result<impl warp::Reply, Infallible> {
    let mac = hmac(key, info.file.into_bytes().to_vec());
    println!("mac = {:02x?}", &mac);
    let mut status = warp::http::StatusCode::OK;
    for (a, b) in mac.iter().zip(hex::decode(info.signature).unwrap().iter()) {
        if a != b {
            status = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
            break;
        }
        thread::sleep(time::Duration::from_millis(5));
    }
    Ok(warp::reply::with_status(format!("test"), status))    
}

fn process_key(mut key: Vec<u8>, blocksize: usize) -> Vec<u8> {
    if key.len() > blocksize {
        key = sha::SHA1::hash(&key, &Vec::new(), 0)
            .into_iter()
            .flat_map(|n| n.to_be_bytes().to_vec())
            .collect::<Vec<u8>>();
    }
    if key.len() < blocksize {
        key.append(&mut vec![0u8; blocksize-key.len()]);
    }
    key
}

fn hmac(key: Vec<u8>, mut msg: Vec<u8>) -> Vec<u8> {
    let blocksize = 64;
    let ipad = vec![0x36u8; blocksize];
    let opad = vec![0x5cu8; blocksize];

    let key = process_key(key, blocksize);
    
    let mut state_i = key.iter().zip(ipad.iter())
        .map(|(a,b)| a^b)
        .collect::<Vec<u8>>();
    let mut state_o = key.iter().zip(opad.iter())
        .map(|(a,b)| a^b)
        .collect::<Vec<u8>>();

    state_i.append(&mut msg);
    let mut state = sha::SHA1::hash(&state_i, &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();
    state_o.append(&mut state);
    sha::SHA1::hash(&state_o, &Vec::new(), 0)
        .into_iter()
        .flat_map(|n| n.to_be_bytes().to_vec())
        .collect::<Vec<u8>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() {
        let key = "key".as_bytes().to_vec();
        let msg = "The quick brown fox jumps over the lazy dog".as_bytes().to_vec();
        let mac = hex::decode("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9").unwrap();
        assert_eq!(mac, hmac(key, msg));
        let key = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F").unwrap();
        let msg = "Sample message for keylen=blocklen".as_bytes().to_vec();
        let mac = hex::decode("5FD596EE78D5553C8FF4E72D266DFD192366DA29").unwrap();
        assert_eq!(mac, hmac(key, msg));
        let key = hex::decode("000102030405060708090A0B0C0D0E0F10111213").unwrap();
        let msg = "Sample message for keylen<blocklen".as_bytes().to_vec();
        let mac = hex::decode("4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807").unwrap();
        assert_eq!(mac, hmac(key, msg));
        let key = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263").unwrap();
        let msg = "Sample message for keylen=blocklen".as_bytes().to_vec();
        let mac = hex::decode("2D51B2F7750E410584662E38F133435F4C4FD42A").unwrap();
        assert_eq!(mac, hmac(key, msg));
    }
}