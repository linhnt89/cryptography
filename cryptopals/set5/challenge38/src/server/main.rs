use std::{fs::File, io::{BufReader, BufRead}};
use std::convert::Infallible;
use ibig::{ubig, UBig};
use warp::Filter;
use rand::{thread_rng, Rng};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::Mutex;

mod models {
    use super::*;

    #[derive(PartialEq, PartialOrd, Clone, Debug, Serialize, Deserialize)]
    pub struct User {
        pub email: String,
        pub password: String,
    }

    #[derive(PartialEq, PartialOrd, Clone, Debug, Serialize, Deserialize)]
    pub struct UserKey {
        pub email: String,
        pub pub_key: Vec<u8>,
    }

    #[derive(PartialEq, PartialOrd, Clone, Debug, Serialize, Deserialize)]
    pub struct UserMac {
        pub email: String,
        pub mac: [u8; 32],
    }

    #[derive(PartialEq, PartialOrd, Clone, Debug, Serialize, Deserialize)]
    pub struct ServerKey {
        pub salt: Vec<u8>,
        pub pub_key: Vec<u8>,
        pub u: Vec<u8>
    }

    #[derive(PartialEq, PartialOrd, Clone, Debug)]
    pub struct UserInfo {
        pub email: String,
        pub password: String,
        pub c_pub_key: UBig,
        pub s_pub_key: UBig,
        pub s_prv_key: UBig,
        pub salt: UBig,
        pub u: UBig,
        pub g: UBig,
        pub p: UBig
    }
}

mod db {
    use super::*;
    
    pub type Db = Arc<Mutex<Vec<models::UserInfo>>>;

    pub fn init_db() -> Db {
        Arc::new(Mutex::new(Vec::new()))
    }
}

mod filters {
    use super::*;

    fn with_db(db: db::Db) -> impl Filter<Extract = (db::Db,), Error = Infallible> + Clone {
        warp::any().map(move || db.clone())
    }

    pub fn create_user(db: db::Db
        ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::post()
        .and(warp::path!("user"))
        .and(warp::body::content_length_limit(1024 * 16))
        .and(warp::body::json::<models::User>())
        .and(with_db(db))
        .and_then(handlers::create_user)
    }

    pub fn exchange_public_key(db: db::Db) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::get()
        .and(warp::path!("key"))
        .and(warp::body::content_length_limit(1024 * 32))
        .and(warp::body::json::<models::UserKey>())
        .and(with_db(db))
        .and_then(handlers::exchange_public_key)
    }

    pub fn get_mac(db: db::Db) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::get()
        .and(warp::path!("mac"))
        .and(warp::body::content_length_limit(1024 * 2))
        .and(warp::body::json::<models::UserMac>())
        .and(with_db(db))
        .and_then(handlers::compare_mac)
    }
    
    pub fn user_routes(db: db::Db) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        create_user(db.clone())
        .or(exchange_public_key(db.clone()))
        .or(get_mac(db.clone()))
    }

}

mod handlers {
    use super::*;

    pub async fn create_user(new_user: models::User, db: db::Db) -> Result<impl warp::Reply, Infallible> {
        let mut users = db.lock().await;

        for user in users.iter() {
            if user.email == new_user.email {
                return Ok(warp::http::StatusCode::BAD_REQUEST);
            }
        }
        
        let (p, g) = dh::get_p_g(dh::DHMODE::FFDHE2048);
        let (prk, puk) = dh::get_keypair(dh::DHMODE::FFDHE2048);

        let user = models::UserInfo {
            email: new_user.email,
            password: new_user.password,
            c_pub_key: ubig!(0),
            s_pub_key: puk,
            s_prv_key: prk,
            salt: ubig!(0),
            u: ubig!(0),
            g,
            p
        };

        users.push(user);
        Ok(warp::http::StatusCode::CREATED)
    }

    pub async fn exchange_public_key(user_key: models::UserKey, db: db::Db) -> Result<impl warp::Reply, Infallible> {
        let mut users = db.lock().await;
        let mut sinf = models::ServerKey {
            salt: vec![0u8; 1],
            pub_key: vec![0u8; 1],
            u: vec![0u8; 1],
        };
        let ret = warp::reply::json(&sinf);

        for user in users.iter_mut() {
            if user.email == user_key.email {
                user.c_pub_key = UBig::from_be_bytes(&user_key.pub_key);

                let salt = thread_rng().gen_range(ubig!(100)..ubig!(1000));
                // let min = ubig!(2).pow(127);
                let max = ubig!(2).pow(128);
                let u = thread_rng().gen_range(ubig!(1)..max);
                sinf = models::ServerKey {
                    salt: salt.clone().to_be_bytes(),
                    pub_key: user.s_pub_key.clone().to_be_bytes(),
                    u: u.clone().to_be_bytes(),
                };
                user.salt = salt;
                user.u = u;
                return Ok(warp::reply::json(&sinf))
            }
        }

        Ok(ret)
    }

    pub async fn compare_mac(user_mac: models::UserMac, db: db::Db) -> Result<impl warp::Reply, Infallible> {
        let users = db.lock().await;

        for user in users.iter() {
            if user.email == user_mac.email {
                if brute_force_password(user, user_mac.mac) {
                    return Ok(warp::http::StatusCode::OK);
                }
            }
        }
        Ok(warp::http::StatusCode::NOT_ACCEPTABLE)
    }

    fn brute_force_password(user: &models::UserInfo, user_mac: [u8; 32]) -> bool {
        let mut ret = false;
        const FILENAME: &str = "C:\\Programming\\workspace\\rust\\cryptography\\cryptopals\\set5\\challenge38\\10k-most-commons.txt";

        let f = File::open(FILENAME)
            .unwrap_or_else(|e| panic!("(;_;) file not found: {}: {}", FILENAME, e));
        let f = BufReader::new(f);
    
        let lines = f.lines().map(|l| l.expect("Couldn't read line"));
        for line in lines {
            let saltpass = [&user.salt.to_be_bytes(), line.as_bytes()].concat();
            let x = UBig::from_str_radix(&sha256::digest_bytes(&saltpass), 16).unwrap();
            let v = dh::modular_pow(user.g.clone(), x, user.p.clone());
            let s = dh::modular_pow(user.c_pub_key.clone() * dh::modular_pow(v, user.u.clone(), user.p.clone()), user.s_prv_key.clone(), user.p.clone());
            let k = sha256::digest(s.to_string());
            let mac = hmac_sha256::HMAC::mac(k, user.salt.clone().to_be_bytes());

            if mac == user_mac {
                println!("password = {}", line);
                ret = true;
                break;
            }
        }
        ret
    }
}

#[tokio::main]
async fn main() {
    let db = db::init_db();
    let user_routes = filters::user_routes(db);

    warp::serve(user_routes)
        .run(([127, 0, 0, 1], 9000))
        .await;
}
