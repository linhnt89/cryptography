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
    }

    #[derive(PartialEq, PartialOrd, Clone, Debug)]
    pub struct UserInfo {
        pub email: String,
        pub password: String,
        pub c_pub_key: UBig,
        pub s_pub_key: UBig,
        pub s_prv_key: UBig,
        pub salt: UBig,
        pub v: UBig,
        pub p: UBig,
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
        
        let k = ubig!(3);

        let (p, g) = dh::get_p_g(dh::DHMODE::FFDHE2048);
        let (prk, _) = dh::get_keypair(dh::DHMODE::FFDHE2048);


        let salt = thread_rng().gen_range(ubig!(100)..ubig!(1000));
        // println!("salt = {:02x?}", &salt);
        let saltpass = [&salt.to_be_bytes(), new_user.password.clone().as_bytes()].concat();
        let x = sha256::digest_bytes(&saltpass);
        // println!("sha256 digest = {:?}", &x);
        let x = UBig::from_str_radix(&x, 16).unwrap();
        // println!("x = {:?}", &x);
        let v = dh::modular_pow(g.clone(), x, p.clone());

        // let puk = (k * v.clone() + dh::modular_pow(g, prk.clone(), p.clone())) % p.clone();
        let puk = k * v.clone() + dh::modular_pow(g, prk.clone(), p.clone());
        
        let user = models::UserInfo {
            email: new_user.email,
            password: new_user.password,
            c_pub_key: ubig!(0),
            s_pub_key: puk,
            s_prv_key: prk,
            salt,
            v,
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
        };
        let ret = warp::reply::json(&sinf);

        for user in users.iter_mut() {
            if user.email == user_key.email {
                user.c_pub_key = UBig::from_be_bytes(&user_key.pub_key);
                // println!("user public key = {:?}", &user.c_pub_key);

                // println!("server public key = {:?}", &user.s_pub_key);
                sinf = models::ServerKey {
                    salt: user.salt.clone().to_be_bytes(),
                    pub_key: user.s_pub_key.clone().to_be_bytes(),
                };
                return Ok(warp::reply::json(&sinf))
            }
        }

        Ok(ret)
    }

    pub async fn compare_mac(user_mac: models::UserMac, db: db::Db) -> Result<impl warp::Reply, Infallible> {
        let users = db.lock().await;

        for user in users.iter() {
            if user.email == user_mac.email {
                // let mut pukcs = user.c_pub_key.clone().to_string();
                // pukcs.push_str(&user.s_pub_key.clone().to_string());
                // let u = UBig::from_str_radix(&sha256::digest(pukcs), 16).unwrap();
                let pukcs = [user.c_pub_key.clone().to_be_bytes(), user.s_pub_key.clone().to_be_bytes()].concat();
                let u = UBig::from_str_radix(&sha256::digest_bytes(&pukcs), 16).unwrap();
                // println!("u = {:?}", &u);
                    
                let s = dh::modular_pow(user.c_pub_key.clone() * dh::modular_pow(user.v.clone(), u, user.p.clone()), user.s_prv_key.clone(), user.p.clone());
                // println!("s = {}", &s);
                let k = sha256::digest(s.to_string());
                // println!("k = {}", &k);
                let mac = hmac_sha256::HMAC::mac(k, user.salt.clone().to_be_bytes());

                // // println!("user mac = {:02x?}", &user_mac.mac);
                // // println!("server mac = {:02x?}", &mac);

                if  mac == user_mac.mac {
                    return Ok(warp::http::StatusCode::OK);
                }
            }
        }
        Ok(warp::http::StatusCode::NOT_ACCEPTABLE)
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


#[cfg(test)]
mod tests {
    use warp::http::StatusCode;
    use warp::test::request;

    use super::*;

    #[tokio::test]
    async fn test_get_user_info() {
        let user = models::User {
            email : "test@gmail.com".to_string(),
            password : "1234".to_string()
        };
        let db = db::init_db();

        let filter = filters::create_user(db.clone());

        let res = request()
            .method("POST")
            .path("/user")
            .json(&user)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);

        let mut users = db.lock().await;
        let user_db = users.pop().unwrap();
        assert_eq!(user.email, user_db.email);
        assert_eq!(user.password, user_db.password);
        assert_eq!(ubig!(0), user_db.c_pub_key);
    }

    #[test]
    fn test_ubig_string() {
        let a = ubig!(0xfe38);
        let b = a.clone().to_be_bytes();
        let c = UBig::from_be_bytes(&b);
        assert_eq!(a, c);
    }

}