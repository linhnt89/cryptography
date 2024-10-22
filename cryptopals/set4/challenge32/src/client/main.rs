use hex;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use std::time::{Instant};
use std::collections::HashMap;

// This is using the `tokio` runtime. You'll need the following dependency:
//
// `tokio = { version = "1", features = ["full"] }`
#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    let file = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect::<String>();
    let mut sign = vec![0u8; 20];
    let mut index = 0;

    'outer: loop {
        let mut v2 = HashMap::new();
        for _ in 0..10 {
            let mut v = Vec::new();
            for i in 0..u8::MAX {
                let mut url = String::from("http://localhost:9000/test?");
                url += "file=";
                url += &file;
                url += "&signature=";
                let signature = hex::encode(&sign);
                url += &signature;
        
                eprintln!("Fetching {:?}...", url);
                    
                // reqwest::get() is a convenience function.
                //
                // In most cases, you should create/build a reqwest::Client and reuse
                // it for all requests.
                let start = Instant::now();
                let res = reqwest::get(url).await?;
                let duration = start.elapsed().as_millis();
    
                if res.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
                    v.push((duration, i));
                    sign[index] += 1;
                } else {
                    eprintln!("Response: {:?} {}", res.version(), res.status());
                    eprintln!("Headers: {:#?}\n", res.headers());
            
                    let body = res.text().await?;
            
                    println!("{}", body);
                    break 'outer;                
                }
            }
            v.sort_by_key(|k| k.0);
            *v2.entry(v[u8::MAX as usize -1].1).or_insert(0) += 1;    
            sign[index] = 0;
        }
        let top_char = v2.iter().max_by(|a, b| a.1.cmp(&b.1)).unwrap();
        sign[index] = *top_char.0;
        index += 1;
    }

    Ok(())
}

// The [cfg(not(target_arch = "wasm32"))] above prevent building the tokio::main function
// for wasm32 target, because tokio isn't compatible with wasm32.
// If you aren't building for wasm32, you don't need that line.
// The two lines below avoid the "'main' function not found" error when building for wasm32 target.
#[cfg(target_arch = "wasm32")]
fn main() {}
