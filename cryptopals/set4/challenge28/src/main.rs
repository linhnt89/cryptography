use rand::{thread_rng, Rng, distributions::Alphanumeric};
use sha;

fn main() {
    let mut msg = vec![0u8; 100];
    let mac1 = get_mac(&msg);
    msg[0] = 1; // modify msg
    let mac2 = get_mac(&msg);
    assert_ne!(mac1, mac2);
}

fn get_mac(msg: &[u8]) -> Vec<u32> {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let keyed_msg = [&key, msg].concat();
    sha::SHA1::hash(&keyed_msg, &Vec::new(), 0)
}