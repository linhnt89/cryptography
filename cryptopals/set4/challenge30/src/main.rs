use rand::{thread_rng, Rng, distributions::Alphanumeric};
use md;
use md4::{self, Digest};

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(thread_rng().gen_range(1..100))
        .map(u8::from)
        .collect::<Vec<u8>>();
    let msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        .as_bytes();
    let new_text = ";admin=true".as_bytes();
    let mac = get_mac(&key, &msg);
    let mut mac32 = Vec::new();
    let mut i = 0;
    while i < mac.len() {
        let n = ((mac[i+3] as u32) << 24) 
            | ((mac[i+2] as u32) << 16) 
            | ((mac[i+1] as u32) << 8) 
            | mac[i] as u32;
            mac32.push(n);
        i += 4;
    }
    let mut key_len = 1;
    loop {
        let padded_msg = find_padding(key_len, msg);
        let new_mac = md::MD4::hash(
            new_text, &mac32, padded_msg.len() + key_len);
        let new_msg = [&padded_msg, new_text].concat();
        if new_mac == get_mac(&key, &new_msg) {
            println!("key length = {}", key_len);
            break;
        }
        key_len += 1;
    }
}

fn get_mac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let keyed_msg = [key, msg].concat();
    let mut hasher = md4::Md4::new();
    hasher.update(keyed_msg);
    let mac = hasher.finalize().to_vec();
    mac
}

fn find_padding(key_len: usize, msg: &[u8]) -> Vec<u8> {
    let original_msg_len = msg.len() * 8;
    // MD4 has the following properties :
    // - 1 block = 512 bits
    // - final block has to reserve 64 last bits for the length of the message + 1 bit for '1'
    // => if the message length > 512 - 64 - 1 => pad more blocks
    let mut padded_msg = msg.clone().to_vec();
    let keyed_msg_len = key_len*8 + original_msg_len;
    let mut padded_msg_len = 512;
    if keyed_msg_len > 512 - 64 - 1 {
        padded_msg_len *= ((keyed_msg_len - (512 - 64 - 1)) / 512) + 2;
    }
    let zero_bytes_len = (padded_msg_len - keyed_msg_len - 64 - 8) / 8;
    padded_msg.push(0x80);
    padded_msg.append(&mut vec![0u8; zero_bytes_len]);
    let mut padded_l = (keyed_msg_len as u64).to_le_bytes().to_vec();
    padded_msg.append(&mut padded_l);
    padded_msg
}