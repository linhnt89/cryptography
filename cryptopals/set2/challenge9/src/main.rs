use aes;

fn main() {
    let s = "YELLOW SUBMARINE".as_bytes().to_vec();
    assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes().to_vec(), aes::padding(s, 20));
}
