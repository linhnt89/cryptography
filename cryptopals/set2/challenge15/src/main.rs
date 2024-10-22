use aes;

fn main() {
    let removed1 = aes::remove_padding("ICE ICE BABY\x04\x04\x04\x04".as_bytes().to_vec());
    assert_eq!("ICE ICE BABY".as_bytes().to_vec(), removed1);
    let removed2 = aes::remove_padding("ICE ICE BABY\x05\x05\x05\x05".as_bytes().to_vec());
    assert_eq!("ICE ICE BABY\x05\x05\x05\x05".as_bytes().to_vec(), removed2);
    let removed3 = aes::remove_padding("ICE ICE BABY\x01\x02\x03\x04".as_bytes().to_vec());
    assert_eq!("ICE ICE BABY\x01\x02\x03\x04".as_bytes().to_vec(), removed3);
}
