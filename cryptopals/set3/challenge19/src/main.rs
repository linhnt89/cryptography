use std::collections::HashMap;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use base64;
use aes;

fn main() {
    let key = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(u8::from)
        .collect::<Vec<u8>>();
    let iv = [0u8; 16];
    let pts = vec![
        base64::decode("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==").unwrap(),
        base64::decode("Q29taW5nIHdpdGggdml2aWQgZmFjZXM=").unwrap(),
        base64::decode("RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==").unwrap(),
        base64::decode("RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=").unwrap(),
        base64::decode("SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk").unwrap(),
        base64::decode("T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==").unwrap(),
        base64::decode("T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=").unwrap(),
        base64::decode("UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==").unwrap(),
        base64::decode("QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=").unwrap(),
        base64::decode("T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl").unwrap(),
        base64::decode("VG8gcGxlYXNlIGEgY29tcGFuaW9u").unwrap(),
        base64::decode("QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==").unwrap(),
        base64::decode("QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=").unwrap(),
        base64::decode("QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==").unwrap(),
        base64::decode("QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=").unwrap(),
        base64::decode("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").unwrap(),
        base64::decode("VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==").unwrap(),
        base64::decode("SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==").unwrap(),
        base64::decode("SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==").unwrap(),
        base64::decode("VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==").unwrap(),
        base64::decode("V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==").unwrap(),
        base64::decode("V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==").unwrap(),
        base64::decode("U2hlIHJvZGUgdG8gaGFycmllcnM/").unwrap(),
        base64::decode("VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=").unwrap(),
        base64::decode("QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=").unwrap(),
        base64::decode("VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=").unwrap(),
        base64::decode("V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=").unwrap(),
        base64::decode("SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==").unwrap(),
        base64::decode("U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==").unwrap(),
        base64::decode("U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=").unwrap(),
        base64::decode("VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==").unwrap(),
        base64::decode("QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu").unwrap(),
        base64::decode("SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=").unwrap(),
        base64::decode("VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs").unwrap(),
        base64::decode("WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=").unwrap(),
        base64::decode("SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0").unwrap(),
        base64::decode("SW4gdGhlIGNhc3VhbCBjb21lZHk7").unwrap(),
        base64::decode("SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=").unwrap(),
        base64::decode("VHJhbnNmb3JtZWQgdXR0ZXJseTo=").unwrap(),
        base64::decode("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=").unwrap(),
    ];
    let ciphers = pts.iter()
        .map(|pt| aes::ctr_encrypt(pt, &key, &iv, 128, 
            aes::ENDIAN::BIG, &aes::AESKIND::AES128))
        .collect::<Vec<Vec<u8>>>();
    let mut arranged_ciphers = Vec::new();
    for i in 0.. {
        let mut tmp = Vec::new();
        ciphers.iter().for_each(|cipher| {
            match cipher.get(i) {
                Some(x) => tmp.push(*x),
                None => (),
            }
        });
        if tmp.is_empty() {
            break;
        } else {
            arranged_ciphers.push(tmp);
        }
    }
    let keystream = arranged_ciphers.iter()
        .map(|block| find_xored_char(block))
        .collect::<Vec<u8>>();
    ciphers.iter().for_each(|cipher| {
        let pt = cipher.iter().zip(keystream.iter())
            .map(|(&a, &b)| a^b)
            .collect::<Vec<u8>>();
        println!("{}", String::from_utf8(pt).unwrap());
    });
}

fn find_xored_char(input_v: &[u8]) -> u8 {
    let mut coefficient = 0.0;
    let mut xored_char: u8 = 0;
    (0..=255 as u8).into_iter().for_each(|i| {
        let xored_v = input_v.iter().map(|b| b ^ i).collect::<Vec<u8>>();
        let new_coefficient = englishness(xored_v);
        if new_coefficient > coefficient {
            coefficient = new_coefficient;
            xored_char = i;
        }
    });
    xored_char
}

fn englishness(decrypted_u8_vec: Vec<u8>) -> f64 {
    let eng_expected_frq = HashMap::from([
        (0x45 as u8, 13.0), // E
        (0x54 as u8, 9.6), // T
        (0x41 as u8, 8.2), // A
        (0x4F as u8, 7.8), // O
        (0x49 as u8, 6.9), // I
        (0x4E as u8, 6.7), // N
        (0x48 as u8, 6.2), // H
        (0x53 as u8, 6.2), // S
        (0x52 as u8, 5.9), // R
        (0x44 as u8, 4.7), // D
        (0x4C as u8, 4.0), // L
        (0x43 as u8, 2.7), // C
        (0x4D as u8, 2.7), // M
        (0x55 as u8, 2.7), // U
        (0x57 as u8, 2.4), // W
        (0x46 as u8, 2.2), // F
        (0x47 as u8, 2.0), // G
        (0x59 as u8, 2.0), // Y
        (0x50 as u8, 1.9), // P
        (0x42 as u8, 1.5), // B
        (0x56 as u8, 0.97), // V
        (0x4B as u8, 0.81), // K
        (0x4A as u8, 0.16), // J
        (0x58 as u8, 0.15), // X
        (0x51 as u8, 0.11), // Q
        (0x5A as u8, 0.078), // Z
        (0x20 as u8, 0.01), // Space (additional to remove the wrong similar result)
    ]);

    // The Bhattacharyya coefficient is a fairly intuitive measure of
    // overlap of two different distributions: for each point in the distribution,
    // multiply the probability for each distribution together, then take the
    // square root. Sum all the probabilities together, and you get your
    // coefficient.
    let mut chr_cnt = HashMap::new();
    decrypted_u8_vec.iter().for_each(|&c| {
        let counter = chr_cnt.entry(c).or_insert(0.0);
        *counter += 1.0;
    });
    let mut coefficient = 0.0;
    for (c, cnt) in &chr_cnt {
        let expected_frq = match eng_expected_frq.get(&c.to_ascii_uppercase()) {
            Some(&f)   => f,
            None            => 0.0, 
        };
        coefficient += (expected_frq * cnt / decrypted_u8_vec.len() as f64).sqrt();
    }
    coefficient
}
