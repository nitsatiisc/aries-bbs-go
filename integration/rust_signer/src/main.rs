use bbs::prelude::*;
use std::env;
use std::convert::TryInto;

fn parse_sig_bytes<T>(v: Vec<T>) -> [T; 112] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", 112, v.len()))
}

fn parse_pk_bytes<T>(v: Vec<T>) -> [T; 96] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", 96, v.len()))
}

fn main() {
    // messages needs to be kept in sync with the `messagesBytes`
    // vector in ../../rust_test.go
    let messages = vec![
        SignatureMessage::hash(b"message 1"),
        SignatureMessage::hash(b"message 2"),
        SignatureMessage::hash(b"message 3"),
        SignatureMessage::hash(b"message 4"),
        SignatureMessage::hash(b"message 5"),
    ];

    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        let (dpk, sk) = Issuer::new_short_keys(None);
        let pk = dpk.to_public_key(5).unwrap();
        let pk_bytes = dpk.to_bytes_compressed_form();
        let hex_string = hex::encode(pk_bytes);

        println!("PK: {}", hex_string);
        
        let signature = Signature::new(messages.as_slice(), &sk, &pk).unwrap();
        let bytes = signature.to_bytes_compressed_form();
        let hex_string = hex::encode(bytes);

        println!("sig: {}", hex_string);
    } else {
        let pk_hex = &args[1];
        let sig_hex = &args[2];

        let pk_bytes = hex::decode(pk_hex).unwrap();
        let sig_bytes = hex::decode(sig_hex).unwrap();

        let dpk = DeterministicPublicKey::from(parse_pk_bytes::<u8>(pk_bytes));
        let signature = Signature::from(parse_sig_bytes::<u8>(sig_bytes));

        let pk = dpk.to_public_key(5).unwrap();
        
        let res = signature.verify(messages.as_slice(), &pk);
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
