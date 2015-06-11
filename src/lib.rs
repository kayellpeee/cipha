#![feature(collections)]
mod cipher;

pub use cipher::feistel_encrypt;
pub use cipher::feistel_decrypt;
#[test]
fn it_works() {
    let ciphertext = feistel_encrypt("keenan", 19, 4);
    let plaintext = feistel_decrypt(ciphertext, 19, 4);
    assert_eq!("keenan", plaintext);
    let odd_ciphertext = feistel_encrypt("ricky", 110, 2);
    let odd_plaintext = feistel_decrypt(odd_ciphertext, 110, 2);
    assert_eq!("ricky", odd_plaintext);
}
#[test]
fn it_works_larger() {
    // shouldn't error with larger key for longer rounds
    let ciphertext = feistel_encrypt("Larger string", 10091993, 32);
    let plaintext = feistel_decrypt(ciphertext, 10091993, 32);
    assert_eq!("Larger string", plaintext);
}
#[test]
fn max_key_rounds() {
    // should work for max u32 u8
    let ciphertext = feistel_encrypt("The quick brown fox", 4294967295, 255);
    let plaintext = feistel_decrypt(ciphertext, 4294967295, 255);
    assert_eq!("The quick brown fox", plaintext);
}
/// One "metric" of an encryption protocol's strength is how little relation
/// there is between the inputs and outputs. AKA there must be either
/// a random difference between input and output, or a consistent output
/// regardless of input
/// i.e. either
///  "a" -> 7, "b" -> 42, "c" -> 0.1451, "de" -> 6623
///  or
///  "a" -> 1.013, "b" -> 1.003, "c" -> 1.201, "de" -> 1.031
/// Both are really hard to draw patterns from & thus reverse engineer the
/// encryption algorithm. To test this we'll find the difference b/w input and
/// output and see if similar inputs map to similar outputs (not random) as long
/// as all inupts don't map to similar outputs (consistent).
#[test]
}
