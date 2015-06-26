#![feature(test)]
extern crate test;
extern crate cipher;
use cipher::feistel_encrypt;
use cipher::feistel_decrypt;

#[test]
fn it_works() {
    let ciphertext = feistel_encrypt("keenan", 19, 4);
    let plaintext = feistel_decrypt(ciphertext, 19, 4);
    assert_eq!("keenan", plaintext);

    let odd_ciphertext = feistel_encrypt("ricky", 110, 2);
    let odd_plaintext = feistel_decrypt(odd_ciphertext, 110, 2);
    assert_eq!("ricky", odd_plaintext);

    let odd_round_ciphertext = feistel_encrypt("julian", 92, 5);
    let odd_round_plaintext = feistel_decrypt(odd_round_ciphertext, 92, 5);
    assert_eq!("julian", odd_round_plaintext);
}

#[test]
fn it_works_larger() {
    // shouldn't error with larger key for longer rounds
    let ciphertext = feistel_encrypt("Larger string", 10091993, 32);
    let plaintext = feistel_decrypt(ciphertext, 10091993, 32);
    assert_eq!("Larger string", plaintext);

    let odd_rounds_even_ciphertext = feistel_encrypt(
        "Some odd rounds even str", 564738291, 25);
    let odd_rounds_even_plaintext = feistel_decrypt(
        odd_rounds_even_ciphertext, 564738291, 25);
    assert_eq!("Some odd rounds even str", odd_rounds_even_plaintext);

    let odd_rounds_ciphertext = feistel_encrypt(
        "Some odd rounds", 564738291, 25);
    let odd_rounds_plaintext = feistel_decrypt(
        odd_rounds_ciphertext, 564738291, 25);
    assert_eq!("Some odd rounds", odd_rounds_plaintext);
}

#[test]
fn max_key_rounds() {
    // should work for max u32 u8
    let even_ciphertext = feistel_encrypt(
        "The quick blue fox", 4294967295, 255);
    let even_plaintext = feistel_decrypt(
        even_ciphertext, 4294967295, 255);
    assert_eq!("The quick blue fox", even_plaintext);

    let odd_ciphertext = feistel_encrypt(
        "The quick brown fox", 4294967295, 255);
    let odd_plaintext = feistel_decrypt(odd_ciphertext, 4294967295, 255);
    assert_eq!("The quick brown fox", odd_plaintext);
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
/// encryption algorithm. To test this we'll find the difference b/w input
/// and output and see if similar inputs map to similar outputs (not random)
/// as long as all inupts don't map to similar outputs (consistent).
///   note: This is not necessarily a test of the code or this
///   implementation of a feistel cipher, but a test of feistel ciphers
///   themselve. Take it with a grain of salt
#[test]
fn variance() {
    // all a's - should either have flat variance (nothing outside a certain
    // range) - or "chaotic" variance (no large amount in same relatively
    // small range
    let plain_ayes = "abcdefghijklmnopqrstuvwxyz";
    let cipher_ayes = feistel_encrypt(plain_ayes, 186220, 217);
    let mean: f32= (cipher_ayes.iter().fold(0, |sum, x| sum + x)
        / cipher_ayes.len() as u32) as f32;
    let mut variance: f32 = 0_f32;
    for x in cipher_ayes.iter() {
        variance += (*x as f32 - mean).powi(2);
    }
    variance = variance / cipher_ayes.len() as f32;
    let standard_deviation = variance.sqrt();
    // let's say encrypted bytes should have a standard deviation at least
    // 40% of the mean OR 5% of it (very large vs. very small variance)
    let teir_1: f32 = 0.40;
    let teir_2: f32 = 0.05;
    assert!(standard_deviation / mean > teir_1 ||
           standard_deviation / mean < teir_2);
}

