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

    let odd_rounds_ciphertext = feistel_encrypt("julian", 92, 5);
    let odd_rounds_plaintext = feistel_decrypt(odd_rounds_ciphertext, 92, 5);
    assert_eq!("julian", odd_rounds_plaintext);
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
/// encryption algorithm. To test this we'll find the difference b/w input and
/// output and see if similar inputs map to similar outputs (not random) as long
/// as all inupts don't map to similar outputs (consistent).
#[test]
fn delta() {
    let plain_alphabet = "abcdefghijklmnopqrstuvwxyz";
    let cipher_alphabet = feistel_encrypt(plain_alphabet, 42, 5);
    let mut delta: u32;
    let mut average_delta: u32 = 0;
    let mut max_delta: u32 = 0;
    for tuple in plain_alphabet.bytes().enumerate() {
        if cipher_alphabet[tuple.0] > tuple.1 as u32 {
            delta = cipher_alphabet[tuple.0] - tuple.1 as u32;
        } else {
            delta =  tuple.1 as u32 - cipher_alphabet[tuple.0];
        }
        average_delta += (delta / cipher_alphabet.len() as u32);
        if delta > max_delta {
           max_delta = delta;
        }
        println!("tuple {:?} delta {:?}", tuple, delta);
    }
    println!("average delta\t {:?}", average_delta);
    println!("max delta\t\t {:?}", max_delta);

    // These aren't really tests, just printing results to get a sense of what's
    // going on. Well set up defined tests later, which will probably be similar
    // to benchmark tests——used for insight not testing code functionality
    let plain_message = "Perhaps it was because I was a younger man and more
    impressionable.";
    let cipher_message = feistel_encrypt(plain_message, 1381964, 32);
    average_delta = 0;
    max_delta = 0;
    for tuple in plain_message.bytes().enumerate() {
        if cipher_message[tuple.0] > tuple.1 as u32 {
            delta = cipher_message[tuple.0] - tuple.1 as u32;
        } else {
            delta =  tuple.1 as u32 - cipher_message[tuple.0];
        }
       average_delta += (delta / cipher_message.len() as u32);;
       if delta > max_delta {
           max_delta = delta;
       }
       println!("tuple {:?} delta {:?}", tuple, delta);
    }
    println!("average delta\t {:?}", average_delta);
    println!("max delta\t\t {:?}", max_delta);
    assert!(false);
}
