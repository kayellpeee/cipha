#![feature(collections)]
/// encryption is similar to hashing without destructive operation
/// it also requires a key - or something to encrypt against
/// For a Feistel cipher we'll have to generate subkeys from the master key
/// One subkey is used per round and there can be multiple rounds of encryption
/// One approach would be to hash a key to generate the subkey, which is hashed
/// to generate the next subkey...so on so forth
/// This will take a simpler approach so decryption subkey generation is easier
mod cipher;

pub use cipher::feistel_encrypt;
pub use cipher::feistel_decrypt;
#[test]
fn it_works() {
    let ciphertext = feistel_encrypt("keenan", 19, 4);
    let plaintext = feistel_decrypt(ciphertext, 19, 4);
    assert_eq!("keenan", plaintext);
}
#[test]
fn odd_length_message() {
    let ciphertext = feistel_encrypt("ricky", 110, 2);
    let plaintext = feistel_decrypt(ciphertext, 110, 2);
    assert_eq!("ricky", plaintext);
}
