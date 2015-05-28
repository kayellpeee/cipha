#![feature(collections)]
/// encryption is similar to hashing without destructive operation
/// it also requires a key - or something to encrypt against
/// For a Feistel cipher we'll have to generate subkeys from the master key
/// One subkey is used per round and there can be multiple rounds of encryption
/// One approach would be to hash a key to generate the subkey, which is hashed
/// to generate the next subkey...so on so forth
/// This will take a simpler approach so decryption subkey generation is easier
mod encrypt;

pub use encrypt::feistel_encrypt;
#[test]
fn it_works() {
    let result = feistel_encrypt("test", 123, 3);
    println!("here's simple result {:?}", result);
    panic!("lemme see std_out rust");
}
