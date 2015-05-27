/// encryption is similar to hashing without destructive operation
/// it also requires a key - or something to encrypt against
/// For a Fiestel cipher we'll have to generate subkeys from the master key
/// One subkey is used per round and there can be multiple rounds of encryption
/// One approach would be to hash a key to generate the subkey, which is hashed
/// to generate the next subkey...so on so forth
/// This will take a simpler approach so decryption subkey generation is easier
fn fiestel_encrypt(message: &str, key: i32, rounds: isize) -> str {
    // basic subkey generation: take element at key[round] (1st turn key to vec)
    // ^ because easily reversible for decryption
    // break message into character bytes
    // add subkey to byte for this round
    // parse into chars again, return as unified str
}
#[test]
fn it_works() {
}
