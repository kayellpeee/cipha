/// encryption is similar to hashing without destructive operation
/// it also requires a key - or something to encrypt against
/// For a Feistel cipher we'll have to generate subkeys from the master key
/// One subkey is used per round and there can be multiple rounds of encryption
/// One approach would be to hash a key to generate the subkey, which is hashed
/// to generate the next subkey...so on so forth
/// This will take a simpler approach so decryption subkey generation is easier
fn feistel_encrypt(message: &str, key: i32, rounds: isize) -> &str {
    let mut left: Vec<_> = message.bytes().collect();
    let mut right: Vec<_> = left.split_off((left.len() / 2).floor());
    let mut subkey: usize;
    let mut updated_left: Vec<_>;
    let mut updated_right: Vec<_>;
    for x in 0..rounds {
        subkey = key.rotate_right(x);
        // L[i] = R[i - 1]
        updated_left = right;
        // R[i] = L[i - 1] ⊕ f(r[i - 1], k[i])
        updated_right = left ^ encrypt_helper(right, subkey);
        right = updated_right;
        left = updated_left;
    }
    println!("Finished all {:?} rounds\nleft {:?}\nright {:?}",
             rounds, left, right);
    message
}
fn encrypt_helper(right: Vec<u8>, subkey: i32) -> Vec<u8> {
    println!("before running helper - {:?}", right);
    for byte in right {
        byte += subkey;
    }
    println!("ran helper with subkey {:?} - {:?}", subkey, right);
    right
}
#[test]
fn it_works() {
    use super::feistel_encrypt;
    let result = feistel_encrypt("test", 123, 3);
    println!("here's simple result {:?}", result);
}
