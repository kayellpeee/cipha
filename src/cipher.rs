/// encryption is similar to hashing without destructive operation
/// it also requires a key - or something to encrypt against
/// For a Feistel cipher we'll have to generate subkeys from the master key
/// One subkey is used per round and there can be multiple rounds of encryption
/// One approach would be to hash a key to generate the subkey, which is hashed
/// to generate the next subkey...so on so forth
/// This will take a simpler approach so decryption subkey generation is easier
pub fn feistel_encrypt(plaintext: &str, key: u8, rounds: u8) -> Vec<u8> {
    let mut left: Vec<u8> = plaintext.bytes().collect();
    let plaintext_length: usize = left.len();
    let mut right: Vec<u8> = left.split_off(plaintext_length / 2);
    let mut subkey: u8;
    let mut updated_left: Vec<u8>;
    let mut updated_right: Vec<u8>;
    println!("About to encrypt!\nleft {:?}\nright {:?}", left, right);
    for x in 0..rounds {
        subkey = key.clone().rotate_right(x as u32);
        // L[i] = R[i - 1]
        updated_left = right.clone();
        // R[i] = L[i - 1] ⊕ f(r[i - 1], k[i])
        updated_right = Vec::new();
        right = encrypt_helper(right, subkey);
        if left.len() < right.len() {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ right[i]);
            }
        } else if left.len() > right.len() {
            for i in 0..right.len() {
                updated_right.push(left[i] ^ right[i]);
            }
            let last_index = left.len();
            updated_right.push(left[last_index - 1]);
        } else {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ right[i]);
            }
        }
        right = updated_right;
        left = updated_left;
        println!("On round {:?}/{:?} of encryption\n\tleft {:?}\n\tright {:?}
                \tsubkey {:?}", x + 1, rounds, left, right, subkey);
    }
    let mut _ciphertext: Vec<u8> = left.clone();
    _ciphertext.append(&mut right);
    let ciphertext = _ciphertext;
    println!("fully encrypted - {:?}", &ciphertext);
    ciphertext
}

fn encrypt_helper(right: Vec<u8>, subkey: u8) -> Vec<u8> {
    let mut added_right = Vec::new();
    for byte in right.clone() {
        byte.wrapping_add(subkey);
        added_right.push(byte);
    }
    added_right
}

pub fn feistel_decrypt(ciphertext: Vec<u8>, key: u8, rounds: u8) -> String {
    let mut right: Vec<u8> = ciphertext.clone();
    let mut left: Vec<u8> = right.split_off(ciphertext.len() / 2);
    let mut subkey: u8;
    let mut updated_left: Vec<u8>;
    let mut updated_right: Vec<u8>;
    // because encryption went from [0, rounds) decryption should
    // generate subkeys for (rounds, 0]
    for x in 1..rounds + 1 {
        // only difference in encryption & decryption is order of subkeys
        // and reversible round function
        subkey = key.clone().rotate_right((rounds - x) as u32);
        // l[i] = R[i - 1]
        updated_left = right.clone();
        // R[i] = L[i - 1] ⊕ f(r[i - 1], k[i])
        updated_right = Vec::new();
        right = decrypt_helper(right, subkey);
        if left.len() < right.len() {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ right[i]);
            }
        } else if left.len() > right.len() {
            for i in 0..right.len() {
                updated_right.push(left[i] ^ right[i]);
            }
            let last_index = left.len();
            updated_right.push(left[last_index - 1]);
        } else {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ right[i]);
            }
        }
        right = updated_right;
        left = updated_left;
        println!("On round {:?}/{:?} of decryption\n\tleft {:?}\n\tright {:?}
                 \tsubkey {:?}", x, rounds, left, right, subkey);
    }
    let decrypted_left = String::from_utf8(right).unwrap();
    let decrypted_right = String::from_utf8(left).unwrap();
    let mut plaintext: String = String::new();
    plaintext.push_str(&decrypted_left);
    plaintext.push_str(&decrypted_right);
    println!("fully decrypted!\n{:?}", &plaintext);
    plaintext
}

fn decrypt_helper(right: Vec<u8>, subkey: u8) -> Vec<u8> {
    let mut subtracted_right = Vec::new();
    for byte in right.clone() {
        byte.wrapping_sub(subkey);
        subtracted_right.push(byte);
    }
    subtracted_right
}

