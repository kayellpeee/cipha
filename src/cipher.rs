/// encryption is similar to hashing without destructive operation
/// it also requires a key - or something to encrypt against
/// For a Feistel cipher we'll have to generate subkeys from the master key
/// One subkey is used per round and there can be multiple rounds of encryption
/// One approach would be to hash a key to generate the subkey, which is hashed
/// to generate the next subkey...so on so forth
/// This will take a simpler approach so decryption subkey generation is easier
pub fn feistel_encrypt(plaintext: &str, key: u32, rounds: u8) -> Vec<u32> {
    let mut _left: Vec<u8> = plaintext.bytes().collect();
    let plaintext_length: usize = _left.len();
    let mut _right: Vec<u8> = _left.split_off(plaintext_length / 2);
    let mut left: Vec<u32> = _left.into_iter().map(|x| x as u32).collect();
    let mut right: Vec<u32> = _right.into_iter().map(|x| x as u32).collect();
    let mut subkey: u32;
    let mut salty: u32;
    let mut updated_left: Vec<u32>;
    let mut updated_right: Vec<u32>;
    for x in 0..rounds {
        // Subkey should be as unique as possible
        salty = key.count_ones() - x as u32;
        subkey = key.wrapping_mul(salty);
        // L[i] = R[i - 1]
        updated_left = right.clone();
        // R[i] = L[i - 1] ⊕ f(r[i - 1], k[i])
        updated_right = Vec::new();
        right = round_fn(right, subkey);
        if left.len() <= right.len() {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ right[i]);
            }
        } else if left.len() > right.len() {
            for i in 0..right.len() {
                updated_right.push(left[i] ^ right[i]);
            }
            let last_index = left.len();
            updated_right.push(left[last_index - 1]);
        }
        right = updated_right;
        left = updated_left;
    }
    let mut _ciphertext: Vec<u32> = left.clone();
    _ciphertext.append(&mut right);
    let ciphertext = _ciphertext;
    ciphertext
}

/// Here lies the real brains of encryption algorithm...
/// Round function must take full advantage of the uniqueness of the subkey
/// in order to have a really strong encryption. And because round fn doesn't
/// *need* to be reversible, it could theoretically hash values with a subkey.
/// So we want round fn to have a large, well-distributed range. To do that
/// we'll increase (+ * ^) and decrease (- / %) several times to get a unique
/// byte.
fn round_fn(right: Vec<u32>, subkey: u32) -> Vec<u32> {
    let mut updated_right = Vec::new();
    let mut new_val: u32;
    for byte in right {
        new_val = byte.wrapping_mul(subkey.count_ones());
        new_val = subkey % new_val;
        new_val += (byte as f32).cbrt() as u32;
        new_val -= byte.count_ones();
        updated_right.push(new_val);
    }
    updated_right
}

pub fn feistel_decrypt(ciphertext: Vec<u32>, key: u32, rounds: u8) -> String {
    let mut right: Vec<u32> = ciphertext.clone();
    let mut left: Vec<u32> = right.split_off(ciphertext.len() / 2);
    let mut subkey: u32;
    let mut salty: u32;
    let mut updated_left: Vec<u32>;
    let mut updated_right: Vec<u32>;
    // because encryption went from [0, rounds) decryption should
    // generate subkeys for (rounds, 0]
    for x in 1..rounds + 1 {
        // only difference in encryption & decryption is order of subkeys
        salty = key.count_ones() - (rounds - x) as u32;
        subkey = key.wrapping_mul(salty);
        // l[i] = R[i - 1]
        updated_left = right.clone();
        // R[i] = L[i - 1] ⊕ f(r[i - 1], k[i])
        updated_right = Vec::new();
        right = round_fn(right, subkey);
        if left.len() <= right.len() {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ right[i]);
            }
        } else if left.len() > right.len() {
            for i in 0..right.len() {
                updated_right.push(left[i] ^ right[i]);
            }
            let last_index = left.len();
            updated_right.push(left[last_index - 1]);
        }
        right = updated_right;
        left = updated_left;
    }
    let right_u8 = right.into_iter().map(|x| x as u8).collect();
    let left_u8 = left.into_iter().map(|x| x as u8).collect();
    let decrypted_left = String::from_utf8(right_u8).unwrap();
    let decrypted_right = String::from_utf8(left_u8).unwrap();
    let mut plaintext: String = String::new();
    plaintext.push_str(&decrypted_left);
    plaintext.push_str(&decrypted_right);
    plaintext
}

