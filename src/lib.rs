extern crate base64;
extern crate byteorder;
extern crate crypto;
extern crate hex;
extern crate is_sorted;
extern crate itertools;
#[macro_use]
extern crate percent_encoding;
extern crate rand;

mod aes_cbc;
mod aes_ecb;
mod challenges;
mod ctr;
mod exception;
mod mt19937;
mod util;
mod xor;

use crate::aes_cbc::aes_128_cbc_encrypt;
use crate::aes_ecb::aes_128_ecb_encrypt;
use crate::util::generate_random_bytes;
use crate::util::map_blocks;

use crypto::symmetriccipher::SymmetricCipherError;
use itertools::Itertools;
use std::iter;
use std::str;

const ETAOIN: &str = " \neEtTaAoOiInNsShHrRlLdDuUcCmMwWyYfFgGpPbBvVkKjJxXqQzZ0123456789.,!?'\":;-";

pub enum EncryptionType {
    ECB,
    CBC(Vec<u8>),
}

pub fn encrypt_with_prefix_and_suffix(
    key: &[u8],
    prefix: &[u8],
    plaintext: &[u8],
    suffix: &[u8],
    encryption_type: EncryptionType,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut buffer = Vec::<u8>::new();
    buffer.extend(prefix);
    buffer.extend(plaintext);
    buffer.extend(suffix);

    match encryption_type {
        EncryptionType::CBC(iv) => aes_128_cbc_encrypt(key, &iv, &buffer),
        EncryptionType::ECB => aes_128_ecb_encrypt(key, &buffer, true),
    }
}

pub fn encryption_oracle(plaintext: &[u8]) -> Result<(Vec<u8>, bool), SymmetricCipherError> {
    let key = generate_random_bytes(16);
    let prefix = generate_random_bytes((rand::random::<f32>() * 5.0) as usize + 5);
    let suffix = generate_random_bytes((rand::random::<f32>() * 5.0) as usize + 5);
    if rand::random() {
        Ok((
            encrypt_with_prefix_and_suffix(&key, &prefix, plaintext, &suffix, EncryptionType::ECB)?,
            true,
        ))
    } else {
        let iv = generate_random_bytes(16);
        Ok((
            encrypt_with_prefix_and_suffix(
                &key,
                &prefix,
                plaintext,
                &suffix,
                EncryptionType::CBC(iv),
            )?,
            false,
        ))
    }
}

pub fn find_blocksize<F: Fn(&[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    encrypt_fn: &F,
) -> Option<usize> {
    let mut plaintext = Vec::<u8>::new();
    let initial = encrypt_fn(&plaintext).unwrap().len();
    let mut ciphertext;
    for _ in 0..2048 {
        plaintext.push(0u8);
        ciphertext = encrypt_fn(&plaintext).unwrap();
        if ciphertext.len() != initial {
            return Some(ciphertext.len() - initial);
        }
    }

    None
}

pub fn profile_for(email: &str, uid: usize, role: &str) -> String {
    let sanitized = email.replace("&", "").replace("=", "");
    let keys: Vec<String> = vec!["email".to_string(), "uid".to_string(), "role".to_string()];
    let values: Vec<String> = vec![sanitized.to_string(), uid.to_string(), role.to_string()];
    keys.iter()
        .zip(values.iter())
        .map(|(k, v)| format!("{}={}", k, v))
        .join("&")
}

pub fn find_prefix_length<F: Fn(&[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    encrypt_fn: &F,
) -> Option<usize> {
    let blocksize = find_blocksize(encrypt_fn).unwrap();

    let mut test_string: Vec<u8> = iter::repeat(b'A').take(blocksize * 2).collect::<Vec<u8>>();
    for padding in 0..blocksize {
        let ciphertext = encrypt_fn(&test_string).unwrap();
        let blocks = map_blocks(&ciphertext, blocksize);
        for i in 0..blocks.len() - 1 {
            if blocks[i] == blocks[i + 1] {
                return Some(blocksize * i - padding);
            }
        }
        test_string.push(b'A');
    }

    None
}

pub fn find_prefix_suffix_lengths<F: Fn(&[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    encrypt_fn: &F,
) -> (usize, usize) {
    let prefix_length = find_prefix_length(&encrypt_fn).unwrap();

    let mut test_string = vec![];
    let empty_ciphertext = encrypt_fn(&test_string).unwrap();
    let empty_ciphertext_len = empty_ciphertext.len();
    test_string.push(b'A');
    let mut ciphertext = encrypt_fn(&test_string).unwrap();
    while ciphertext.len() == empty_ciphertext_len {
        test_string.push(b'A');
        ciphertext = encrypt_fn(&test_string).unwrap();
    }

    (
        prefix_length,
        empty_ciphertext_len - prefix_length - test_string.len(),
    )
}

#[cfg(test)]
mod tests {
    //use brute_force_xor_key;
    use crate::encrypt_with_prefix_and_suffix;
    use crate::find_prefix_length;
    use crate::find_prefix_suffix_lengths;
    use crate::generate_random_bytes;
    use crate::profile_for;
    use crate::EncryptionType;

    #[test]
    fn test_key_value_encode() {
        assert_eq!(
            "email=foo@bar.com&uid=10&role=user",
            profile_for("foo@bar.com", 10, "user")
        );
        assert_eq!(
            "email=foo@bar.com&uid=10&role=user",
            profile_for("foo&@bar=.com", 10, "user")
        );
    }

    #[test]
    fn test_find_prefix_length() {
        let prefix_size = rand::random::<u8>() as usize;
        let prefix = generate_random_bytes(prefix_size);
        let key = generate_random_bytes(16);
        let suffix_size = rand::random::<u8>() as usize;
        let suffix = generate_random_bytes(suffix_size);
        let encrypt = |plaintext: &[u8]| {
            encrypt_with_prefix_and_suffix(&key, &prefix, plaintext, &suffix, EncryptionType::ECB)
        };
        let found_size = find_prefix_length(&encrypt);
        assert_eq!(prefix_size, found_size.unwrap());
    }

    #[test]
    fn test_find_suffix_length() {
        let prefix_size = rand::random::<u8>() as usize;
        let prefix = generate_random_bytes(prefix_size);
        let key = generate_random_bytes(16);
        let suffix_size = rand::random::<u8>() as usize;
        let suffix = generate_random_bytes(suffix_size);
        let encrypt = |plaintext: &[u8]| {
            encrypt_with_prefix_and_suffix(&key, &prefix, plaintext, &suffix, EncryptionType::ECB)
        };
        let (_, found_size) = find_prefix_suffix_lengths(&encrypt);
        assert_eq!(suffix_size, found_size);
    }
}
