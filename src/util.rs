use crate::aes_cbc::aes_128_cbc_encrypt;
use crate::aes_ecb::aes_128_ecb_encrypt;
use crate::exception::CryptoError;
use crypto::symmetriccipher::SymmetricCipherError;
use itertools::Itertools;
use std::collections::HashMap;
use std::error::Error;
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::{BufRead, BufReader};
use std::iter;
use std::str;

pub const ETAOIN: &str =
    " \neEtTaAoOiInNsShHrRlLdDuUcCmMwWyYfFgGpPbBvVkKjJxXqQzZ0123456789.,!?'\":;-";

pub enum EncryptionType {
    ECB,
    CBC(Vec<u8>),
}

#[cfg(test)]
pub fn hex_to_base64(hex_string: &str) -> Result<String, Box<Error>> {
    let binary = hex::decode(hex_string)?;
    Ok(base64::encode(&binary))
}

pub fn xor(first: &[u8], second: &[u8]) -> Result<Vec<u8>, Box<Error>> {
    assert_eq!(first.len(), second.len());

    Ok(first
        .iter()
        .zip(second.iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>())
}

#[cfg(test)]
pub fn read_base64_file(filename: &str) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        data.append(&mut base64::decode(&line.unwrap()).unwrap());
    }

    data
}

#[cfg(test)]
pub fn read_base64_file_line_by_line(filename: &str) -> Vec<Vec<u8>> {
    let mut data: Vec<Vec<u8>> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        data.push(base64::decode(&line.unwrap()).unwrap());
    }

    data
}

// Get a list of the characters in the string, ordered by frequency
pub fn get_character_histogram(string: &[u8]) -> Vec<u8> {
    let histogram = string.iter().fold(HashMap::<u8, usize>::new(), |mut h, c| {
        if h.contains_key(c) {
            let count = h.get_mut(c).unwrap();
            *count += 1;
        } else {
            h.insert(*c, 1);
        }
        h
    });

    let mut list = histogram.into_iter().collect::<Vec<(u8, usize)>>();
    // Sort in decreasing order of count
    list.sort_by(|(_ch1, count1), (_ch2, count2)| count2.cmp(count1));

    list.into_iter().map(|(c, _)| c).collect()
}

// Score text based on frequency of letters we expect to be frequent
pub fn score_text(string_data: &[u8]) -> usize {
    let mut score: usize = 0;
    if let Ok(string) = str::from_utf8(string_data) {
        for ch in string.chars() {
            match ch {
                ' ' => score += 7,
                'e' => score += 6,
                'E' => score += 6,
                't' => score += 5,
                'T' => score += 5,
                'a' => score += 4,
                'A' => score += 4,
                'o' => score += 3,
                'O' => score += 3,
                'i' => score += 2,
                'I' => score += 2,
                'n' => score += 1,
                'N' => score += 1,
                _ => score += 0,
            }
        }
    }

    score
}

pub fn hamming_distance(string1: &[u8], string2: &[u8]) -> usize {
    string1
        .iter()
        .zip(string2.iter())
        .fold(0, |mut acc, (a, b)| {
            acc += (a ^ b).count_ones() as usize;
            acc
        })
}

// Check if the string is padded, if so, return it
// Otherwise, pad it and return it
pub fn pkcs7_pad(string: &[u8], blocksize: usize) -> Vec<u8> {
    let mut ret = string.to_vec();
    match validate_pkcs7_padding(string) {
        Err(_) => {
            let padding_size = blocksize - (string.len() % blocksize);
            ret.extend(iter::repeat(padding_size as u8).take(padding_size));
            ret
        }
        Ok(_) => ret,
    }
}

pub fn remove_padding(string: &[u8], blocksize: usize) -> Vec<u8> {
    let maybe_pad: usize = string[string.len() - 1] as usize;
    if maybe_pad <= blocksize {
        if !string[(string.len() - maybe_pad)..string.len()]
            .to_vec()
            .iter()
            .all(|&c| c == maybe_pad as u8)
        {
            return string.to_vec();
        }

        return string[..(string.len() - maybe_pad)].to_vec();
    }

    string.to_vec()
}

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    iter::repeat_with(rand::random::<u8>)
        .take(size)
        .collect::<Vec<u8>>()
}

#[cfg(test)]
pub fn parse_key_value(string: &str) -> HashMap<String, String> {
    let mut ret = HashMap::<String, String>::new();
    for kv in string.split('&').collect::<Vec<&str>>() {
        let key_value = kv.split('=').collect::<Vec<&str>>();
        ret.insert(key_value[0].to_string(), key_value[1].to_string());
    }

    ret
}

pub fn validate_pkcs7_padding(string: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut result = string.to_vec();
    let maybe_pad_byte: Option<u8> = result.pop();
    if maybe_pad_byte.is_some() {
        let pad_byte = maybe_pad_byte.unwrap();
        if pad_byte == 0 {
            return Err(CryptoError::BadPadding);
        };
        for _ in 0..pad_byte - 1 {
            match result.pop() {
                None => return Err(CryptoError::BadPadding),
                Some(byte) => {
                    if byte != pad_byte {
                        return Err(CryptoError::BadPadding);
                    }
                }
            }
        }
    }

    Ok(result)
}

pub fn map_blocks(ciphertext: &[u8], blocksize: usize) -> Vec<Vec<u8>> {
    ciphertext
        .iter()
        .chunks(blocksize)
        .into_iter()
        .map(|c| c.cloned().collect::<Vec<u8>>())
        .collect::<Vec<Vec<u8>>>()
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
    use crate::util::encrypt_with_prefix_and_suffix;
    use crate::util::find_prefix_length;
    use crate::util::find_prefix_suffix_lengths;
    use crate::util::generate_random_bytes;
    use crate::util::profile_for;
    use crate::util::EncryptionType;

    use crate::util::hamming_distance;
    use crate::util::parse_key_value;
    use crate::util::pkcs7_pad;
    use crate::util::remove_padding;

    #[test]
    fn test_pkcs7_padding() {
        let blocksize = 16;

        let mut string = Vec::<u8>::new();
        for size in 0..blocksize - 1 {
            string.push(b'A');
            let output = pkcs7_pad(&string, blocksize);
            for index in size + 1..blocksize {
                assert_eq!((blocksize - size - 1) as u8, output[index]);
            }
        }

        string.push(b'A');
        let output = pkcs7_pad(&string, blocksize);
        assert_eq!(blocksize * 2, output.len());
        for index in 0..blocksize {
            assert_eq!(blocksize as u8, output[index + blocksize]);
        }
    }

    #[test]
    fn test_remove_padding() {
        let padded = pkcs7_pad(&"foobar".as_bytes(), 16);
        assert_eq!("foobar".as_bytes().to_vec(), remove_padding(&padded, 16));
    }

    #[test]
    fn test_hamming() {
        let string1 = "this is a test";
        let string2 = "wokka wokka!!!";
        assert_eq!(
            37,
            hamming_distance(
                &string1.bytes().collect::<Vec<u8>>(),
                &string2.bytes().collect::<Vec<u8>>()
            )
        );
    }

    #[test]
    fn test_parse_key_value() {
        let test_string = "foo=bar&baz=qux&zap=zazzle";
        let map = parse_key_value(test_string);
        assert_eq!("bar", map.get("foo").unwrap());
        assert_eq!("qux", map.get("baz").unwrap());
        assert_eq!("zazzle", map.get("zap").unwrap());
    }

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
