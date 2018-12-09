#![feature(iterator_repeat_with)]

extern crate base64;
extern crate crypto;
extern crate hex;
extern crate is_sorted;
extern crate itertools;
extern crate rand;

use crypto::buffer::ReadBuffer;
use crypto::buffer::WriteBuffer;
use crypto::symmetriccipher::SymmetricCipherError;
use itertools::Itertools;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter;
use std::str;

#[derive(Debug)]
enum CryptoError {
    XorError(String),
}

impl Error for CryptoError {}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::XorError(message) => write!(f, "Xor error: {}", message),
        }
    }
}

pub fn hex_to_base64(hex_string: &str) -> Result<String, Box<Error>> {
    let binary = hex::decode(hex_string)?;
    Ok(base64::encode(&binary))
}

pub fn xor(first: &[u8], second: &[u8]) -> Result<Vec<u8>, Box<Error>> {
    if first.len() != second.len() {
        println!("first: {}, second: {}", first.len(), second.len());
        return Err(
            CryptoError::XorError("Strings being xor-ed must be same size".to_string()).into(),
        );
    }

    Ok(first
        .into_iter()
        .zip(second.into_iter())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>())
}

pub fn read_base64_file(filename: &str) -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    for line in BufReader::new(File::open(filename).unwrap()).lines() {
        data.append(&mut base64::decode(&line.unwrap()).unwrap());
    }

    data
}

// Get a list of the characters in the string, ordered by frequency
pub fn get_character_histogram(string: &[u8]) -> Vec<u8> {
    let histogram = string
        .into_iter()
        .fold(HashMap::<u8, usize>::new(), |mut h, c| {
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

// Decrypt ciphertext using xor
pub fn decrypt_xor(key: &u8, ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.iter().map(|c| c ^ *key).collect::<Vec<u8>>()
}

// Decrypt using the key and return the score and decrypted value, or None if the decryption failed
fn get_score(key: &u8, ciphertext: &[u8]) -> (usize, Vec<u8>) {
    let string = decrypt_xor(&key, &ciphertext);
    (score_text(&string), string)
}

// Iterate through a list of keys, and try each key in turn, returning the highest-scoring
// plaintext, along with the key and score
fn try_decrypt_against_key_list<F>(
    ciphertext: &[u8],
    key_list: &[u8],
    key_generator: F,
    current_score: usize,
    current_key: u8,
    current_decrypted: &[u8],
) -> (usize, u8, Vec<u8>)
where
    F: Fn(&u8) -> u8,
{
    let (score, key, decrypted) = key_list.iter().fold(
        (current_score, current_key, current_decrypted.to_vec()),
        |(mut score, mut key, mut decrypted), byte| {
            let test_key = key_generator(byte);
            let (test_score, test_decrypted) = get_score(&test_key, ciphertext);
            if test_score > score {
                score = test_score;
                key = test_key;
                decrypted = test_decrypted;
            }

            (score, key, decrypted)
        },
    );
    (score, key, decrypted)
}

// Use a test string to guess the key
fn try_decrypt_with_test_string(
    ciphertext: &[u8],
    test_string: &[u8],
    key_list: &[u8],
) -> Option<(usize, u8, Vec<u8>)> {
    // Try each key in the key list against each
    let (score, key, decrypted) = test_string.into_iter().fold(
        (0, 0u8, Vec::<u8>::new()),
        |(score, key, decrypted), value| {
            // Iterate over the key list,
            let (local_score, local_key, local_decrypted) = try_decrypt_against_key_list(
                ciphertext,
                key_list,
                |b| b ^ value,
                score,
                key,
                &decrypted.clone(),
            );
            if local_score > score {
                (local_score, local_key, local_decrypted)
            } else {
                (score, key, decrypted)
            }
        },
    );

    if score > 0 {
        return Some((score, key, decrypted));
    }

    None
}

// Try to brute force the decryption by iterating through all 255 keys
pub fn brute_force_xor_key(ciphertext: &[u8]) -> Option<(usize, u8, Vec<u8>)> {
    Some(try_decrypt_against_key_list(
        ciphertext,
        &(0u8..255u8).collect::<Vec<u8>>(),
        |b| *b,
        0,
        0,
        &Vec::<u8>::new(),
    ))
}

// Find the key by finding the most frequent chars in the ciphertext
// and then test them against a list of the most frequent characters in English
pub fn find_xor_key(ciphertext: &[u8]) -> Option<(usize, u8, Vec<u8>)> {
    let histogram = get_character_histogram(&ciphertext);
    let etaoin = " eEtTaAoOiInN".as_bytes();

    try_decrypt_with_test_string(ciphertext, &histogram, etaoin)
}

// Encrypt/decrypt using a repeating key and xor
pub fn encrypt_decrypt_repeating_key_xor(key: &[u8], plain_or_ciphertext: &[u8]) -> Vec<u8> {
    // How many times to repeat the key
    let repeat = (plain_or_ciphertext.len() as f32 / key.len() as f32).ceil() as usize;

    // Generate the repeated key which has the same length as the text
    let mut repeated_key = std::iter::repeat(key).take(repeat).fold(
        Vec::<u8>::new(),
        |mut v, b| {
            v.append(&mut b.to_vec());
            v
        },
    );
    repeated_key.truncate(plain_or_ciphertext.len());

    // Xor the key with the text and return the result
    plain_or_ciphertext
        .iter()
        .zip(repeated_key.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>()
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

// Returns a list of the keysizes, ordered by distance
pub fn find_repeating_xor_keysize(string: &[u8]) -> Vec<usize> {
    let keysizes = 2..40;
    // For each key size...
    let mut keysize_distance_list = keysizes
        .map(|keysize| {
            // split string into keysize chunks and partition into groups of even and odd chunks...
            let (even, odd): (Vec<(usize, &[u8])>, Vec<(usize, &[u8])>) = string
                .chunks(keysize)
                .enumerate()
                .partition(|(i, _)| i % 2 == 0);
            // Zip the groups together and add up the hamming distances between each pair
            let distance = even.into_iter().zip(odd.into_iter()).fold(
                0usize,
                |mut acc, ((_, first), (_, second))| {
                    acc += hamming_distance(&first, &second);
                    acc
                },
            );
            // average distance normalized by dividing by key length
            // avg = total distance / num samples / key length
            // num samples = string length / key length
            // therefore avg distance = total distance over string length
            let normalized = distance as f32 / string.len() as f32;
            (keysize, normalized)
        })
        .collect::<Vec<(usize, f32)>>();
    keysize_distance_list.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    keysize_distance_list
        .iter()
        .map(|(keysize, _)| *keysize)
        .collect::<Vec<usize>>()
}

pub fn break_repeating_key_xor(ciphertext: &[u8], keysize: usize) -> Vec<u8> {
    let mut vector_of_vectors: Vec<Vec<u8>> = Vec::new();
    for _ in 0..keysize {
        vector_of_vectors.push(Vec::new());
    }
    ciphertext.iter().enumerate().for_each(|(index, value)| {
        let chunk_index = index % keysize;
        vector_of_vectors[chunk_index].push(*value);
    });
    let key = vector_of_vectors
        .iter()
        .fold(vec![] as Vec<u8>, |mut key, string| {
            let (_, k, _) = find_xor_key(&string).unwrap();
            key.push(k);
            key
        });
    key
}

pub fn aes_128_ecb_decrypt(
    key: &[u8],
    mut ciphertext: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = crypto::aes::ecb_decryptor(
        crypto::aes::KeySize::KeySize128,
        key,
        crypto::blockmodes::NoPadding,
    );
    let mut output = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);
    decryptor.decrypt(
        &mut crypto::buffer::RefReadBuffer::new(&mut ciphertext),
        &mut write_buffer,
        true,
    )?;
    output.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );

    Ok(output)
}

pub fn aes_128_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = crypto::aes::ecb_encryptor(
        crypto::aes::KeySize::KeySize128,
        key,
        crypto::blockmodes::NoPadding,
    );
    let mut output = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);
    let mut padded_plaintext = pkcs7_pad(&plaintext, 16);
    encryptor.encrypt(
        &mut crypto::buffer::RefReadBuffer::new(&mut padded_plaintext),
        &mut write_buffer,
        true,
    )?;
    output.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .map(|&i| i),
    );

    Ok(output)
}

pub fn detect_aes_ecb(ciphertext: &[u8]) -> bool {
    let chunks = ciphertext
        .chunks(16)
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    for (index, chunk1) in chunks.iter().enumerate() {
        for chunk2 in chunks[index + 1..].to_vec() {
            if *chunk1 == chunk2 {
                return true;
            }
        }
    }
    return false;
}

pub fn aes_128_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let chunks = ciphertext
        .chunks(16)
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut plaintext = Vec::<u8>::new();
    let mut vector = iv.to_vec();
    for chunk in chunks {
        plaintext.extend(xor(&aes_128_ecb_decrypt(&key, &chunk).unwrap(), &vector).unwrap());
        vector = chunk;
    }

    Ok(plaintext)
}

pub fn aes_128_cbc_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    println!("plaintext len = {}", plaintext.len());
    let chunks = pkcs7_pad(&plaintext, iv.len())
        .chunks(16)
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut ciphertext = Vec::<u8>::new();
    let mut vector = iv.to_vec();
    for chunk in chunks {
        let cipher_chunk = aes_128_ecb_encrypt(&key, &xor(&chunk, &vector).unwrap())?;
        ciphertext.extend(cipher_chunk.clone());
        vector = cipher_chunk;
    }

    Ok(ciphertext)
}

pub fn pkcs7_pad(string: &[u8], blocksize: usize) -> Vec<u8> {
    let mut ret = string.to_vec();
    ret.extend(
        iter::repeat('\x04' as u8).take((blocksize - (string.len() % blocksize)) % blocksize),
    );
    ret
}

pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    iter::repeat_with(|| rand::random::<u8>())
        .take(size)
        .collect::<Vec<u8>>()
}

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
        EncryptionType::ECB => aes_128_ecb_encrypt(key, &buffer),
    }
}

pub fn encryption_oracle(plaintext: &[u8]) -> Result<(Vec<u8>, bool), SymmetricCipherError> {
    let key = generate_random_bytes(16);
    let prefix = generate_random_bytes((rand::random::<f32>() * 5.0) as usize + 5);
    let suffix = generate_random_bytes(
        (rand::random::<f32>() * 5.0) as usize + 5,
    );
    if rand::random() {
        Ok((
            encrypt_with_prefix_and_suffix(&key, &prefix, plaintext, &suffix, EncryptionType::ECB)?,
            true,
        ))
    } else {
        let iv = generate_random_bytes(16);
        Ok((
            encrypt_with_prefix_and_suffix(&key, &prefix, plaintext, &suffix, EncryptionType::CBC(iv))?,
            false,
        ))
    }
}

const UNKNOWN_STRING_BASE64: &str =
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
     aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
     dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub fn encrypt_with_string(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let unknown_string = base64::decode(UNKNOWN_STRING_BASE64).unwrap();
    encrypt_with_prefix_and_suffix(key, &vec![], plaintext, &unknown_string, EncryptionType::ECB)
}

pub fn decrypt_ecb_byte_at_a_time<F: Fn(&[u8], &[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    blocksize: usize,
    encrypt_fn: F,
) -> Vec<u8> {
    let key = generate_random_bytes(blocksize);
    let total_size = encrypt_fn(&key, &vec![]).unwrap().len();
    let mut solution = Vec::<u8>::new();
    for pos in 1usize..total_size {
        let mut test_string = iter::repeat('A' as u8)
            .take(total_size - pos)
            .collect::<Vec<u8>>();
        let mut ciphertext = encrypt_fn(&key, &test_string).unwrap();
        test_string.extend(solution.clone());
        test_string.push(0u8);
        loop {
            let test_ciphertext = encrypt_fn(&key, &test_string).unwrap();
            if test_ciphertext[..total_size] == ciphertext[..total_size] {
                if test_string[total_size - 1] == 4u8 {
                    return solution; // We've hit the padding
                }
                solution.push(test_string[total_size - 1]);
                break;
            }
            if test_string[total_size - 1] as char == '~' {
                assert!(false);
            }
            test_string[total_size - 1] += 1;
        }
    }

    solution
}

pub fn find_blocksize<F: Fn(&[u8], &[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    encrypt_fn: F,
) -> Option<usize> {
    let key = generate_random_bytes(16);
    let mut plaintext = Vec::<u8>::new();
    let initial = encrypt_fn(&key, &plaintext).unwrap().len();
    let mut ciphertext;
    for _ in 0..2048 {
        plaintext.push(0u8);
        ciphertext = encrypt_fn(&key, &plaintext).unwrap();
        if ciphertext.len() != initial {
            return Some(ciphertext.len() - initial);
        }
    }

    None
}

pub fn parse_key_value(string: &str) -> HashMap<String, String> {
    let mut ret = HashMap::<String, String>::new();
    for kv in string.split('&').collect::<Vec<&str>>() {
        let key_value = kv.split('=').collect::<Vec<&str>>();
        ret.insert(key_value[0].to_string(), key_value[1].to_string());
    }

    ret
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

#[cfg(test)]
mod tests {
    use aes_128_cbc_decrypt;
    use aes_128_cbc_encrypt;
    use aes_128_ecb_decrypt;
    use aes_128_ecb_encrypt;
    use base64;
    use break_repeating_key_xor;
    //use brute_force_xor_key;
    use crypto::symmetriccipher::SymmetricCipherError;
    use decrypt_ecb_byte_at_a_time;
    use detect_aes_ecb;
    use encrypt_decrypt_repeating_key_xor;
    use encrypt_with_string;
    use encryption_oracle;
    use find_blocksize;
    use find_repeating_xor_keysize;
    use find_xor_key;
    use generate_random_bytes;
    use hamming_distance;
    use hex;
    use hex_to_base64;
    use iter;
    use parse_key_value;
    use pkcs7_pad;
    use profile_for;
    use read_base64_file;
    use std;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use str;
    use xor;

    // First cryptopals challenge - https://cryptopals.com/sets/1/challenges/1
    #[test]
    fn test_hex_to_base64() {
        assert_eq!(hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

    // Second cryptopals challenge - https://cryptopals.com/sets/1/challenges/2
    #[test]
    fn test_xor() {
        assert_eq!(
            hex::encode(
                xor(
                    &hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
                    &hex::decode("686974207468652062756c6c277320657965").unwrap()
                ).unwrap()
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }

    // Third cryptopals challenge - https://cryptopals.com/sets/1/challenges/3
    #[test]
    fn test_decrypt_xor() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let ciphertext_bin = hex::decode(ciphertext).unwrap();
        let (_, _, decrypted) = find_xor_key(&ciphertext_bin).unwrap();
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            str::from_utf8(&decrypted).unwrap()
        );
    }

    // Fourth cryptopals challenge - https://cryptopals.com/sets/1/challenges/4
    #[test]
    fn test_detect_single_char_xor() {
        let mut score = 0;
        let mut string = vec![];
        for line in BufReader::new(File::open("data/4.txt").unwrap()).lines() {
            if let Some((s, _, decrypted)) = find_xor_key(&hex::decode(line.unwrap()).unwrap()) {
                if s > score {
                    score = s;
                    string = decrypted;
                }
            }
        }
        assert_eq!(
            "Now that the party is jumping\n",
            str::from_utf8(&string).unwrap()
        );
    }

    // Fifth cryptopals challenge - https://cryptopals.com/sets/1/challenges/5
    #[test]
    fn test_repeating_key_xor() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let ciphertext =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
             a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let key: &str = "ICE";
        let encrypted = hex::encode(&encrypt_decrypt_repeating_key_xor(
            &key.bytes().collect::<Vec<u8>>(),
            &plaintext.bytes().collect::<Vec<u8>>(),
        ));
        assert_eq!(ciphertext, encrypted);
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

    // Sixth cryptopals challenge - https://cryptopals.com/sets/1/challenges/6
    #[test]
    fn test_break_repeating_key_xor() {
        let data = read_base64_file("data/6.txt");
        let keysize_list = find_repeating_xor_keysize(&data)
            .into_iter()
            .take(4)
            .collect::<Vec<usize>>();
        let key = break_repeating_key_xor(&data, keysize_list[0]);
        let plaintext = encrypt_decrypt_repeating_key_xor(&key, &data);
        assert!(
            str::from_utf8(&plaintext)
                .unwrap()
                .starts_with("I'm back and I'm ringin' the bell")
        );
    }

    // Seventh cryptopals challenge - https://cryptopals.com/sets/1/challenges/7
    #[test]
    fn test_decrypt_aes_128_ecb() {
        let mut data = read_base64_file("data/7.txt");
        let output = aes_128_ecb_decrypt("YELLOW SUBMARINE".as_bytes(), &mut data).unwrap();
        assert!(
            str::from_utf8(&output)
                .unwrap()
                .starts_with("I'm back and I'm ringin' the bell")
        );
    }

    // Eighth cryptopals challenge - https://cryptopals.com/sets/1/challenges/8
    #[test]
    fn test_detect_aes_in_ecb_mode() {
        let mut found: Option<String> = None;
        for line in BufReader::new(File::open("data/8.txt").unwrap()).lines() {
            let real_line = line.unwrap();
            let data = base64::decode(&real_line.clone()).unwrap();
            if detect_aes_ecb(&data) {
                found = Some(real_line.clone());
                break;
            }
        }
        assert!(
            found
                .unwrap()
                .starts_with("d880619740a8a19b7840a8a31c810a3d08649")
        );
    }

    // Ninth cryptopals challenge - https://cryptopals.com/sets/2/challenges/9
    #[test]
    fn test_pkcs7_padding() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04",
            str::from_utf8(&pkcs7_pad(&"YELLOW SUBMARINE".as_bytes(), 20)).unwrap()
        );
    }

    #[test]
    fn test_ecb_encrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "Hello World Jack";
        let ciphertext = aes_128_ecb_encrypt(&key, &plaintext.as_bytes()).unwrap();
        println!("{}, {:?}", ciphertext.len(), ciphertext);
        assert_eq!(
            plaintext,
            str::from_utf8(&aes_128_ecb_decrypt(&key, &ciphertext).unwrap()).unwrap()
        );
    }

    // Tenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/10
    #[test]
    fn test_decrypt_cbc_mode() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let ciphertext = read_base64_file("data/10.txt");
        let iv = std::iter::repeat(0u8).take(16).collect::<Vec<u8>>();
        let plaintext = aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert!(
            str::from_utf8(&plaintext)
                .unwrap()
                .starts_with("I'm back and I'm ringin' the bell")
        );
    }

    #[test]
    fn test_encrypt_cbc_mode() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "Hello World Jack";
        let iv = std::iter::repeat(0u8).take(16).collect::<Vec<u8>>();
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, &plaintext.as_bytes()).unwrap();
        assert_eq!(
            plaintext,
            str::from_utf8(&aes_128_cbc_decrypt(&key, &iv, &ciphertext).unwrap()).unwrap()
        );
    }

    // Eleventh cryptopals challenge - https://cryptopals.com/sets/2/challenges/11
    #[test]
    fn test_detect_ecb_cbc() {
        let mut plaintext = String::new();
        File::open("data/11.txt")
            .unwrap()
            .read_to_string(&mut plaintext)
            .unwrap();
        for _ in 0..100 {
            let (ciphertext, is_ecb) = encryption_oracle(&plaintext.as_bytes()).unwrap();
            assert_eq!(is_ecb, detect_aes_ecb(&ciphertext));
        }
    }

    // Twelfth cryptopals challenge - https://cryptopals.com/sets/2/challenges/12
    #[test]
    fn test_byte_at_a_time_ecb_decryption() {
        let solution_string = "Rollin' in my 5.0\n\
                               With my rag-top down so my hair can blow\n\
                               The girlies on standby waving just to say hi\n\
                               Did you stop? No, I just drove by\n";
        let blocksize = find_blocksize(encrypt_with_string).unwrap();
        assert_eq!(16, blocksize);
        let key = generate_random_bytes(16);
        let ciphertext = encrypt_with_string(
            &key,
            &iter::repeat(0u8).take(2 * blocksize).collect::<Vec<u8>>(),
        ).unwrap();
        assert!(detect_aes_ecb(&ciphertext));
        assert_eq!(
            solution_string,
            str::from_utf8(&decrypt_ecb_byte_at_a_time(blocksize, encrypt_with_string)).unwrap()
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

    // Thirteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/13
    #[test]
    fn test_ecb_cut_and_paste() {
        let key = generate_random_bytes(16);
        fn encrypt_user_profile(key: &[u8], email: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
            let profile = profile_for(str::from_utf8(email).unwrap(), 10, "user");
            aes_128_ecb_encrypt(key, profile.as_bytes())
        }
        fn decrypt_user_profile(
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<HashMap<String, String>, SymmetricCipherError> {
            let mut decrypted: Vec<u8> = aes_128_ecb_decrypt(key, ciphertext)?;
            let mut last = decrypted.pop().unwrap();
            while last == 4u8 {
                last = decrypted.pop().unwrap();
            }
            decrypted.push(last);
            Ok(parse_key_value(str::from_utf8(&decrypted).unwrap()))
        }
        let blocksize = find_blocksize(encrypt_user_profile).unwrap();
        assert_eq!(16, blocksize);

        // Want an email address that runs through the first block, with only 'admin', followed
        // by padding, in the second
        let mut test_email = iter::repeat('A' as u8)
            .take(blocksize - 6)
            .collect::<Vec<u8>>();
        assert_eq!(10, test_email.len()); // + "email=" makes 16 bytes
        test_email.extend("admin".as_bytes());
        test_email.extend(iter::repeat(4u8).take(11).collect::<Vec<u8>>()); // Pad rest of second block
        assert_eq!(26, test_email.len());
        let encrypted = encrypt_user_profile(&key, &test_email).unwrap();
        // Now take the second block
        let admin_block = &encrypted[16..32];

        // Next we want an email long enough to end the block with "role="
        // so that's 32 - 19, so 13 bytes
        test_email = iter::repeat('A' as u8).take(13).collect::<Vec<u8>>();
        let encrypted_again = encrypt_user_profile(&key, &test_email).unwrap();

        // We replace the third block with our admin block
        let mut new_encrypted = encrypted_again[..32].to_vec();
        new_encrypted.extend(admin_block);

        let profile = decrypt_user_profile(&key, &new_encrypted).unwrap();

        assert_eq!("admin", profile["role"]);
    }
}
