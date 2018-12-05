#![feature(iterator_repeat_with)]

extern crate base64;
extern crate crypto;
extern crate hex;
extern crate is_sorted;
extern crate rand;

use crypto::buffer::ReadBuffer;
use crypto::buffer::WriteBuffer;
use crypto::symmetriccipher::SymmetricCipherError;
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

pub fn encryption_oracle(plaintext: &[u8]) -> Result<(Vec<u8>, bool), SymmetricCipherError> {
    let mut new_plaintext = generate_random_bytes((rand::random::<f32>() * 5.0) as usize + 5);
    new_plaintext.extend(plaintext);
    new_plaintext.extend(generate_random_bytes(
        (rand::random::<f32>() * 5.0) as usize + 5,
    ));
    if rand::random() {
        Ok((
            aes_128_ecb_encrypt(&generate_random_bytes(16), &new_plaintext)?,
            true,
        ))
    } else {
        let iv = generate_random_bytes(16);
        Ok((
            aes_128_cbc_encrypt(&generate_random_bytes(16), &iv, &new_plaintext)?,
            false,
        ))
    }
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
    use detect_aes_ecb;
    use encrypt_decrypt_repeating_key_xor;
    use encryption_oracle;
    use find_repeating_xor_keysize;
    use find_xor_key;
    use hamming_distance;
    use hex;
    use hex_to_base64;
    use pkcs7_pad;
    use read_base64_file;
    use std;
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
}
