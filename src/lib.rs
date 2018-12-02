extern crate base64;
extern crate hex;
extern crate is_sorted;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
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

pub fn xor(first_hex: &str, second_hex: &str) -> Result<String, Box<Error>> {
    if first_hex.len() != second_hex.len() {
        return Err(
            CryptoError::XorError("Strings being xor-ed must be same size".to_string()).into(),
        );
    }
    let first: Vec<u8> = hex::decode(first_hex)?;
    let second: Vec<u8> = hex::decode(second_hex)?;

    Ok(hex::encode(
        first
            .into_iter()
            .zip(second.into_iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<u8>>(),
    ))
}

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
pub fn score_text(string: &str) -> usize {
    let mut score: usize = 0;
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

    score
}

// Decrypt ciphertext using xor
pub fn decrypt_xor(key: &u8, ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.iter().map(|c| c ^ *key).collect::<Vec<u8>>()
}

// Decrypt using the key and return the score and decrypted value, or None if the decryption failed
fn get_score(key: &u8, ciphertext: &[u8]) -> Option<(usize, String)> {
    if let Ok(string) = str::from_utf8(&decrypt_xor(&key, &ciphertext)) {
        Some((score_text(string), string.to_string()))
    } else {
        None
    }
}

// Iterate through a list of keys, and try each key in turn, returning the highest-scoring
// plaintext, along with the key and score
fn try_decrypt_against_key_list<F>(
    ciphertext: &[u8],
    key_list: &[u8],
    key_generator: F,
    current_score: usize,
    current_key: u8,
    current_decrypted: String,
) -> (usize, u8, String)
where
    F: Fn(&u8) -> u8,
{
    let (score, key, decrypted) = key_list.iter().fold(
        (current_score, current_key, current_decrypted),
        |(mut score, mut key, mut decrypted), byte| {
            let test_key = key_generator(byte);
            if let Some((test_score, test_decrypted)) = get_score(&test_key, ciphertext) {
                if test_score > score {
                    score = test_score;
                    key = test_key;
                    decrypted = test_decrypted;
                }
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
) -> Option<(usize, u8, String)> {
    // Try each key in the key list against each
    let (score, key, decrypted) = test_string.into_iter().fold(
        (0, 0u8, String::new()),
        |(score, key, decrypted), value| {
            // Iterate over the key list,
            let (local_score, local_key, local_decrypted) = try_decrypt_against_key_list(
                ciphertext,
                key_list,
                |b| b ^ value,
                score,
                key,
                decrypted.clone(),
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
pub fn brute_force_xor_key(ciphertext: &[u8]) -> Option<(usize, u8, String)> {
    Some(try_decrypt_against_key_list(
        ciphertext,
        &(0u8..255u8).collect::<Vec<u8>>(),
        |b| *b,
        0,
        0,
        String::new(),
    ))
}

// Find the key by finding the most frequent chars in the ciphertext
// and then test them against a list of the most frequent characters in English
pub fn find_xor_key(ciphertext: &[u8]) -> Option<(usize, u8, String)> {
    let histogram = get_character_histogram(&ciphertext);
    let etaoin = " eEtTaAoOiInN".as_bytes();

    try_decrypt_with_test_string(ciphertext, &histogram, etaoin)
}

pub fn encrypt_repeating_key_xor(key: &str, plaintext: &str) -> String {
    let repeat = (plaintext.len() as f32 / key.len() as f32).ceil() as usize;
    let mut repeated_key = std::iter::repeat(key).take(repeat).collect::<String>();
    repeated_key.truncate(plaintext.len());
    hex::encode(&plaintext
        .bytes()
        .zip(repeated_key.bytes())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>())
}

#[cfg(test)]
mod tests {
    //use brute_force_xor_key;
    use encrypt_repeating_key_xor;
    use find_xor_key;
    use hex;
    use hex_to_base64;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
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
            xor(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ).unwrap(),
            "746865206b696420646f6e277420706c6179"
        );
    }

    // Third cryptopals challenge - https://cryptopals.com/sets/1/challenges/3
    #[test]
    fn test_decrypt_xor() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let ciphertext_bin = hex::decode(ciphertext).unwrap();
        let (_, _, decrypted) = find_xor_key(&ciphertext_bin).unwrap();
        assert_eq!("Cooking MC's like a pound of bacon", decrypted);
    }

    // Fourth cryptopals challenge - https://cryptopals.com/sets/1/challenges/4
    #[test]
    fn test_detect_single_char_xor() {
        let mut score = 0;
        let mut string = "".to_string();
        for line in BufReader::new(File::open("data/4.txt").unwrap()).lines() {
            if let Some((s, _, decrypted)) = find_xor_key(&hex::decode(line.unwrap()).unwrap()) {
                if s > score {
                    score = s;
                    string = decrypted;
                }
            }
        }
        assert_eq!("Now that the party is jumping\n", string);
    }

    // Fifth cryptopals challenge - https://cryptopals.com/sets/1/challenges/5
    #[test]
    fn test_repeating_key_xor() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let ciphertext =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
             a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let key = "ICE";
        let encrypted = encrypt_repeating_key_xor(key, plaintext);
        assert_eq!(ciphertext, encrypted);
    }
}
