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

pub fn decrypt_xor(key: &u8, ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.iter().map(|c| c ^ *key).collect::<Vec<u8>>()
}

fn get_score(key: &u8, ciphertext: &[u8]) -> Option<(usize, String)> {
    if let Ok(string) = str::from_utf8(&decrypt_xor(&key, &ciphertext)) {
        Some((score_text(string), string.to_string()))
    } else {
        None
    }
}

// TODO:
// 1) extract common functionality between this and find_xor_key()
// 2) cache the plaintext so I don't have to decrypt it twice
// 3) Put the tuple values in the same order as the return values
pub fn brute_force_xor_key(ciphertext: &[u8]) -> Option<(usize, u8, String)> {
    let (key, score) = ciphertext
        .into_iter()
        .fold((0u8, 0), |key_and_score, value| {
            let (local_key, local_score) =
                (0u8..255u8).fold(key_and_score, |(mut key, mut score), byte| {
                    let test_key = byte ^ value;
                    if let Some((test_score, decrypted)) = get_score(&test_key, ciphertext) {
                        if test_score > score {
                            score = test_score;
                            key = test_key;
                        }
                    }

                    (key, score)
                });
            if local_score > key_and_score.1 {
                (local_key, local_score)
            } else {
                key_and_score
            }
        });

    if score > 0 {
        return Some((
            score,
            key,
            str::from_utf8(&decrypt_xor(&key, &ciphertext))
                .unwrap()
                .to_string(),
        ));
    }

    None
}

// Find the key by finding the most frequent chars in the ciphertext
// and then test them against a list of the most frequent characters in English
pub fn find_xor_key(ciphertext: &[u8]) -> Option<(usize, u8, String)> {
    let histogram = get_character_histogram(&ciphertext);
    let etaoin = " eEtTaAoOiInN".as_bytes();

    let (key, score) = histogram.into_iter().fold((0u8, 0), |(k, s), value| {
        let (local_key, local_score) = etaoin.iter().fold((k, s), |(mut key, mut score), byte| {
            let test_key = byte ^ value;
            if let Some((test_score, decrypted)) = get_score(&test_key, ciphertext) {
                if test_score > score {
                    score = test_score;
                    key = test_key;
                }
            }

            (key, score)
        });

        if local_score > s {
            (local_key, local_score)
        } else {
            (k, s)
        }
    });

    if score > 0 {
        return Some((
            score,
            key,
            str::from_utf8(&decrypt_xor(&key, &ciphertext))
                .unwrap()
                .to_string(),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use brute_force_xor_key;
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
}
