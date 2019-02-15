use crate::util::get_character_histogram;
use crate::util::hamming_distance;
use crate::util::score_text;

// Decrypt ciphertext using xor
pub fn decrypt_xor(key: u8, ciphertext: &[u8]) -> Vec<u8> {
    ciphertext.iter().map(|c| c ^ key).collect::<Vec<u8>>()
}

// Decrypt using the key and return the score and decrypted value, or None if the decryption failed
fn get_score(key: u8, ciphertext: &[u8]) -> (usize, Vec<u8>) {
    let string = decrypt_xor(key, &ciphertext);
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
            let (test_score, test_decrypted) = get_score(test_key, ciphertext);
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
    let (score, key, decrypted) = test_string.iter().fold(
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
    let etaoin = b" eEtTaAoOiInN";

    try_decrypt_with_test_string(ciphertext, &histogram, etaoin)
}

// Encrypt/decrypt using a repeating key and xor
pub fn encrypt_decrypt_repeating_key_xor(key: &[u8], plain_or_ciphertext: &[u8]) -> Vec<u8> {
    // How many times to repeat the key
    let repeat = (plain_or_ciphertext.len() as f32 / key.len() as f32).ceil() as usize;

    // Generate the repeated key which has the same length as the text
    let mut repeated_key =
        std::iter::repeat(key)
            .take(repeat)
            .fold(Vec::<u8>::new(), |mut v, b| {
                v.append(&mut b.to_vec());
                v
            });
    repeated_key.truncate(plain_or_ciphertext.len());

    // Xor the key with the text and return the result
    plain_or_ciphertext
        .iter()
        .zip(repeated_key.iter())
        .map(|(a, b)| a ^ b)
        .collect::<Vec<u8>>()
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
    vector_of_vectors
        .iter()
        .fold(vec![] as Vec<u8>, |mut key, string| {
            let (_, k, _) = find_xor_key(&string).unwrap();
            key.push(k);
            key
        })
}
