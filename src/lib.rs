extern crate base64;
extern crate byteorder;
extern crate crypto;
extern crate hex;
extern crate is_sorted;
extern crate itertools;
#[macro_use]
extern crate percent_encoding;
extern crate rand;

mod challenges;
mod exception;
mod util;

use crate::util::generate_random_bytes;
use crate::util::get_character_histogram;
use crate::util::hamming_distance;
use crate::util::map_blocks;
use crate::util::pkcs7_pad;
use crate::util::score_text;
use crate::util::validate_pkcs7_padding;
use crate::util::xor;

use byteorder::{LittleEndian, WriteBytesExt};
use crypto::buffer::ReadBuffer;
use crypto::buffer::WriteBuffer;
use crypto::symmetriccipher::SymmetricCipherError;
use itertools::Itertools;
use rand::RngCore;
use std::iter;
use std::str;

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

pub fn aes_128_ecb_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    padding: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = if padding {
        crypto::aes::ecb_decryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::PkcsPadding,
        )
    } else {
        crypto::aes::ecb_decryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::NoPadding,
        )
    };
    let mut output = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);
    decryptor.decrypt(
        &mut crypto::buffer::RefReadBuffer::new(&ciphertext),
        &mut write_buffer,
        true,
    )?;
    output.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .cloned(),
    );

    Ok(output)
}

pub fn aes_128_ecb_encrypt(
    key: &[u8],
    plaintext: &[u8],
    padding: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = if padding {
        crypto::aes::ecb_encryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::PkcsPadding,
        )
    } else {
        crypto::aes::ecb_encryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::NoPadding,
        )
    };
    let mut output = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);
    encryptor.encrypt(
        &mut crypto::buffer::RefReadBuffer::new(&plaintext),
        &mut write_buffer,
        true,
    )?;
    output.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .cloned(),
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
    false
}

pub fn aes_128_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    remove_padding: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let chunks = ciphertext
        .chunks(16)
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut plaintext = Vec::<u8>::new();
    let mut vector = iv.to_vec();
    for chunk in chunks {
        plaintext.extend(xor(&aes_128_ecb_decrypt(&key, &chunk, false)?, &vector).unwrap());
        vector = chunk;
    }

    if remove_padding {
        Ok(validate_pkcs7_padding(&plaintext).unwrap())
    } else {
        Ok(plaintext)
    }
}

pub fn aes_128_cbc_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let chunks = pkcs7_pad(&plaintext, iv.len())
        .chunks(iv.len())
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut ciphertext = Vec::<u8>::new();
    let mut vector = iv.to_vec();
    for chunk in chunks {
        let cipher_chunk = aes_128_ecb_encrypt(&key, &xor(&chunk, &vector).unwrap(), false)?;
        ciphertext.extend(cipher_chunk.clone());
        vector = cipher_chunk;
    }

    Ok(ciphertext)
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

// Decrypt an AES ECB ciphertext one byte at a time
pub fn decrypt_ecb_byte_at_a_time<F: Fn(&[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    encrypt_fn: F,
) -> Vec<u8> {
    let blocksize = find_blocksize(&encrypt_fn).unwrap();
    let (prefix_size, target_size) = find_prefix_suffix_lengths(&encrypt_fn);

    // Number of bytes to add so that our target starts on a block boundary
    let padding_size = (blocksize - (prefix_size + target_size) % blocksize) % blocksize;

    // Our test string will be big enough to contain the target, plus whatever padding to
    // ensure the target starts on the block boundary
    let test_string_size = target_size + padding_size;

    // Start with an empty solution string and our test string
    let mut solution = Vec::<u8>::new();

    for pos in 1usize..test_string_size {
        // We start with our test string such that one character of the target is just this side
        // of the block boundary
        let mut test_string = iter::repeat(b'A')
            .take(test_string_size - pos)
            .collect::<Vec<u8>>();

        // Get our base ciphertext to compare to
        let ciphertext = encrypt_fn(&test_string).unwrap();

        // Add our solution so far
        test_string.extend(solution.clone());

        // We start with a zero byte, and increment it until our
        // ciphertexts match in that block
        test_string.push(0u8);

        // Loop through and add 1 to the last byte until the ciphertext matches our base
        // ciphertext (or we hit the end of our char set)
        loop {
            let test_ciphertext = encrypt_fn(&test_string).unwrap();

            // They match, we found another char
            if test_ciphertext[..prefix_size + test_string_size]
                == ciphertext[..prefix_size + test_string_size]
            {
                // We've hit padding, end early
                // Padding will always be 0x01 because we'll be
                // one byte away from the block boundary
                if test_string[test_string_size - 1] == 1u8 {
                    return solution; // We've hit the padding
                }
                // Add it to our solution string
                solution.push(test_string[test_string_size - 1]);
                break;
            }

            // Abort if we ran out of characters
            if test_string[test_string_size - 1] as char == '~' {
                assert!(false);
            }

            // Increment the char and try again
            test_string[test_string_size - 1] += 1;
        }
    }

    solution
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

pub struct CTRKeystreamIterator {
    key: Vec<u8>,
    counter: usize,
    nonce_counter: Vec<u8>,
    buffer: Vec<u8>,
    index: usize,
}

impl CTRKeystreamIterator {
    fn new(key: &[u8], nonce: &[u8]) -> Self {
        CTRKeystreamIterator {
            key: key.to_vec(),
            counter: 0,
            nonce_counter: nonce.to_vec(),
            buffer: vec![],
            index: 0,
        }
    }

    fn next_block(&mut self) -> Result<Vec<u8>, SymmetricCipherError> {
        self.nonce_counter.write_u64::<LittleEndian>(self.counter as u64).unwrap();
        self.counter += 1;
        let result = aes_128_ecb_encrypt(&self.key, &self.nonce_counter, false);
        self.nonce_counter.truncate(8);
        result
    }
}

impl iter::Iterator for CTRKeystreamIterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.buffer.len() {
            self.buffer = self.next_block().unwrap();
            self.index = 0;
        }

        let ret = self.buffer[self.index];
        self.index += 1;
        Some(ret)
    }
}

pub fn ctr(key: &[u8], nonce: &[u8], input: &[u8]) -> Vec<u8> {
    let iter = CTRKeystreamIterator::new(key, nonce);

    input.iter().zip(iter).map(|(t, k)| t ^ k).collect()
}

pub fn break_ctr(ciphertexts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    // Get max size of our keystream
    let keystream_size = ciphertexts.iter().fold(0usize, |mut size, c| {
        if c.len() > size {
            size = c.len();
        }
        size
    });

    // Make a list of the nth letter of each ciphertext
    let mut letters: Vec<Vec<u8>> = iter::repeat(Vec::<u8>::new())
        .take(keystream_size)
        .collect();
    ciphertexts.iter().for_each(|c| {
        c.iter().enumerate().for_each(|(index, value)| {
            letters[index].push(*value);
        });
    });

    // Find the key letter by letter
    let mut key: Vec<u8> = vec![];
    letters.iter().for_each(|string| {
        let (_, k, _) = find_xor_key(&string).unwrap();
        key.push(k);
    });

    ciphertexts
        .iter()
        .map(|ciphertext| xor(&key[..ciphertext.len()], ciphertext).unwrap())
        .collect()
}

pub struct MarsenneTwister {
    mt: Vec<u64>,
    index: usize,
    w: u64,
    n: usize,
    m: usize,
    r: usize,
    a: u64,
    f: u64,
}

impl MarsenneTwister {
    pub fn new(w: u64, n: usize, m: usize, r: usize, a: u64, f: u64) -> MarsenneTwister {
        MarsenneTwister {
            mt: iter::repeat(0u64).take(n).collect(),
            index: n,
            w,
            n,
            m,
            r,
            a,
            f,
        }
    }

    fn twist(&mut self) {
        let lower_mask: u64 = (1 << self.r) - 1;
        let upper_mask: u64 = !lower_mask;
        for i in 0..self.n {
            let x = (upper_mask & self.mt[i]) + (self.mt[(i + 1) % self.n] & lower_mask);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa |= self.a;
            }
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xa;
        }
    }
}

pub fn mt19937() -> MarsenneTwister {
    MarsenneTwister::new(32, 624, 397, 31, 0x9908B0DF, 1812433253)
}

impl MarsenneTwister {
    pub fn from_seed(seed: u32) -> Self {
        let mut mt = mt19937();
        mt.index = mt.n;
        mt.mt[0] = u64::from(seed);
        for i in 1..mt.n {
            mt.mt[i] =
                0xFFFFFFFF & (mt.f * (mt.mt[i - 1] ^ (mt.mt[i - 1] >> (mt.w - 2))) + (i as u64));
        }

        mt
    }

    pub fn from_splice(generator: &[u64]) -> Self {
        let mut mt = mt19937();
        mt.index = 0;
        mt.mt = generator.to_vec();

        mt
    }
}

const U: usize = 11;
const D: u64 = 0xFFFFFFFF;
const S: usize = 7;
const B: u64 = 0x9D2C5680;
const T: usize = 15;
const C: u64 = 0xEFC60000;
const L: usize = 18;

pub fn temper(value: u64) -> u32 {
    let mut y: u64 = value as u64;
    y ^= (y >> U) & D;
    y ^= (y << S) & B;
    y ^= (y << T) & C;
    y ^= y >> L;

    (y & 0xFFFFFFFF) as u32
}

impl rand::RngCore for MarsenneTwister {
    fn next_u32(&mut self) -> u32 {
        if self.index >= self.n {
            self.twist();
            self.index = 0;
        };

        let result = temper(self.mt[self.index]);

        self.index += 1;
        result
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u32().into()
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
        unimplemented!()
    }
}

pub struct MTIterator {
    mt: MarsenneTwister,
    buffer: Vec<u8>,
    index: usize,
}

impl MTIterator {
    fn new(seed: u32) -> Self {
        MTIterator {
            mt: MarsenneTwister::from_seed(seed),
            buffer: vec![],
            index: 0,
        }
    }
}

// Byte-wise iterator of the Marsenne Twister
impl iter::Iterator for MTIterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.buffer.len() {
            self.buffer.clear();
            self.buffer
                .write_u32::<LittleEndian>(self.mt.next_u32())
                .unwrap();
            self.index = 0;
        }

        let ret = self.buffer[self.index];
        self.index += 1;
        Some(ret)
    }
}

impl iter::IntoIterator for MarsenneTwister {
    type Item = u8;
    type IntoIter = MTIterator;

    fn into_iter(self) -> Self::IntoIter {
        MTIterator {
            mt: self,
            buffer: vec![],
            index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aes_128_cbc_decrypt;
    use crate::aes_128_cbc_encrypt;
    use crate::aes_128_ecb_decrypt;
    use crate::aes_128_ecb_encrypt;
    use base64;
    //use brute_force_xor_key;
    use crate::encrypt_with_prefix_and_suffix;
    use crate::find_prefix_length;
    use crate::find_prefix_suffix_lengths;
    use crate::generate_random_bytes;
    use crate::profile_for;
    use crate::EncryptionType;
    use crate::MarsenneTwister;
    use byteorder::{LittleEndian, ReadBytesExt};
    use hex;
    use rand::RngCore;
    use std;
    use std::io::Cursor;
    use std::iter;
    use std::str;

    #[test]
    fn test_ecb_encrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "Hello World Jack";
        let ciphertext = aes_128_ecb_encrypt(&key, &plaintext.as_bytes(), true).unwrap();
        let decrypted = aes_128_ecb_decrypt(&key, &ciphertext, true).unwrap();
        assert_eq!(plaintext, str::from_utf8(&decrypted).unwrap());
    }

    #[test]
    fn test_encrypt_cbc_mode() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "Hello World Jack";
        let iv = std::iter::repeat(0u8).take(16).collect::<Vec<u8>>();
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, &plaintext.as_bytes()).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext, true).unwrap();
        assert_eq!(plaintext, str::from_utf8(&decrypted).unwrap());
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

    #[test]
    fn test_mt19937() {
        let seed = rand::random::<u32>();
        let mut mt1 = MarsenneTwister::from_seed(seed);
        let values: Vec<u32> = iter::repeat_with(|| mt1.next_u32())
            .take(100)
            .collect::<Vec<u32>>();
        let mut mt2 = MarsenneTwister::from_seed(seed);
        let values2: Vec<u32> = iter::repeat_with(|| mt2.next_u32())
            .take(100)
            .collect::<Vec<u32>>();
        assert_eq!(None, values.iter().zip(values2).find(|(v1, v2)| *v1 != v2));
    }

    #[test]
    fn test_mt_iterator() {
        let seed = rand::random::<u32>();
        let mut mt = MarsenneTwister::from_seed(seed);
        let ref mut mt_iterator = MarsenneTwister::from_seed(seed).into_iter();
        for _count in 0..100 {
            let buffer = mt_iterator.take(4).collect::<Vec<u8>>();
            let mut rdr = Cursor::new(buffer);
            let value = rdr.read_u32::<LittleEndian>().unwrap();
            assert_eq!(mt.next_u32(), value);
        }
    }
}
