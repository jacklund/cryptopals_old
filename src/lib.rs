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
mod exception;
mod util;
mod xor;

use crate::aes_cbc::aes_128_cbc_encrypt;
use crate::aes_ecb::aes_128_ecb_encrypt;
use crate::util::generate_random_bytes;
use crate::util::map_blocks;
use crate::util::xor;
use crate::xor::find_xor_key;

use byteorder::{LittleEndian, WriteBytesExt};
use crypto::symmetriccipher::SymmetricCipherError;
use itertools::Itertools;
use rand::RngCore;
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

#[derive(Clone)]
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
