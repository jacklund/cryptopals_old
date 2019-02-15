use crate::aes_ecb::aes_128_ecb_encrypt;
use crate::util::xor;
use crate::xor::find_xor_key;

use byteorder::{LittleEndian, WriteBytesExt};
use crypto::symmetriccipher::SymmetricCipherError;
use std::iter;

#[derive(Clone)]
pub struct CTRKeystreamIterator {
    key: Vec<u8>,
    counter: usize,
    nonce_counter: Vec<u8>,
    buffer: Vec<u8>,
    index: usize,
}

impl CTRKeystreamIterator {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        CTRKeystreamIterator {
            key: key.to_vec(),
            counter: 0,
            nonce_counter: nonce.to_vec(),
            buffer: vec![],
            index: 0,
        }
    }

    fn next_block(&mut self) -> Result<Vec<u8>, SymmetricCipherError> {
        self.nonce_counter
            .write_u64::<LittleEndian>(self.counter as u64)
            .unwrap();
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
