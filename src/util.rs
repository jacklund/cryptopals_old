use crate::exception::CryptoError;
use itertools::Itertools;
use std::collections::HashMap;
use std::error::Error;
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::{BufRead, BufReader};
use std::iter;
use std::str;

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
    let histogram = string
        .iter()
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
        if ! string[(string.len() - maybe_pad)..string.len()].to_vec().iter().all(|&c| c == maybe_pad as u8) {
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

#[cfg(test)]
mod tests {
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
}
