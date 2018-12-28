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
        .into_iter()
        .zip(second.into_iter())
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

pub fn hamming_distance(string1: &[u8], string2: &[u8]) -> usize {
    string1
        .iter()
        .zip(string2.iter())
        .fold(0, |mut acc, (a, b)| {
            acc += (a ^ b).count_ones() as usize;
            acc
        })
}

pub fn pkcs7_pad(string: &[u8], blocksize: usize) -> Vec<u8> {
    let mut ret = string.to_vec();
    ret.extend(iter::repeat(4u8).take((blocksize - (string.len() % blocksize)) % blocksize));
    ret
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

#[cfg(test)]
mod tests {
    use crate::util::hamming_distance;
    use crate::util::parse_key_value;

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
