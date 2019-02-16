use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::iter;

pub fn get_padding(length: usize) -> Vec<u8> {
    let bitlength: u64 = (length * 8) as u64;
    let mut padding_size_bytes: usize = 64 - (length % 64);
    if padding_size_bytes < 9 {
        padding_size_bytes += 64;
    }
    let mut ret = vec![];
    ret.push(0x80u8); // Append '1' bit
    let padding_prefix_size = padding_size_bytes - 8;
    ret.extend(
        iter::repeat(0u8)
            .take(padding_prefix_size - 1)
            .collect::<Vec<u8>>(),
    );
    ret.write_u64::<BigEndian>(bitlength).unwrap();

    ret
}

fn add32(a: u32, b: u32) -> u32 {
    ((a as u64 + b as u64) & 0xFFFFFFFF) as u32
}

pub fn sha1(message: &[u8]) -> Vec<u8> {
    // Initialize variables
    let h0: u32 = 0x67452301;
    let h1: u32 = 0xEFCDAB89;
    let h2: u32 = 0x98BADCFE;
    let h3: u32 = 0x10325476;
    let h4: u32 = 0xC3D2E1F0;

    sha1_with_init(message, h0, h1, h2, h3, h4, message.len())
}

pub fn sha1_with_init(
    message: &[u8],
    mut h0: u32,
    mut h1: u32,
    mut h2: u32,
    mut h3: u32,
    mut h4: u32,
    length: usize,
) -> Vec<u8> {
    // Break message into 512-bit chunks
    let mut buffer = message.to_vec();
    buffer.extend(get_padding(length));
    for chunk512 in buffer.chunks(64) {
        // Break each chunk into 32-bit "words"
        let mut words: Vec<u32> = vec![];
        for chunk32 in chunk512.chunks(4) {
            let mut rdr = Cursor::new(chunk32);
            words.push(rdr.read_u32::<BigEndian>().unwrap());
        }

        // Extend the 16 32-bit words into 80 32-bit words
        for index in 16..80 {
            words.push(
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1),
            );
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        // Main loop
        let mut f: u32;
        let mut k: u32;
        for index in 0..80 {
            if index < 20 {
                f = (b & c) | ((!b) & d);
                k = 0x5A827999;
            } else if index < 40 {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if index < 60 {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            let temp: u32 = add32(add32(add32(add32(a.rotate_left(5), f), e), k), words[index]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = add32(h0, a);
        h1 = add32(h1, b);
        h2 = add32(h2, c);
        h3 = add32(h3, d);
        h4 = add32(h4, e);
    }

    let mut hh = vec![];
    hh.write_u32::<BigEndian>(h0).unwrap();
    hh.write_u32::<BigEndian>(h1).unwrap();
    hh.write_u32::<BigEndian>(h2).unwrap();
    hh.write_u32::<BigEndian>(h3).unwrap();
    hh.write_u32::<BigEndian>(h4).unwrap();

    hh
}

pub fn sha1_mac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut value = key.to_vec();
    value.extend(message);
    sha1(&value)
}

#[cfg(test)]
mod tests {
    use crate::sha1::get_padding;
    use crate::sha1::sha1;

    #[test]
    fn test_sha1_padding() {
        let message: Vec<u8> = vec![0x61, 0x62, 0x63, 0x64, 0x65];
        let mut padded = message.clone();
        padded.extend(get_padding(message.len()));

        let expected_value = vec![
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
        ];

        assert_eq!(expected_value, padded);
    }

    #[test]
    fn test_sha1() {
        let mut sha = sha1(&"Hello, World!".as_bytes());

        let mut expected_value = vec![
            0x0a, 0x0a, 0x9f, 0x2a, 0x67, 0x72, 0x94, 0x25, 0x57, 0xab, 0x53, 0x55, 0xd7, 0x6a,
            0xf4, 0x42, 0xf8, 0xf6, 0x5e, 0x01,
        ];

        assert_eq!(expected_value, sha);

        sha = sha1(&"".as_bytes());

        expected_value = vec![
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];

        assert_eq!(expected_value, sha);
    }
}
