use crate::ctr::CTRKeystreamIterator;
use std::iter;

// "Edit" part of the ciphertext by decrypting that part, changing it, then re-encrypting
// We create a keystream which is zeroes everywhere but where the text to change is.
pub fn edit_ctr(ciphertext: &[u8], key: &[u8], offset: usize, new_text: &[u8]) -> Vec<u8> {
    let keystream: CTRKeystreamIterator =
        CTRKeystreamIterator::new(key, &iter::repeat(0u8).take(8).collect::<Vec<u8>>());

    let keystream_chunk: Vec<u8> = keystream
        .clone()
        .skip(offset)
        .take(new_text.len())
        .collect();
    let ciphertext_chunk: Vec<u8> = new_text
        .iter()
        .zip(keystream_chunk.iter())
        .map(|(t, k)| t ^ k)
        .collect();

    let mut output: Vec<u8> = ciphertext.to_vec();
    output[offset..(offset + new_text.len())].clone_from_slice(&ciphertext_chunk[0..((offset + new_text.len()) - offset)]);

    output
}

#[cfg(test)]
mod tests {
    use crate::challenges::set_4::challenge25::edit_ctr;
    use crate::util::{read_base64_file, generate_random_bytes};
    use crate::aes_ecb::aes_128_ecb_decrypt;
    use crate::ctr::ctr;
    use crate::util::ETAOIN;
    use std::iter;
    use std::str;

    #[test]
    fn test_edit_ctr() {
        let plaintext = "The quick brown fox jumps over the lazy dog";
        let key = generate_random_bytes(16);
        let ciphertext = ctr(
            &key,
            &iter::repeat(0u8).take(8).collect::<Vec<u8>>(),
            plaintext.as_bytes(),
        );

        let new_ciphertext = edit_ctr(&ciphertext, &key, 16, "dog".as_bytes());

        let new_plaintext = ctr(
            &key,
            &iter::repeat(0u8).take(8).collect::<Vec<u8>>(),
            &new_ciphertext,
        );

        assert_eq!(
            "The quick brown dog jumps over the lazy dog",
            str::from_utf8(&new_plaintext).unwrap()
        );
    }

    // Twenty-fifth cryptopals challenge - https://cryptopals.com/sets/4/challenges/25
    #[test]
    fn challenge25() {
        let mut data = read_base64_file("data/25.txt");
        let plaintext =
            aes_128_ecb_decrypt("YELLOW SUBMARINE".as_bytes(), &mut data, true).unwrap();
        assert!(str::from_utf8(&plaintext)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));

        let key: Vec<u8> = generate_random_bytes(16);

        let ciphertext = ctr(
            &key,
            &iter::repeat(0u8).take(8).collect::<Vec<u8>>(),
            &plaintext,
        );

        let edit_api = |ciphertext: &[u8], offset: usize, text: &[u8]| {
            edit_ctr(&ciphertext, &key, offset, text)
        };

        let mut my_plaintext: Vec<u8> = vec![];
        for index in 0..ciphertext.len() {
            let mut found = false;
            for letter in ETAOIN.as_bytes() {
                let new_ciphertext = edit_api(&ciphertext, index, &[*letter]);
                if new_ciphertext[index] == ciphertext[index] {
                    my_plaintext.push(*letter);
                    found = true;
                    break;
                }
            }
            assert!(found);
        }
        assert!(str::from_utf8(&my_plaintext)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
