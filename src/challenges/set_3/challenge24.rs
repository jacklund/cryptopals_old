use crate::MTIterator;

// Encrypt/decrypt using MT
pub fn mt_encrypt_decrypt(key: u32, text: &[u8]) -> Vec<u8> {
    let iter = MTIterator::new(key);

    text.iter().zip(iter).map(|(t, k)| t ^ k).collect()
}

#[cfg(test)]
mod tests {
    use crate::challenges::set_3::challenge24::mt_encrypt_decrypt;
    use rand;
    use rand::Rng;
    use std::str;

    #[test]
    fn test_mt_encrypt_decrypt() {
        let key = rand::random::<u32>();
        let text = "Hello, World!";

        let ciphertext = mt_encrypt_decrypt(key, text.as_bytes());
        let plaintext = mt_encrypt_decrypt(key, &ciphertext);

        assert_eq!(text, str::from_utf8(&plaintext).unwrap());
    }

    fn setup_challenge24(key: u32, known_plaintext: &str) -> Vec<u8> {
        let prefix_length: usize = rand::thread_rng().gen_range(1, 20);
        let prefix = (0..prefix_length)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();
        let mut plaintext = prefix.clone();
        plaintext.extend(known_plaintext.as_bytes());
        mt_encrypt_decrypt(key, &plaintext)
    }

    #[test]
    fn challenge24() {
        let known_plaintext = "AAAAAAAAAAAAAA";
        let known_plaintext_bytes = known_plaintext.as_bytes();
        let key = rand::thread_rng().gen_range(0, std::u16::MAX) as u32;

        let ciphertext = setup_challenge24(key, known_plaintext);
        let prefix_length = ciphertext.len() - known_plaintext.len();
        for test_key in 0..std::u16::MAX as u32 {
            let possible_plaintext = mt_encrypt_decrypt(test_key, &ciphertext);
            if &possible_plaintext[prefix_length..] == known_plaintext_bytes {
                assert_eq!(key, test_key);
                return;
            }
        }
        assert!(false);
    }
}
