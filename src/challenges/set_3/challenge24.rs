#[cfg(test)]
mod tests {
    use crate::mt_encrypt_decrypt;
    use rand;
    use rand::Rng;

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
