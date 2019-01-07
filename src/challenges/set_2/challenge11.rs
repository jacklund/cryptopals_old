#[cfg(test)]
mod tests {
    use crate::detect_aes_ecb;
    use crate::encryption_oracle;
    use std::fs::File;
    use std::io::Read;

    // Eleventh cryptopals challenge - https://cryptopals.com/sets/2/challenges/11
    #[test]
    fn challenge11() {
        let mut plaintext = String::new();
        File::open("data/11.txt")
            .unwrap()
            .read_to_string(&mut plaintext)
            .unwrap();
        for _ in 0..100 {
            let (ciphertext, is_ecb) = encryption_oracle(&plaintext.as_bytes()).unwrap();
            assert_eq!(is_ecb, detect_aes_ecb(&ciphertext));
        }
    }
}
