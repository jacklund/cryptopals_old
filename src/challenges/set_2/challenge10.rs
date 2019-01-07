#[cfg(test)]
mod tests {
    use crate::aes_128_cbc_decrypt;
    use crate::util::read_base64_file;
    use std::str;

    // Tenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/10
    #[test]
    fn challenge10() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let ciphertext = read_base64_file("data/10.txt");
        let iv = std::iter::repeat(0u8).take(16).collect::<Vec<u8>>();
        let plaintext = aes_128_cbc_decrypt(&key, &iv, &ciphertext, true).unwrap();
        assert!(str::from_utf8(&plaintext)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
