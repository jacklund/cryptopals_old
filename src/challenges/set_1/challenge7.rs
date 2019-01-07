#[cfg(test)]
mod tests {
    use crate::aes_128_ecb_decrypt;
    use crate::util::read_base64_file;
    use std::str;

    // Seventh cryptopals challenge - https://cryptopals.com/sets/1/challenges/7
    #[test]
    fn challenge7() {
        let mut data = read_base64_file("data/7.txt");
        let output = aes_128_ecb_decrypt("YELLOW SUBMARINE".as_bytes(), &mut data, true).unwrap();
        assert!(str::from_utf8(&output)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
