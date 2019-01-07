#[cfg(test)]
mod tests {
    use crate::util::pkcs7_pad;
    use std::str;

    // Ninth cryptopals challenge - https://cryptopals.com/sets/2/challenges/9
    #[test]
    fn challenge9() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04",
            str::from_utf8(&pkcs7_pad(&"YELLOW SUBMARINE".as_bytes(), 20)).unwrap()
        );
    }
}
