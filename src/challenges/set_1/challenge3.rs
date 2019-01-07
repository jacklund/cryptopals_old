#[cfg(test)]
mod tests {
    use crate::find_xor_key;
    use std::str;

    // Third cryptopals challenge - https://cryptopals.com/sets/1/challenges/3
    #[test]
    fn challenge3() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let ciphertext_bin = hex::decode(ciphertext).unwrap();
        let (_, _, decrypted) = find_xor_key(&ciphertext_bin).unwrap();
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            str::from_utf8(&decrypted).unwrap()
        );
    }
}
