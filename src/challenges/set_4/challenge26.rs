#[cfg(test)]
mod tests {
    use crate::ctr::ctr;
    use crate::util::generate_random_bytes;
    use percent_encoding::percent_encode;
    use std::iter;
    use std::str;

    // Twenty-sixth cryptopals challenge - https://cryptopals.com/sets/4/challenges/26
    #[test]
    fn challenge26() {
        define_encode_set! {
            pub ENCODING_SET = [percent_encoding::SIMPLE_ENCODE_SET] | {'=', ';'}
        };

        let key = generate_random_bytes(16);
        let nonce = iter::repeat(0u8).take(8).collect::<Vec<u8>>();

        // First function
        let encrypt = |plaintext: &[u8]| {
            let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
            let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
            let mut text: Vec<u8> = Vec::new();
            text.extend(prefix);
            text.extend(
                percent_encode(&plaintext, ENCODING_SET)
                    .to_string()
                    .as_bytes(),
            );
            text.extend(suffix);

            ctr(&key, &nonce, &text)
        };

        // Decrypt function
        let decrypt = |ciphertext: &[u8]| ctr(&key, &nonce, ciphertext);

        // Second function
        let is_admin = |ciphertext: &[u8]| {
            let decrypted = decrypt(ciphertext);
            let string = str::from_utf8(&decrypted).unwrap();
            for token in string.split(';') {
                let split = token.split('=').collect::<Vec<&str>>();
                if split[0] == "admin" && split[1] == "true" {
                    return true;
                }
            }

            false
        };

        // Make sure we can't just set the string
        let mut encrypted = encrypt(";admin=true;".as_bytes());
        assert!(!is_admin(&encrypted));

        // Our attempt
        encrypted = encrypt("?admin?true?".as_bytes());

        // Since '?' = 0x3F = 1111111, to make it into a ';' we flip the third bit,
        // and to make it into an '=' we flip the second.
        encrypted[32] ^= 4;
        encrypted[38] ^= 2;
        encrypted[43] ^= 4;

        assert!(is_admin(&encrypted));
    }
}
