#[cfg(test)]
mod tests {
    use crate::aes_128_cbc_decrypt;
    use crate::aes_128_cbc_encrypt;
    use crate::util::generate_random_bytes;
    use percent_encoding::percent_encode;
    use std::iter;
    use std::str;

    // Sixteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/16
    #[test]
    fn challenge16() {
        define_encode_set! {
            pub ENCODING_SET = [percent_encoding::SIMPLE_ENCODE_SET] | {'=', ';'}
        };

        let key = generate_random_bytes(16);
        let iv = iter::repeat(0u8).take(16).collect::<Vec<u8>>();

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

            aes_128_cbc_encrypt(&key, &iv, &text)
        };

        // Decrypt function
        let decrypt = |ciphertext: &[u8]| aes_128_cbc_decrypt(&key, &iv, ciphertext, true);

        // Second function
        let is_admin = |ciphertext: &[u8]| {
            let decrypted = decrypt(ciphertext).unwrap();
            let string;
            unsafe {
                // Have to use unsafe here because our bit flipping
                // munges the second block of the string
                string = str::from_utf8_unchecked(&decrypted);
            };
            for token in string.split(';') {
                let split = token.split('=').collect::<Vec<&str>>();
                if split[0] == "admin" && split[1] == "true" {
                    return true;
                }
            }

            false
        };

        // Make sure we can't just set the string
        let mut encrypted = encrypt(";admin=true;".as_bytes()).unwrap();
        assert!(!is_admin(&encrypted));

        // Our attempt
        encrypted = encrypt("?admin?true?".as_bytes()).unwrap();

        // If we flip the bits on the block containing our data, it will munge the entire block,
        // so instead we flip bits on the previous block, and the errors propagate through to our
        // target block. Since '?' = 0x3F = 1111111, to make it into a ';' we flip the third bit,
        // and to make it into an '=' we flip the second.
        encrypted[16] ^= 4;
        encrypted[22] ^= 2;
        encrypted[27] ^= 4;

        assert!(is_admin(&encrypted));
    }
}
