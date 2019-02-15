#[cfg(test)]
mod tests {
    use crate::aes_cbc::aes_128_cbc_decrypt;
    use crate::aes_cbc::aes_128_cbc_encrypt;
    use crate::util::generate_random_bytes;
    use crate::util::remove_padding;
    use percent_encoding::percent_encode;
    use std::iter;
    use std::str;

    // Twenty-seventh cryptopals challenge - https://cryptopals.com/sets/4/challenges/27
    //
    // Basically, we're exposing the horrors of using the key as the IV, by encrypting
    // something 3 blocks long, then modifying the ciphertext so that it looks like
    // C1 + 0 + C1 (where 0 means a zero-block). Because of the way CBC decrypts things
    // this decrypts the last block as D(C1) ^ 0 = D(C1) and the first block as
    // D(C1) ^ IV = D(C1) ^ key. So, when we XOR them, we get:
    // D(C1) ^ D(C1) ^ key = key. ¯\_(ツ)_/¯
    #[test]
    fn challenge27() {
        define_encode_set! {
            pub ENCODING_SET = [percent_encoding::SIMPLE_ENCODE_SET] | {'=', ';'}
        };

        let key = generate_random_bytes(16);
        let iv = key.clone();

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
        let decrypt = |ciphertext: &[u8]| aes_128_cbc_decrypt(&key, &iv, ciphertext, false);

        #[derive(Debug)]
        struct ASCIIError {
            decrypted: Vec<u8>,
        };

        // Second function
        let is_admin = |ciphertext: &[u8]| {
            let decrypted = remove_padding(&decrypt(ciphertext).unwrap(), 16);
            let string;
            unsafe {
                // Have to use unsafe here because our bit flipping
                // munges the second block of the string
                string = str::from_utf8_unchecked(&decrypted);
            };
            if string.as_bytes().iter().any(|&c| c.is_ascii_control()) {
                return Err(ASCIIError { decrypted });
            }
            for token in string.split(';') {
                let split = token.split('=').collect::<Vec<&str>>();
                if split[0] == "admin" && split[1] == "true" {
                    return Ok(true);
                }
            }

            Ok(false)
        };

        // Make sure we can't just set the string
        let mut encrypted: Vec<u8> = encrypt(";admin=true;".as_bytes()).unwrap();
        assert!(!is_admin(&encrypted).unwrap());

        encrypted = encrypt("foo".as_bytes()).unwrap();
        let mut bogus_encrypted: Vec<u8> = encrypted[..16].to_vec();
        bogus_encrypted.extend(iter::repeat(0u8).take(16).collect::<Vec<u8>>());
        bogus_encrypted.extend(&encrypted[..16]);

        let error = is_admin(&bogus_encrypted).unwrap_err();
        let guessed_key: Vec<u8> = error.decrypted[..16]
            .iter()
            .zip(&error.decrypted[32..48])
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(key, guessed_key);
    }
}
