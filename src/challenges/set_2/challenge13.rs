#[cfg(test)]
mod tests {
    use crate::aes_ecb::aes_128_ecb_decrypt;
    use crate::aes_ecb::aes_128_ecb_encrypt;
    use crate::find_blocksize;
    use crate::profile_for;
    use crate::util::generate_random_bytes;
    use crate::util::parse_key_value;
    use crypto::symmetriccipher::SymmetricCipherError;
    use std::collections::HashMap;
    use std::iter;
    use std::str;

    // Thirteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/13
    #[test]
    fn challenge13() {
        // Black Box
        let key = generate_random_bytes(16);
        let encrypt_user_profile = |email: &[u8]| {
            let profile = profile_for(str::from_utf8(email).unwrap(), 10, "user");
            aes_128_ecb_encrypt(&key, profile.as_bytes(), true)
        };

        // Test
        fn decrypt_user_profile(
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<HashMap<String, String>, SymmetricCipherError> {
            let mut decrypted: Vec<u8> = aes_128_ecb_decrypt(key, ciphertext, true)?;
            let mut last = decrypted.pop().unwrap();
            while last == 4u8 {
                last = decrypted.pop().unwrap();
            }
            decrypted.push(last);
            Ok(parse_key_value(str::from_utf8(&decrypted).unwrap()))
        }
        let blocksize = find_blocksize(&encrypt_user_profile).unwrap();
        assert_eq!(16, blocksize);

        // Create an "email address" long enough to fill up the first block so that we can add 'admin'
        // and padding in the next
        let mut test_email = iter::repeat('A' as u8)
            .take(blocksize - 6)
            .collect::<Vec<u8>>();
        assert_eq!(10, test_email.len()); // + "email=" makes 16 bytes
        test_email.extend("admin".as_bytes());
        test_email.extend(iter::repeat(4u8).take(11).collect::<Vec<u8>>()); // Pad rest of second block

        assert_eq!(26, test_email.len());

        // Try encrypting that email address
        let encrypted = encrypt_user_profile(&test_email).unwrap();

        // Now take the second block. We'll substitute that block in later
        let admin_block = &encrypted[16..32];

        // Next we want an email long enough to end the block with "role="
        // so that's 32 - 19, so 13 bytes
        test_email = iter::repeat('A' as u8).take(13).collect::<Vec<u8>>();
        let encrypted_again = encrypt_user_profile(&test_email).unwrap();

        // We replace the third block with our admin block
        let mut new_encrypted = encrypted_again[..32].to_vec();
        new_encrypted.extend(admin_block);

        let profile = decrypt_user_profile(&key, &new_encrypted).unwrap();

        assert_eq!("admin", profile["role"]);
    }
}
