#[cfg(test)]
mod tests {
    use crate::aes_ecb::decrypt_ecb_byte_at_a_time;
    use crate::aes_ecb::detect_aes_ecb;
    use crate::encrypt_with_prefix_and_suffix;
    use crate::find_blocksize;
    use crate::util::generate_random_bytes;
    use crate::EncryptionType;
    use std::iter;
    use std::str;

    const UNKNOWN_STRING_BASE64: &str =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    // Twelfth cryptopals challenge - https://cryptopals.com/sets/2/challenges/12
    #[test]
    fn challenge12() {
        // Black Box
        let key = generate_random_bytes(16);
        let encrypt_with_string = |plaintext: &[u8]| {
            let unknown_string = base64::decode(UNKNOWN_STRING_BASE64).unwrap();
            encrypt_with_prefix_and_suffix(
                &key,
                &vec![],
                plaintext,
                &unknown_string,
                EncryptionType::ECB,
            )
        };

        // Test
        let blocksize = find_blocksize(&encrypt_with_string).unwrap();
        assert_eq!(16, blocksize);
        let ciphertext =
            encrypt_with_string(&iter::repeat(0u8).take(2 * blocksize).collect::<Vec<u8>>())
                .unwrap();
        assert!(detect_aes_ecb(&ciphertext));
        let solution_string = "Rollin' in my 5.0\n\
                               With my rag-top down so my hair can blow\n\
                               The girlies on standby waving just to say hi\n\
                               Did you stop? No, I just drove by\n";
        assert_eq!(
            solution_string,
            str::from_utf8(&decrypt_ecb_byte_at_a_time(encrypt_with_string)).unwrap()
        );
    }
}
