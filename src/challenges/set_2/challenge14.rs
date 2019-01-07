#[cfg(test)]
mod tests {
    use crate::decrypt_ecb_byte_at_a_time;
    use crate::encrypt_with_prefix_and_suffix;
    use crate::util::generate_random_bytes;
    use crate::EncryptionType;
    use std::str;

    const UNKNOWN_STRING_BASE64: &str =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    // Fourteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/14
    // Output looks like:
    //   AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    // Approach:
    //   - Find prefix and target sizes
    //   - Generate message size that's bigger than target bytes and puts target bytes on block
    //     boundary
    //   - Repeat what we did with #12
    #[test]
    fn challenge14() {
        // Black Box
        let prefix_size = rand::random::<u8>() as usize;
        let prefix = generate_random_bytes(prefix_size);
        let key = generate_random_bytes(16);
        let unknown_string = base64::decode(UNKNOWN_STRING_BASE64).unwrap();
        let encrypt = |plaintext: &[u8]| {
            encrypt_with_prefix_and_suffix(
                &key,
                &prefix,
                plaintext,
                &unknown_string,
                EncryptionType::ECB,
            )
        };

        // Solution
        let solution_string = "Rollin' in my 5.0\n\
                               With my rag-top down so my hair can blow\n\
                               The girlies on standby waving just to say hi\n\
                               Did you stop? No, I just drove by\n";
        assert_eq!(
            solution_string,
            str::from_utf8(&decrypt_ecb_byte_at_a_time(encrypt)).unwrap()
        );
    }
}
