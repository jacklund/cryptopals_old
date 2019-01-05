#[cfg(test)]
mod tests {
    use crate::aes_128_cbc_decrypt;
    use crate::aes_128_cbc_encrypt;
    use crate::aes_128_ecb_decrypt;
    use crate::aes_128_ecb_encrypt;
    use crate::break_repeating_key_xor;
    use base64;
    use rand::Rng;
    use std::cmp::max;
    //use brute_force_xor_key;
    use crate::decrypt_ecb_byte_at_a_time;
    use crate::detect_aes_ecb;
    use crate::encrypt_decrypt_repeating_key_xor;
    use crate::encrypt_with_prefix_and_suffix;
    use crate::encryption_oracle;
    use crate::exception::CryptoError;
    use crate::find_blocksize;
    use crate::find_repeating_xor_keysize;
    use crate::find_xor_key;
    use crate::generate_random_bytes;
    use crate::pkcs7_pad;
    use crate::profile_for;
    use crate::util::hex_to_base64;
    use crate::util::parse_key_value;
    use crate::util::read_base64_file;
    use crate::util::validate_pkcs7_padding;
    use crate::xor;
    use crate::EncryptionType;
    use crypto::symmetriccipher::SymmetricCipherError;
    use hex;
    use percent_encoding::percent_encode;
    use std;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};
    use std::iter;
    use std::str;

    // First cryptopals challenge - https://cryptopals.com/sets/1/challenges/1
    #[test]
    fn test_hex_to_base64() {
        assert_eq!(hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

    // Second cryptopals challenge - https://cryptopals.com/sets/1/challenges/2
    #[test]
    fn test_xor() {
        assert_eq!(
            hex::encode(
                xor(
                    &hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
                    &hex::decode("686974207468652062756c6c277320657965").unwrap()
                )
                .unwrap()
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }

    // Third cryptopals challenge - https://cryptopals.com/sets/1/challenges/3
    #[test]
    fn test_decrypt_xor() {
        let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let ciphertext_bin = hex::decode(ciphertext).unwrap();
        let (_, _, decrypted) = find_xor_key(&ciphertext_bin).unwrap();
        assert_eq!(
            "Cooking MC's like a pound of bacon",
            str::from_utf8(&decrypted).unwrap()
        );
    }

    // Fourth cryptopals challenge - https://cryptopals.com/sets/1/challenges/4
    #[test]
    fn test_detect_single_char_xor() {
        let mut score = 0;
        let mut string = vec![];
        for line in BufReader::new(File::open("data/4.txt").unwrap()).lines() {
            if let Some((s, _, decrypted)) = find_xor_key(&hex::decode(line.unwrap()).unwrap()) {
                if s > score {
                    score = s;
                    string = decrypted;
                }
            }
        }
        assert_eq!(
            "Now that the party is jumping\n",
            str::from_utf8(&string).unwrap()
        );
    }

    // Fifth cryptopals challenge - https://cryptopals.com/sets/1/challenges/5
    #[test]
    fn test_repeating_key_xor() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let ciphertext =
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
             a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let key: &str = "ICE";
        let encrypted = hex::encode(&encrypt_decrypt_repeating_key_xor(
            &key.bytes().collect::<Vec<u8>>(),
            &plaintext.bytes().collect::<Vec<u8>>(),
        ));
        assert_eq!(ciphertext, encrypted);
    }

    // Sixth cryptopals challenge - https://cryptopals.com/sets/1/challenges/6
    #[test]
    fn test_break_repeating_key_xor() {
        let data = read_base64_file("data/6.txt");
        let keysize_list = find_repeating_xor_keysize(&data)
            .into_iter()
            .take(4)
            .collect::<Vec<usize>>();
        let key = break_repeating_key_xor(&data, keysize_list[0]);
        let plaintext = encrypt_decrypt_repeating_key_xor(&key, &data);
        assert!(str::from_utf8(&plaintext)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }

    // Seventh cryptopals challenge - https://cryptopals.com/sets/1/challenges/7
    #[test]
    fn test_decrypt_aes_128_ecb() {
        let mut data = read_base64_file("data/7.txt");
        let output = aes_128_ecb_decrypt("YELLOW SUBMARINE".as_bytes(), &mut data, true).unwrap();
        assert!(str::from_utf8(&output)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }

    // Eighth cryptopals challenge - https://cryptopals.com/sets/1/challenges/8
    #[test]
    fn test_detect_aes_in_ecb_mode() {
        let mut found: Option<String> = None;
        for line in BufReader::new(File::open("data/8.txt").unwrap()).lines() {
            let real_line = line.unwrap();
            let data = base64::decode(&real_line.clone()).unwrap();
            if detect_aes_ecb(&data) {
                found = Some(real_line.clone());
                break;
            }
        }
        assert!(found
            .unwrap()
            .starts_with("d880619740a8a19b7840a8a31c810a3d08649"));
    }

    // Ninth cryptopals challenge - https://cryptopals.com/sets/2/challenges/9
    #[test]
    fn test_pkcs7_padding() {
        assert_eq!(
            "YELLOW SUBMARINE\x04\x04\x04\x04",
            str::from_utf8(&pkcs7_pad(&"YELLOW SUBMARINE".as_bytes(), 20)).unwrap()
        );
    }

    // Tenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/10
    #[test]
    fn test_decrypt_cbc_mode() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let ciphertext = read_base64_file("data/10.txt");
        let iv = std::iter::repeat(0u8).take(16).collect::<Vec<u8>>();
        let plaintext = aes_128_cbc_decrypt(&key, &iv, &ciphertext, true).unwrap();
        assert!(str::from_utf8(&plaintext)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }

    // Eleventh cryptopals challenge - https://cryptopals.com/sets/2/challenges/11
    #[test]
    fn test_detect_ecb_cbc() {
        let mut plaintext = String::new();
        File::open("data/11.txt")
            .unwrap()
            .read_to_string(&mut plaintext)
            .unwrap();
        for _ in 0..100 {
            let (ciphertext, is_ecb) = encryption_oracle(&plaintext.as_bytes()).unwrap();
            assert_eq!(is_ecb, detect_aes_ecb(&ciphertext));
        }
    }

    const UNKNOWN_STRING_BASE64: &str =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
         aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
         dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    // Twelfth cryptopals challenge - https://cryptopals.com/sets/2/challenges/12
    #[test]
    fn test_byte_at_a_time_ecb_decryption() {
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

    // Thirteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/13
    #[test]
    fn test_ecb_cut_and_paste() {
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

    // Fourteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/14
    // Output looks like:
    //   AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    // Approach:
    //   - Find prefix and target sizes
    //   - Generate message size that's bigger than target bytes and puts target bytes on block
    //     boundary
    //   - Repeat what we did with #12
    #[test]
    fn test_harder_byte_at_a_time_ecb() {
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

    // Fifteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/15
    #[test]
    fn test_validate_pkcs7() {
        assert_eq!(
            Ok("ICE ICE BABY".as_bytes().to_vec()),
            validate_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04".as_bytes())
        );
        assert_eq!(
            Err(CryptoError::BadPadding),
            validate_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05".as_bytes())
        );
        assert_eq!(
            Err(CryptoError::BadPadding),
            validate_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04".as_bytes())
        );
    }

    // Sixteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/16
    #[test]
    fn test_bit_flipping_attack() {
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

    const PADDING_ORACLE_STRINGS: [&str; 10] = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    // Seventeenth cryptopals challenge - https://cryptopals.com/sets/3/challenges/17
    #[test]
    fn test_cbc_padding_oracle() {
        let blocksize = 16;
        let key = generate_random_bytes(blocksize);
        let mut rng = rand::thread_rng();
        let plaintext = PADDING_ORACLE_STRINGS[rng.gen_range(0, 10)].as_bytes();

        // First function
        // Encrypt a random plaintext and return the ciphertext and the IV
        let encrypt = || {
            let iv = iter::repeat_with(|| rand::random::<u8>())
                .take(blocksize)
                .collect::<Vec<u8>>();
            (aes_128_cbc_encrypt(&key, &iv, &plaintext).unwrap(), iv)
        };

        // Second function
        // Decrypt the ciphertext and return true if the padding is legit, false if not
        let check_padding = |ciphertext: &[u8], iv: &[u8]| {
            let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext, false).unwrap();
            match validate_pkcs7_padding(&decrypted) {
                Ok(_) => true,
                Err(_) => false,
            }
        };

        // Function to decrypt it block-by-block
        let try_block = |block_num: usize, ciphertext: &[u8], iv: &[u8], solution: &mut Vec<u8>| {
            // If we're at the first block, we have to modify the IV,
            // otherwise we're modifying the previous block of ciphertext
            let mut block = if block_num == 0 {
                iv.to_vec()
            } else {
                ciphertext.to_vec()
            };

            // Iterate through the block
            for block_index in (0..blocksize).rev() {
                // The value we're modifying is either in the IV or the ciphertext
                let index = if block_num == 0 {
                    block_index
                } else {
                    (block_num - 1) * blocksize + block_index
                };

                // Hold on to the actual value
                let original_value = block[index];
                let padding_value: u8 = (blocksize - block_index) as u8;
                let mut found = false;

                // Try all the possible u8 values
                for byte in 0..=255 {
                    if byte != original_value {
                        block[index] = byte;
                        let padding_correct = if block_num == 0 {
                            check_padding(ciphertext, &block)
                        } else {
                            check_padding(&block, iv)
                        };
                        // Found it
                        if padding_correct {
                            solution.push(byte ^ padding_value ^ original_value);
                            found = true;
                            break;
                        }
                    }
                }

                // If we didn't find it, chances are it's the first byte of padding
                // because that wouldn't need to be changed
                if !found {
                    solution.push(padding_value);
                    block[index] = original_value;
                }

                // We modify the padding bytes we've done so far to generate
                // the next padding value
                if block_index > 0 {
                    let block_max = if block_num == 0 {
                        blocksize
                    } else {
                        block_num * blocksize
                    };
                    for mod_index in index..block_max {
                        block[mod_index] ^= padding_value ^ (padding_value + 1);
                    }
                }
            }
        };

        let mut solution = Vec::<u8>::new();

        // To start, we grab the ciphertext
        let (ciphertext, iv) = encrypt();

        // We clone the ciphertext and iterate backwards through the blocks
        let num_blocks = ciphertext.len() / blocksize;
        let test_ciphertext = ciphertext.clone();
        for block in (0..num_blocks).rev() {
            try_block(
                block,
                &test_ciphertext[..(block + 1) * blocksize], // Truncate the last block after we're done
                &iv,
                &mut solution,
            );
        }

        // Reverse the order of the solution
        solution.reverse();
        assert_eq!(
            str::from_utf8(plaintext).unwrap(),
            str::from_utf8(&validate_pkcs7_padding(&solution).unwrap()).unwrap(),
        );
    }
}
