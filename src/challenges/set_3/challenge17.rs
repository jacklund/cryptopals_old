#[cfg(test)]
mod tests {
    use crate::aes_128_cbc_decrypt;
    use crate::aes_128_cbc_encrypt;
    use crate::util::generate_random_bytes;
    use crate::validate_pkcs7_padding;
    use rand::Rng;
    use std::iter;
    use std::str;

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
    fn challenge17() {
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
