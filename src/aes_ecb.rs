use crypto::buffer::ReadBuffer;
use crypto::buffer::WriteBuffer;
use crypto::symmetriccipher::SymmetricCipherError;
use std::iter;

use crate::find_blocksize;
use crate::find_prefix_suffix_lengths;

pub fn aes_128_ecb_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    padding: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor = if padding {
        crypto::aes::ecb_decryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::PkcsPadding,
        )
    } else {
        crypto::aes::ecb_decryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::NoPadding,
        )
    };
    let mut output = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);
    decryptor.decrypt(
        &mut crypto::buffer::RefReadBuffer::new(&ciphertext),
        &mut write_buffer,
        true,
    )?;
    output.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .cloned(),
    );

    Ok(output)
}

pub fn aes_128_ecb_encrypt(
    key: &[u8],
    plaintext: &[u8],
    padding: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = if padding {
        crypto::aes::ecb_encryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::PkcsPadding,
        )
    } else {
        crypto::aes::ecb_encryptor(
            crypto::aes::KeySize::KeySize128,
            key,
            crypto::blockmodes::NoPadding,
        )
    };
    let mut output = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut buffer);
    encryptor.encrypt(
        &mut crypto::buffer::RefReadBuffer::new(&plaintext),
        &mut write_buffer,
        true,
    )?;
    output.extend(
        write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .cloned(),
    );

    Ok(output)
}

pub fn detect_aes_ecb(ciphertext: &[u8]) -> bool {
    let chunks = ciphertext
        .chunks(16)
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    for (index, chunk1) in chunks.iter().enumerate() {
        for chunk2 in chunks[index + 1..].to_vec() {
            if *chunk1 == chunk2 {
                return true;
            }
        }
    }
    false
}

// Decrypt an AES ECB ciphertext one byte at a time
pub fn decrypt_ecb_byte_at_a_time<F: Fn(&[u8]) -> Result<Vec<u8>, SymmetricCipherError>>(
    encrypt_fn: F,
) -> Vec<u8> {
    let blocksize = find_blocksize(&encrypt_fn).unwrap();
    let (prefix_size, target_size) = find_prefix_suffix_lengths(&encrypt_fn);

    // Number of bytes to add so that our target starts on a block boundary
    let padding_size = (blocksize - (prefix_size + target_size) % blocksize) % blocksize;

    // Our test string will be big enough to contain the target, plus whatever padding to
    // ensure the target starts on the block boundary
    let test_string_size = target_size + padding_size;

    // Start with an empty solution string and our test string
    let mut solution = Vec::<u8>::new();

    for pos in 1usize..test_string_size {
        // We start with our test string such that one character of the target is just this side
        // of the block boundary
        let mut test_string = iter::repeat(b'A')
            .take(test_string_size - pos)
            .collect::<Vec<u8>>();

        // Get our base ciphertext to compare to
        let ciphertext = encrypt_fn(&test_string).unwrap();

        // Add our solution so far
        test_string.extend(solution.clone());

        // We start with a zero byte, and increment it until our
        // ciphertexts match in that block
        test_string.push(0u8);

        // Loop through and add 1 to the last byte until the ciphertext matches our base
        // ciphertext (or we hit the end of our char set)
        loop {
            let test_ciphertext = encrypt_fn(&test_string).unwrap();

            // They match, we found another char
            if test_ciphertext[..prefix_size + test_string_size]
                == ciphertext[..prefix_size + test_string_size]
            {
                // We've hit padding, end early
                // Padding will always be 0x01 because we'll be
                // one byte away from the block boundary
                if test_string[test_string_size - 1] == 1u8 {
                    return solution; // We've hit the padding
                }
                // Add it to our solution string
                solution.push(test_string[test_string_size - 1]);
                break;
            }

            // Abort if we ran out of characters
            if test_string[test_string_size - 1] as char == '~' {
                assert!(false);
            }

            // Increment the char and try again
            test_string[test_string_size - 1] += 1;
        }
    }

    solution
}

#[cfg(test)]
mod test {
    use std::str;

    use crate::aes_ecb::aes_128_ecb_decrypt;
    use crate::aes_ecb::aes_128_ecb_encrypt;

    #[test]
    fn test_ecb_encrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "Hello World Jack";
        let ciphertext = aes_128_ecb_encrypt(&key, &plaintext.as_bytes(), true).unwrap();
        let decrypted = aes_128_ecb_decrypt(&key, &ciphertext, true).unwrap();
        assert_eq!(plaintext, str::from_utf8(&decrypted).unwrap());
    }
}
