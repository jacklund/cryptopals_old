use crate::aes_ecb::aes_128_ecb_decrypt;
use crate::aes_ecb::aes_128_ecb_encrypt;
use crate::util::pkcs7_pad;
use crate::util::validate_pkcs7_padding;
use crate::util::xor;
use crypto::symmetriccipher::SymmetricCipherError;

pub fn aes_128_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    remove_padding: bool,
) -> Result<Vec<u8>, SymmetricCipherError> {
    let chunks = ciphertext
        .chunks(16)
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut plaintext = Vec::<u8>::new();
    let mut vector = iv.to_vec();
    for chunk in chunks {
        plaintext.extend(xor(&aes_128_ecb_decrypt(&key, &chunk, false)?, &vector).unwrap());
        vector = chunk;
    }

    if remove_padding {
        Ok(validate_pkcs7_padding(&plaintext).unwrap())
    } else {
        Ok(plaintext)
    }
}

pub fn aes_128_cbc_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let chunks = pkcs7_pad(&plaintext, iv.len())
        .chunks(iv.len())
        .map(|c| c.to_vec())
        .collect::<Vec<Vec<u8>>>();
    let mut ciphertext = Vec::<u8>::new();
    let mut vector = iv.to_vec();
    for chunk in chunks {
        let cipher_chunk = aes_128_ecb_encrypt(&key, &xor(&chunk, &vector).unwrap(), false)?;
        ciphertext.extend(cipher_chunk.clone());
        vector = cipher_chunk;
    }

    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use crate::aes_cbc::aes_128_cbc_decrypt;
    use crate::aes_cbc::aes_128_cbc_encrypt;
    use std::str;

    #[test]
    fn test_encrypt_cbc_mode() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintext = "Hello World Jack";
        let iv = std::iter::repeat(0u8).take(16).collect::<Vec<u8>>();
        let ciphertext = aes_128_cbc_encrypt(&key, &iv, &plaintext.as_bytes()).unwrap();
        let decrypted = aes_128_cbc_decrypt(&key, &iv, &ciphertext, true).unwrap();
        assert_eq!(plaintext, str::from_utf8(&decrypted).unwrap());
    }
}
