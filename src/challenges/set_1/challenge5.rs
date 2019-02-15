#[cfg(test)]
mod tests {
    use crate::xor::encrypt_decrypt_repeating_key_xor;

    // Fifth cryptopals challenge - https://cryptopals.com/sets/1/challenges/5
    #[test]
    fn challenge5() {
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
}
