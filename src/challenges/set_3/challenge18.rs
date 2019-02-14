#[cfg(test)]
mod tests {
    use crate::ctr;
    use std::iter;
    use std::str;

    // Eighteenth cryptopals challenge - https://cryptopals.com/sets/3/challenges/18
    #[test]
    fn challenge18() {
        let ciphertext: Vec<u8> = base64::decode(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".as_bytes(),
        )
        .unwrap();
        let key: &[u8] = "YELLOW SUBMARINE".as_bytes();

        let decrypted = ctr(
            key,
            &iter::repeat(0u8).take(8).collect::<Vec<u8>>(),
            &ciphertext,
        );

        assert_eq!(
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
            str::from_utf8(&decrypted).unwrap()
        );
    }
}
