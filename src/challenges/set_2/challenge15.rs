#[cfg(test)]
mod tests {
    use crate::exception::CryptoError;
    use crate::util::validate_pkcs7_padding;

    // Fifteenth cryptopals challenge - https://cryptopals.com/sets/2/challenges/15
    #[test]
    fn challenge15() {
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
}
