#[cfg(test)]
mod tests {
        use crate::util::hex_to_base64;

        // First cryptopals challenge - https://cryptopals.com/sets/1/challenges/1
        #[test]
        fn challenge1() {
                assert_eq!(hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        }
}
