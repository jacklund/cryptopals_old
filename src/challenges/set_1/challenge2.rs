#[cfg(test)]
mod tests {
    use crate::util::xor;

    // Second cryptopals challenge - https://cryptopals.com/sets/1/challenges/2
    #[test]
    fn challenge2() {
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
}
