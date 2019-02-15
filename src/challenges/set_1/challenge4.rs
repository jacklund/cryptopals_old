#[cfg(test)]
mod tests {
    use crate::xor::find_xor_key;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::str;

    // Fourth cryptopals challenge - https://cryptopals.com/sets/1/challenges/4
    #[test]
    fn challenge4() {
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
}
