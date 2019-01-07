#[cfg(test)]
mod tests {
    use crate::detect_aes_ecb;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Eighth cryptopals challenge - https://cryptopals.com/sets/1/challenges/8
    #[test]
    fn challenge8() {
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
}
