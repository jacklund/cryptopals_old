#[cfg(test)]
mod tests {
    use crate::break_ctr;
    use crate::ctr;
    use crate::util::read_base64_file_line_by_line;
    use std::iter;
    use std::str;

    // Twentieth cryptopals challenge - https://cryptopals.com/sets/3/challenges/20
    #[test]
    fn challenge20() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let plaintexts = read_base64_file_line_by_line("data/20.txt");

        let ciphertexts: Vec<Vec<u8>> = plaintexts
            .iter()
            .map(|p| ctr(key, &iter::repeat(0u8).take(8).collect::<Vec<u8>>(), &p))
            .collect();

        // Interestingly, the plaintexts aren't exactly the same, but are similar enough
        // to be able to read. Mostly, (very interestingly), there's just a lower-case letter
        // where there should be the corresponding upper-case one, or a minor error which is
        // still readable
        for (index, decrypted) in break_ctr(&ciphertexts).iter().enumerate() {
            println!("{}", str::from_utf8(&decrypted).unwrap());
            println!("{}", str::from_utf8(&plaintexts[index]).unwrap());
        }
    }
}
