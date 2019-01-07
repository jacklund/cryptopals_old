#[cfg(test)]
mod tests {
    use crate::break_repeating_key_xor;
    use crate::encrypt_decrypt_repeating_key_xor;
    use crate::find_repeating_xor_keysize;
    use crate::util::read_base64_file;
    use std::str;

    // Sixth cryptopals challenge - https://cryptopals.com/sets/1/challenges/6
    #[test]
    fn challenge6() {
        let data = read_base64_file("data/6.txt");
        let keysize_list = find_repeating_xor_keysize(&data)
            .into_iter()
            .take(4)
            .collect::<Vec<usize>>();
        let key = break_repeating_key_xor(&data, keysize_list[0]);
        let plaintext = encrypt_decrypt_repeating_key_xor(&key, &data);
        assert!(str::from_utf8(&plaintext)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell"));
    }
}
