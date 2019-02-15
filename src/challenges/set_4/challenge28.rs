#[cfg(test)]
mod tests {
    use crate::sha1::sha1_mac;
    use crate::util::generate_random_bytes;

    #[test]
    fn challenge28() {
        let key = generate_random_bytes(16);

        let mac1 = sha1_mac(&key, &"Hello, World!".as_bytes());

        let mac2 = sha1_mac(&key, &"Goodbye, World!".as_bytes());

        assert!(mac1 != mac2);

        let key2 = generate_random_bytes(16);

        let mac3 = sha1_mac(&key2, &"Hello, World!".as_bytes());

        assert!(mac1 != mac3);
    }
}
