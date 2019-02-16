#[cfg(test)]
mod tests {
    use crate::sha1::get_padding;
    use crate::sha1::sha1_mac;
    use crate::sha1::sha1_with_init;
    use crate::util::generate_random_bytes;
    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use std::io::Cursor;

    fn slice_to_u32(slice: &[u8]) -> u32 {
        let mut rdr = Cursor::new(slice);
        rdr.read_u32::<BigEndian>().unwrap()
    }

    #[test]
    fn challenge29() {
        let original_plaintext =
            "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let key = "SuperSecretKey";
        let mac = sha1_mac(&key.as_bytes(), &original_plaintext.as_bytes());

        let validate_mac = |message: &[u8], digest| sha1_mac(&key.as_bytes(), message) == digest;

        let mut chunks = mac.chunks(4);
        let a = slice_to_u32(&chunks.next().unwrap());
        let b = slice_to_u32(&chunks.next().unwrap());
        let c = slice_to_u32(&chunks.next().unwrap());
        let d = slice_to_u32(&chunks.next().unwrap());
        let e = slice_to_u32(&chunks.next().unwrap());
        println!("mac = {:x?}", mac);
        println!(
            "a = {:x?}, b = {:x?}, c = {:x?}, d = {:x?}, e = {:x?}",
            a, b, c, d, e
        );

        let new_message = ";admin=true";

        let generate_forged_message = |keylen| {
            let glue_padding = get_padding(keylen + original_plaintext.len());
            let mut forged_message = original_plaintext.as_bytes().to_vec();
            forged_message.extend(glue_padding);
            forged_message.extend(new_message.as_bytes().to_vec());
            let forged_digest = sha1_with_init(
                &new_message.as_bytes(),
                a,
                b,
                c,
                d,
                e,
                keylen + forged_message.len(),
            );
            (forged_message, forged_digest)
        };

        for keylen in 0..30 {
            let (message, digest) = generate_forged_message(keylen);
            if validate_mac(&message, digest) {
                assert_eq!(key.len(), keylen);
                return;
            }
        }

        assert!(false);
    }
}
