use crate::exception::CryptoError;
use std::ops::Deref;
use std::slice::Chunks;

#[derive(Debug)]
pub struct Blocks<'a> {
    blocksize: usize,
    length: usize,
    chunks: Chunks<'a, u8>,
}

impl<'a> Blocks<'a> {
    pub fn new(data: &[u8], blocksize: usize) -> Result<Blocks, CryptoError> {
        if data.len() % blocksize != 0 {
            return Err(CryptoError::BadPadding);
        };

        Ok(Blocks {
            blocksize: blocksize,
            length: data.len(),
            chunks: data.chunks(blocksize),
        })
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn byte_len(&self) -> usize {
        self.length
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.chunks
            .clone()
            .fold(Vec::<u8>::new(), |mut acc, chunk| {
                acc.extend(chunk);
                acc
            })
    }
}

impl<'a> Iterator for Blocks<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        self.chunks.next()
    }
}

impl<'a> DoubleEndedIterator for Blocks<'a> {
    fn next_back(&mut self) -> Option<&'a [u8]> {
        self.chunks.next_back()
    }
}

impl<'a> PartialEq for Blocks<'a> {
    fn eq(&self, other: &Blocks) -> bool {
        self.as_bytes().eq(&other.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use crate::block::Blocks;
    use crate::exception::CryptoError;
    use crate::util::generate_random_bytes;

    #[test]
    fn test_new() {
        assert_eq!(
            Err(CryptoError::BadPadding),
            Blocks::new(&generate_random_bytes(14), 16)
        );
        assert!(Blocks::new(&generate_random_bytes(32), 16).is_ok());
    }

    #[test]
    fn test_blocks_iterator() {
        let blocksize = 16;
        let ciphertext = generate_random_bytes(4 * blocksize);
        let mut blocks = Blocks::new(&ciphertext, blocksize).unwrap();
        assert_eq!(ciphertext[..blocksize], *blocks.next().unwrap());
        assert_eq!(
            ciphertext[blocksize..2 * blocksize],
            *blocks.next().unwrap()
        );
        assert_eq!(
            ciphertext[2 * blocksize..3 * blocksize],
            *blocks.next().unwrap()
        );
        assert_eq!(
            ciphertext[3 * blocksize..4 * blocksize],
            *blocks.next().unwrap()
        );
        assert_eq!(None, blocks.next());
    }

    #[test]
    fn test_blocks_reverse_iterator() {
        let blocksize = 16;
        let ciphertext = generate_random_bytes(4 * blocksize);
        let mut blocks = Blocks::new(&ciphertext, blocksize).unwrap().rev();
        assert_eq!(
            ciphertext[3 * blocksize..4 * blocksize],
            *blocks.next().unwrap()
        );
        assert_eq!(
            ciphertext[2 * blocksize..3 * blocksize],
            *blocks.next().unwrap()
        );
        assert_eq!(
            ciphertext[blocksize..2 * blocksize],
            *blocks.next().unwrap()
        );
        assert_eq!(ciphertext[..blocksize], *blocks.next().unwrap());
        assert_eq!(None, blocks.next());
    }
}
