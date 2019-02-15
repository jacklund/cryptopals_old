use byteorder::{LittleEndian, WriteBytesExt};
use rand::RngCore;
use std::iter;

pub const U: usize = 11;
pub const D: u64 = 0xFFFFFFFF;
pub const S: usize = 7;
pub const B: u64 = 0x9D2C5680;
pub const T: usize = 15;
pub const C: u64 = 0xEFC60000;
pub const L: usize = 18;

pub struct MarsenneTwister {
    mt: Vec<u64>,
    index: usize,
    w: u64,
    n: usize,
    m: usize,
    r: usize,
    a: u64,
    f: u64,
}

impl MarsenneTwister {
    pub fn new(w: u64, n: usize, m: usize, r: usize, a: u64, f: u64) -> MarsenneTwister {
        MarsenneTwister {
            mt: iter::repeat(0u64).take(n).collect(),
            index: n,
            w,
            n,
            m,
            r,
            a,
            f,
        }
    }

    fn twist(&mut self) {
        let lower_mask: u64 = (1 << self.r) - 1;
        let upper_mask: u64 = !lower_mask;
        for i in 0..self.n {
            let x = (upper_mask & self.mt[i]) + (self.mt[(i + 1) % self.n] & lower_mask);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa |= self.a;
            }
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xa;
        }
    }
}

pub fn mt19937() -> MarsenneTwister {
    MarsenneTwister::new(32, 624, 397, 31, 0x9908B0DF, 1812433253)
}

impl MarsenneTwister {
    pub fn from_seed(seed: u32) -> Self {
        let mut mt = mt19937();
        mt.index = mt.n;
        mt.mt[0] = u64::from(seed);
        for i in 1..mt.n {
            mt.mt[i] =
                0xFFFFFFFF & (mt.f * (mt.mt[i - 1] ^ (mt.mt[i - 1] >> (mt.w - 2))) + (i as u64));
        }

        mt
    }

    pub fn from_splice(generator: &[u64]) -> Self {
        let mut mt = mt19937();
        mt.index = 0;
        mt.mt = generator.to_vec();

        mt
    }
}

pub fn temper(value: u64) -> u32 {
    let mut y: u64 = value as u64;
    y ^= (y >> U) & D;
    y ^= (y << S) & B;
    y ^= (y << T) & C;
    y ^= y >> L;

    (y & 0xFFFFFFFF) as u32
}

impl rand::RngCore for MarsenneTwister {
    fn next_u32(&mut self) -> u32 {
        if self.index >= self.n {
            self.twist();
            self.index = 0;
        };

        let result = temper(self.mt[self.index]);

        self.index += 1;
        result
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u32().into()
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unimplemented!()
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
        unimplemented!()
    }
}

pub struct MTIterator {
    mt: MarsenneTwister,
    buffer: Vec<u8>,
    index: usize,
}

impl MTIterator {
    pub fn new(seed: u32) -> Self {
        MTIterator {
            mt: MarsenneTwister::from_seed(seed),
            buffer: vec![],
            index: 0,
        }
    }
}

// Byte-wise iterator of the Marsenne Twister
impl iter::Iterator for MTIterator {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.buffer.len() {
            self.buffer.clear();
            self.buffer
                .write_u32::<LittleEndian>(self.mt.next_u32())
                .unwrap();
            self.index = 0;
        }

        let ret = self.buffer[self.index];
        self.index += 1;
        Some(ret)
    }
}

impl iter::IntoIterator for MarsenneTwister {
    type Item = u8;
    type IntoIter = MTIterator;

    fn into_iter(self) -> Self::IntoIter {
        MTIterator {
            mt: self,
            buffer: vec![],
            index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    //use brute_force_xor_key;
    use crate::mt19937::MarsenneTwister;
    use byteorder::{LittleEndian, ReadBytesExt};
    use rand::RngCore;
    use std::io::Cursor;
    use std::iter;

    #[test]
    fn test_mt19937() {
        let seed = rand::random::<u32>();
        let mut mt1 = MarsenneTwister::from_seed(seed);
        let values: Vec<u32> = iter::repeat_with(|| mt1.next_u32())
            .take(100)
            .collect::<Vec<u32>>();
        let mut mt2 = MarsenneTwister::from_seed(seed);
        let values2: Vec<u32> = iter::repeat_with(|| mt2.next_u32())
            .take(100)
            .collect::<Vec<u32>>();
        assert_eq!(None, values.iter().zip(values2).find(|(v1, v2)| *v1 != v2));
    }

    #[test]
    fn test_mt_iterator() {
        let seed = rand::random::<u32>();
        let mut mt = MarsenneTwister::from_seed(seed);
        let ref mut mt_iterator = MarsenneTwister::from_seed(seed).into_iter();
        for _count in 0..100 {
            let buffer = mt_iterator.take(4).collect::<Vec<u8>>();
            let mut rdr = Cursor::new(buffer);
            let value = rdr.read_u32::<LittleEndian>().unwrap();
            assert_eq!(mt.next_u32(), value);
        }
    }
}
