use crate::{B, C, L, S, T, U};
use std::u32;

// The following were cribbed from https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
// I managed the xor parts on my own, but TBH I still don't completely understand how the mask stuff works
fn unbitshift_right_xor(v: u64, shift: usize) -> u64 {
    let mut i = 0;
    let mut result: u64 = 0;
    let mut value: u64 = v;
    while i * shift < 32 {
        let partmask: u64 = ((u32::MAX << (32 - shift)) >> (shift * i) as u64).into();
        let part: u64 = value & partmask;
        value ^= part >> shift;
        result |= part;
        i += 1;
    }

    result
}

fn unbitshift_left_xor(v: u64, shift: usize, mask: u64) -> u64 {
    let mut i = 0;
    let mut result: u64 = 0;
    let mut value: u64 = v;
    while i * shift < 32 {
        let partmask: u64 = ((u32::MAX >> (32 - shift)) << (shift * i) as u64).into();
        let part: u64 = value & partmask;
        value ^= (part << shift) & mask;
        result |= part;
        i += 1;
    }

    result
}

fn untemper(value: u32) -> u64 {
    let mut result = unbitshift_right_xor(u64::from(value), L);
    result = unbitshift_left_xor(result, T, C);
    result = unbitshift_left_xor(result, S, B);
    result = unbitshift_right_xor(result, U);

    result as u64
}

#[cfg(test)]
mod tests {
    use crate::challenges::set_3::challenge23::{
        unbitshift_left_xor, unbitshift_right_xor, untemper,
    };
    use crate::{temper, MarsenneTwister, B, C, L, S, T, U};
    use rand::RngCore;

    #[test]
    fn test_unbitshift_left_xor() {
        let mut original: u64 = rand::random::<u32>() as u64;
        let mut value = original ^ ((original << S) & B);

        assert_eq!(original, unbitshift_left_xor(value, S, B));

        original = rand::random::<u32>() as u64;
        value = original ^ ((original << T) & C);

        assert_eq!(original, unbitshift_left_xor(value, T, C));
    }

    #[test]
    fn test_unbitshift_right_xor() {
        let mut original: u64 = rand::random::<u32>() as u64;
        let mut value = original ^ (original >> L);

        assert_eq!(original, unbitshift_right_xor(value, L));

        original = rand::random::<u32>() as u64;
        value = original ^ (original >> U);

        assert_eq!(original, unbitshift_right_xor(value, U));
    }

    #[test]
    fn test_untemper() {
        let original: u64 = rand::random::<u32>() as u64;
        let result: u32 = temper(original);

        let untempered = untemper(result);
        println!("original = {:x}, untempered = {:x}", original, untempered);
        assert_eq!(original, untempered);
    }

    #[test]
    fn challenge23() {
        let mut mt = MarsenneTwister::from_seed(rand::random::<u32>());
        let mut values = vec![];
        for _ in 0..624 {
            values.push(mt.next_u32());
        }

        let mut generator = vec![];
        for index in 0..624 {
            generator.push(untemper(values[index]));
        }

        let mut mt2 = MarsenneTwister::from_splice(&generator);
        for index in 0..624 {
            println!("Index = {}", index);
            assert_eq!(values[index], mt2.next_u32());
        }
    }
}
