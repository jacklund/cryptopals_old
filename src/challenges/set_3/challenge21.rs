#[cfg(test)]
mod tests {
    use crate::MarsenneTwister;
    use rand::RngCore;

    // Twenty-First cryptopals challenge - https://cryptopals.com/sets/3/challenges/21
    #[test]
    fn challenge21() {
        let seed: u32 = rand::random::<u32>();
        let mut mt = MarsenneTwister::from_seed(seed);
        for _ in 0..100 {
            println!("{}", mt.next_u32());
        }
    }
}
