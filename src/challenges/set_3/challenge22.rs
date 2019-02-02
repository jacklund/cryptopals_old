#[cfg(test)]
mod tests {
    use crate::MarsenneTwister;
    use rand::{Rng, RngCore};
    use std::time;

    fn get_current_timestamp() -> u32 {
        let unix_time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        (unix_time.as_secs() * 1000) as u32 + unix_time.subsec_millis()
    }

    // Twenty-Second cryptopals challenge - https://cryptopals.com/sets/3/challenges/22
    // This one is silly - someone seeds the MT with the timestamp, and all you need to do
    // is grab the first random value, and then use a range of times up to now for the seed
    // guesses.
    #[test]
    fn challenge22() {
        // Random number of seconds ago
        let seconds_ago = rand::thread_rng().gen_range(40, 1000);
        let now = get_current_timestamp();
        let timestamp = now - seconds_ago * 1000;
        let mut mt = MarsenneTwister::from_seed(timestamp);
        let random_value = mt.next_u32();
        let mut seed_guess = now - (seconds_ago + 60) * 1000;
        loop {
            mt = MarsenneTwister::from_seed(seed_guess);
            if mt.next_u32() == random_value {
                break;
            } else if seed_guess > now {
                break;
            }
            seed_guess += 1;
        }

        assert_eq!(timestamp, seed_guess);
    }
}
