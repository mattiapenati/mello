//! A random number generator without dependencies.

/// Generate a random value using thread-local implementation of xorshift64.
pub fn random() -> u64 {
    use std::cell::Cell;

    thread_local! {
        static STATE: Cell<u64> = Cell::new(seed());
    }

    STATE.with(|state| {
        let mut n = state.get();
        n ^= n << 13;
        n ^= n >> 7;
        n ^= n << 17;
        state.set(n);
        n
    })
}

fn seed() -> u64 {
    use std::hash::{BuildHasher, Hasher, RandomState};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    for count in 0.. {
        hasher.write_usize(count);
        let seed = hasher.finish();
        if seed != 0 {
            return seed;
        }
    }
    unreachable!("failed to generate a random seed");
}
