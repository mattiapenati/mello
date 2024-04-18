//! Random number generators

use std::{cell::UnsafeCell, rc::Rc};

use rand::{
    rngs::{adapter::ReseedingRng, OsRng},
    SeedableRng,
};
use rand_chacha::ChaChaCore;
use rand_pcg::Pcg64;

/// A cryptographically secure random generator with reseed.
pub struct CryptoRng {
    inner: ReseedingRng<ChaChaCore, OsRng>,
}

thread_local! {
    static CRYPTO_RNG: Rc<UnsafeCell<CryptoRng>> = {
        let rng = ChaChaCore::from_rng(OsRng)
            .unwrap_or_else(|err| panic!("Failed initialize random number generator: {err}"));
        let threshold: u64 = 32 * 1024; // 32kB
        let inner = ReseedingRng::new(rng, threshold, OsRng);
        Rc::new(UnsafeCell::new(CryptoRng { inner }))
    };
}

/// Calls `f`, passing the cryptographically secure random number generator to `f`.
pub fn with_crypto_rng<F, T>(f: F) -> T
where
    F: FnOnce(&mut CryptoRng) -> T,
{
    CRYPTO_RNG.with(|rng| f(unsafe { &mut *rng.get() }))
}

impl rand::RngCore for CryptoRng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl rand::CryptoRng for CryptoRng {}

/// A fast random number generator.
pub struct Rng {
    inner: Pcg64,
}

thread_local! {
    static RNG: Rc<UnsafeCell<Rng>> = {
        let inner = Pcg64::from_rng(OsRng)
            .unwrap_or_else(|err| panic!("Failed initialize random number generator: {err}"));
        Rc::new(UnsafeCell::new(Rng { inner }))
    };
}

/// Calls `f`, passing the random number generator to `f`.
pub fn with_rng<F, T>(f: F) -> T
where
    F: FnOnce(&mut Rng) -> T,
{
    RNG.with(|rng| f(unsafe { &mut *rng.get() }))
}

impl rand::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.inner.try_fill_bytes(dest)
    }
}
