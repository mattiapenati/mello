//! A cryptographically secure key that can be used to generate new keys.

use std::fmt::Display;

use base64ct::{Base64Url, Encoding};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{debug::DebugSha256, rng};

/// A cryptographically secure random key, it can be used to derive other keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct MasterKey([u8; Self::BYTES]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MasterKey")
            .field(&DebugSha256(&self.0))
            .finish()
    }
}

impl MasterKey {
    /// The size of the key in bytes.
    const BYTES: usize = 64;
    /// The size of the encoded key in bytes.
    const ENCODED_BYTES: usize = 88;

    /// Generate a new random master key using the ChaCha random number generator.
    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut bytes));
        Self(bytes)
    }

    /// Fill the array with random bytes, the generated sequence depends on the
    /// [`MasterKey`] and the tag.
    pub(crate) fn fill_bytes<T: AsRef<[u8]>>(&self, tag: T, bytes: &mut [u8]) {
        argon2::Argon2::default()
            .hash_password_into(tag.as_ref(), &self.0, bytes)
            .expect("failed to generate derived CSRF key");
    }

    /// Returns an object that implements [`Display`].
    ///
    /// [`Display`]: std::fmt::Display
    pub fn display(&self) -> impl Display + '_ {
        DisplayMasterKey(self)
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl MasterKey {
    /// Generate a new random master key using the ChaCha random number generator.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_js() -> MasterKey {
        Self::generate()
    }

    /// Returns a string representing this object.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.display().to_string()
    }

    /// Parses a string containing a master key.
    #[wasm_bindgen(js_name = parseFromString)]
    pub fn parse_from_string(s: &str) -> Result<MasterKey, JsError> {
        s.parse().map_err(JsError::from)
    }
}

/// Helper struct for explicitly printing [`CsrfKey`].
struct DisplayMasterKey<'a>(&'a MasterKey);

impl<'a> std::fmt::Debug for DisplayMasterKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0, f)
    }
}

impl<'a> std::fmt::Display for DisplayMasterKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(key) = self;
        let mut buffer = [0u8; MasterKey::ENCODED_BYTES];
        let encoded_key = Base64Url::encode(key.0.as_slice(), buffer.as_mut_slice()).unwrap();
        f.write_str(encoded_key)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InvalidMasterKey;

impl std::fmt::Display for InvalidMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Master key is invalid")
    }
}

impl std::error::Error for InvalidMasterKey {}

impl std::str::FromStr for MasterKey {
    type Err = InvalidMasterKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::BYTES];
        let len = Base64Url::decode(s, &mut bytes)
            .map_err(|_| InvalidMasterKey)?
            .len();
        (len == Self::BYTES)
            .then_some(Self(bytes))
            .ok_or(InvalidMasterKey)
    }
}
