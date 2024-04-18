//! Cross Site Request Forgery protection.
//!
//! CSRF protection token are 32 bytes randomly generated token signed using
//! HMAC-BLAKE2.
//!
//! Each CSRF token is signed using the HMAC-BLAKE2 authentication algorithm
//! to guarantee its authenticity. Keys can be derived from a [`MasterKey`],
//! each derived key is identified by a tag (a string) and keys generated with
//! the same tag are equal.
//!
//! ```
//! let master = MasterKey::generate();
//! let key = CsrfKey::derive(&master, "tag");
//! ```

use std::fmt::Display;

use base64ct::{Base64Url, Encoding};
use hmac::Mac;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{debug::DebugSha256, rng, MasterKey};

/// A typedef of the signature algorithm.
type Hmac = hmac::SimpleHmac<blake2::Blake2s256>;

/// Private key used to sign and verify tokens.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct CsrfKey([u8; Self::BYTES]);

impl std::fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CsrfKey")
            .field(&DebugSha256(&self.0))
            .finish()
    }
}

impl CsrfKey {
    /// The size of the key in bytes.
    const BYTES: usize = 64;
    /// The size of the encoded key in bytes.
    const ENCODED_BYTES: usize = (Self::BYTES * 4 / 3 + 3) & !3;

    /// Generate a new random key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut bytes));
        Self(bytes)
    }

    /// Derive a new key, keys with the same tag are equals.
    pub fn derive(master: &MasterKey, tag: &str) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        master.fill_bytes(tag, &mut bytes);
        Self(bytes)
    }

    /// Returns an object that implements [`Display`].
    ///
    /// [`Display`]: std::fmt::Display
    pub fn display(&self) -> impl Display + '_ {
        DisplayCsrfKey(self)
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl CsrfKey {
    /// Generate a new random key.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_js() -> CsrfKey {
        Self::generate()
    }

    /// Derive a new key, keys with the same tag are equals.
    #[wasm_bindgen(js_name = derive)]
    pub fn derive_js(master: &MasterKey, tag: &str) -> CsrfKey {
        Self::derive(master, tag)
    }
    /// Returns a string representing this object.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.display().to_string()
    }

    /// Parses a string containing a CSRF key.
    #[wasm_bindgen(js_name = parseFromString)]
    pub fn parse_from_string(s: &str) -> Result<CsrfKey, JsError> {
        s.parse().map_err(JsError::from)
    }
}

/// Helper struct for explicitly printing [`CsrfKey`].
struct DisplayCsrfKey<'a>(&'a CsrfKey);

impl<'a> std::fmt::Debug for DisplayCsrfKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0, f)
    }
}

impl<'a> std::fmt::Display for DisplayCsrfKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let CsrfKey(bytes) = self.0;

        let mut buffer = [0u8; CsrfKey::ENCODED_BYTES];
        let encoded_key = Base64Url::encode(bytes, &mut buffer).expect("Failed to encode CSRF key");

        f.write_str(encoded_key)
    }
}

impl std::str::FromStr for CsrfKey {
    type Err = InvalidCsrfKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::BYTES];
        let len = Base64Url::decode(s, &mut bytes)
            .map_err(|_| InvalidCsrfKey)?
            .len();
        (len == Self::BYTES)
            .then_some(Self(bytes))
            .ok_or(InvalidCsrfKey)
    }
}

/// The error type returned when a key is invalid.
#[derive(Clone, Copy, Debug)]
pub struct InvalidCsrfKey;

impl std::fmt::Display for InvalidCsrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CSRF key is invalid")
    }
}

impl std::error::Error for InvalidCsrfKey {}

/// CSRF signed token.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct CsrfToken([u8; Self::BYTES]);

impl std::fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CsrfToken")
            .field(&DebugSha256(&self.0))
            .finish()
    }
}

impl CsrfToken {
    /// The number of random bytes.
    const RANDOM_BYTES: usize = 32;
    /// The size of the signature in bytes.
    const SIGNATURE_BYTES: usize = 32;
    /// The size of the token in bytes.
    const BYTES: usize = Self::RANDOM_BYTES + Self::SIGNATURE_BYTES;
    /// The size of the encoded token in bytes.
    const ENCODED_BYTES: usize = (Self::BYTES * 4 / 3 + 3) & !3;

    /// Generate a new CSRF random token, signed with the given key.
    pub fn generate(key: &CsrfKey) -> Self {
        // generate random bytes
        let mut bytes = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut bytes[..Self::RANDOM_BYTES]));

        // token signature
        let mut mac = Hmac::new_from_slice(&key.0).unwrap();
        mac.update(&bytes[..Self::RANDOM_BYTES]);
        let signature = mac.finalize().into_bytes();
        bytes[Self::RANDOM_BYTES..].clone_from_slice(&signature);

        Self(bytes)
    }

    /// Verify the CSRF token with the given key.
    pub fn verify(&self, key: &CsrfKey) -> Result<(), InvalidCsrfToken> {
        let Self(bytes) = self;

        let mut mac = Hmac::new_from_slice(&key.0).unwrap();
        mac.update(&bytes[..Self::RANDOM_BYTES]);
        mac.verify_slice(&bytes[Self::RANDOM_BYTES..])
            .map_err(|_| InvalidCsrfToken)
    }

    /// Returns an object that implements [`Display`].
    pub fn display(&self) -> impl Display + '_ {
        DisplayCsrfToken(self)
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl CsrfToken {
    /// Generate a new CSRF random token, signed with the given key.
    #[wasm_bindgen(js_name = generate)]
    pub fn generate_js(key: &CsrfKey) -> CsrfToken {
        Self::generate(key)
    }

    /// Verify the CSRF token with the given key.
    #[wasm_bindgen(js_name = verify)]
    pub fn verify_js(&self, key: &CsrfKey) -> Result<(), JsError> {
        self.verify(key).map_err(JsError::from)
    }

    /// Returns a string representing this object.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.display().to_string()
    }

    /// Parses a string containing a CSRF token.
    #[wasm_bindgen(js_name = parseFromString)]
    pub fn parse_from_string(s: &str) -> Result<CsrfToken, JsError> {
        s.parse().map_err(JsError::from)
    }
}

/// Helper struct for explicitly printing [`CsrfToken`].
struct DisplayCsrfToken<'a>(&'a CsrfToken);

impl<'a> std::fmt::Debug for DisplayCsrfToken<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0, f)
    }
}

impl<'a> std::fmt::Display for DisplayCsrfToken<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let CsrfToken(bytes) = self.0;

        let mut buffer = [0u8; CsrfToken::ENCODED_BYTES];
        let encoded_key =
            Base64Url::encode(bytes, &mut buffer).expect("Failed to encode CSRF token");

        f.write_str(encoded_key)
    }
}

impl std::str::FromStr for CsrfToken {
    type Err = InvalidCsrfToken;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::BYTES];
        let len = Base64Url::decode(s, &mut bytes)
            .map_err(|_| InvalidCsrfToken)?
            .len();
        (len == Self::BYTES)
            .then_some(Self(bytes))
            .ok_or(InvalidCsrfToken)
    }
}

/// The error type returned when a token is invalid.
#[derive(Clone, Copy, Debug)]
pub struct InvalidCsrfToken;

impl std::fmt::Display for InvalidCsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CSRF token is invalid")
    }
}

impl std::error::Error for InvalidCsrfToken {}

#[cfg(test)]
mod tests {
    use claym::*;

    use super::*;

    #[test]
    fn csrf_token_generation_and_verification() {
        let key = CsrfKey::generate();
        let token = CsrfToken::generate(&key);
        assert_ok!(token.verify(&key));

        let another_key = CsrfKey::generate();
        assert_err!(token.verify(&another_key));
    }

    #[test]
    fn csrf_derived_keys_as_distinct() {
        let master = MasterKey::generate();
        let signup_key = CsrfKey::derive(&master, "signup");
        let token = CsrfToken::generate(&signup_key);

        let new_signup_key = CsrfKey::derive(&master, "signup");
        assert_ok!(token.verify(&new_signup_key));

        let signin_key = CsrfKey::derive(&master, "signin");
        assert_err!(token.verify(&signin_key));
    }
}
