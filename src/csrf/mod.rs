//! Cross Site Request Forgery protection.
//!
//! CSRF protection token are 32 bytes randomly generated token signed using
//! HMAC-BLAKE2. Tokens are sent to the client using cookies and should be
//! sent back to the server using a custom header.
//!
//! # Key generation
//!
//! Each CSRF token is signed using the HMAC-BLAKE2 authentication algorithm
//! to guarantee its authenticity. The key used to sign and verify the token
//! is a sequence of 64 bytes randomly generated using the ChaCha algorithm.
//!
//! From an existing key you can derive other keys using the method `derive`,
//! Argon2 algorithm is used to create the derived key. Each derived key is
//! identified by a tag (a string) and keys generated with the same tag are
//! equal.
//!
//! ```
//! let key = CsrfKey::generate();
//! let derived_key = key.derive("tag");
//! ```
//!
//! # Send CSRF token to client
//!
//! CSRF token is send as a cookie to the client using the middleware
//! [`SendCsrf`]. The token is send only if the server received a GET request
//! without a valid CSRF token and if the response is a success.
//!
//! The default name of the cookie is `csrftoken` and it can be customized
//! using the enviroment variable `CSRF_COOKIE_NAME`.
//!
//! # Verify CSRF token on server
//!
//! The CSRF token should be send to the server using a custom header, the
//! middleware [`VerifyCsrf`] can be used to check the presence and verify the
//! signature of the sent token.
//!
//! The default name of the header is `x-csrftoken` and it can be customized
//! using the environment variable `CSRF_HEADER_NAME`.

use std::fmt::Display;

use base64ct::{Base64Url, Encoding};
use hmac::Mac;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng;

#[cfg(not(target_arch = "wasm32"))]
#[doc(inline)]
pub use self::service::*;

#[cfg(not(target_arch = "wasm32"))]
mod service;

/// A typedef of the signature algorithm.
type Hmac = hmac::SimpleHmac<blake2::Blake2s256>;

struct DebugSha256<'a>(&'a [u8]);
impl<'a> std::fmt::Debug for DebugSha256<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::Digest;

        let Self(bytes) = self;

        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();

        f.write_fmt(format_args!("sha256:{:064x?}", hash))
    }
}

/// Private key used to sign and verify tokens.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct CsrfKey([u8; Self::BYTES]);

impl CsrfKey {
    /// The size of the key in bytes.
    const BYTES: usize = 64;

    /// Generate a new random key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::BYTES];
        rng::with_crypto_rng(|rng| rng.fill_bytes(&mut bytes));
        Self(bytes)
    }

    /// Derive a new key, keys with the same tag are equals.
    pub fn derive(&self, tag: &str) -> Self {
        let mut bytes = [0u8; Self::BYTES];
        argon2::Argon2::default()
            .hash_password_into(tag.as_bytes(), &self.0, &mut bytes)
            .expect("failed to generate derived CSRF key");
        Self(bytes)
    }

    /// Returns an object that implements [`Display`].
    ///
    /// [`Display`]: std::fmt::Display
    pub fn display(&self) -> impl Display + '_ {
        DisplayCsrfKey(self)
    }
}

impl std::fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CsrfKey")
            .field(&DebugSha256(&self.0))
            .finish()
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

        const ENCODED_BYTES: usize = (CsrfKey::BYTES * 4 / 3 + 3) & !3;
        let mut buffer = [0u8; ENCODED_BYTES];
        let encoded_key = Base64Url::encode(bytes, &mut buffer).expect("failed to encode CSRF key");

        f.write_str(encoded_key)
    }
}

impl std::str::FromStr for CsrfKey {
    type Err = InvalidCsrfKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::BYTES];
        let len = Base64Url::decode(s, &mut bytes)
            .map_err(|err| {
                tracing::error!("Failed to parse CsrfKey: {err}");
                InvalidCsrfKey
            })?
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
pub struct CsrfToken([u8; Self::BYTES]);

impl CsrfToken {
    /// The number of random bytes.
    const RANDOM_BYTES: usize = 32;
    /// The size of the signature in bytes.
    const SIGNATURE_BYTES: usize = 32;
    /// The size of the token in bytes.
    const BYTES: usize = Self::RANDOM_BYTES + Self::SIGNATURE_BYTES;

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

impl std::fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CsrfToken")
            .field(&DebugSha256(&self.0))
            .finish()
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

        const ENCODED_BYTES: usize = (CsrfToken::BYTES * 4 / 3 + 3) & !3;
        let mut buffer = [0u8; ENCODED_BYTES];
        let encoded_key =
            Base64Url::encode(bytes, &mut buffer).expect("failed to encode CSRF token");

        f.write_str(encoded_key)
    }
}

impl std::str::FromStr for CsrfToken {
    type Err = InvalidCsrfToken;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; Self::BYTES];
        let len = Base64Url::decode(s, &mut bytes)
            .map_err(|err| {
                tracing::error!("Failed to parse CsrfToken: {err}");
                InvalidCsrfToken
            })?
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
        let key = CsrfKey::generate();
        let signup_key = key.derive("signup");
        let token = CsrfToken::generate(&signup_key);

        let new_signup_key = key.derive("signup");
        assert_ok!(token.verify(&new_signup_key));

        let signin_key = key.derive("signin");
        assert_err!(token.verify(&signin_key));
    }
}
