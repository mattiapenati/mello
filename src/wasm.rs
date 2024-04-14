use std::str::FromStr;

use lol_alloc::{FreeListAllocator, LockedAllocator};
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

/// Private key used to sign and verify tokens.
#[wasm_bindgen]
pub struct CsrfKey(crate::csrf::CsrfKey);

#[wasm_bindgen]
impl CsrfKey {
    /// Generate a new random key.
    pub fn generate() -> CsrfKey {
        Self(crate::csrf::CsrfKey::generate())
    }

    /// Derive a new key, keys with the same tag are equals.
    pub fn derive(&self, tag: &str) -> CsrfKey {
        Self(self.0.derive(tag))
    }

    /// Returns a string representing this object.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.display().to_string()
    }

    /// Parses a string containing a CSRF key.
    #[wasm_bindgen(js_name = parseFromString)]
    pub fn parse_from_string(s: &str) -> Result<CsrfKey, JsError> {
        crate::csrf::CsrfKey::from_str(s)
            .map(Self)
            .map_err(JsError::from)
    }
}

/// CSRF signed token.
#[wasm_bindgen]
pub struct CsrfToken(crate::csrf::CsrfToken);

#[wasm_bindgen]
impl CsrfToken {
    /// Generate a new CSRF random token, signed with the given key.
    pub fn generate(key: &CsrfKey) -> CsrfToken {
        Self(crate::csrf::CsrfToken::generate(&key.0))
    }

    /// Verify the CSRF token with the given key.
    pub fn verify(&self, key: &CsrfKey) -> Result<(), JsError> {
        self.0.verify(&key.0).map_err(JsError::from)
    }

    /// Returns a string representing this object.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.display().to_string()
    }

    /// Parses a string containing a CSRF token.
    #[wasm_bindgen(js_name = parseFromString)]
    pub fn parse_from_string(s: &str) -> Result<CsrfToken, JsError> {
        crate::csrf::CsrfToken::from_str(s)
            .map(Self)
            .map_err(JsError::from)
    }
}
