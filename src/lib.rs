#[doc(inline)]
pub use self::master_key::{InvalidMasterKey, MasterKey};

pub mod csrf;
mod debug;
mod master_key;
pub mod rng;

#[cfg(not(target_arch = "wasm32"))]
pub mod kvstorage;

#[cfg(not(target_arch = "wasm32"))]
pub mod otel;

#[cfg(not(target_arch = "wasm32"))]
pub mod proxy;

#[cfg(not(target_arch = "wasm32"))]
pub mod ticket;

#[cfg(not(target_arch = "wasm32"))]
pub mod time;

#[cfg(not(target_arch = "wasm32"))]
pub mod trace;

#[cfg(target_arch = "wasm32")]
mod wasm;
