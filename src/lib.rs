#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod csrf;

#[cfg(not(target_arch = "wasm32"))]
pub mod kvstorage;

#[cfg(not(target_arch = "wasm32"))]
pub mod otel;

#[cfg(not(target_arch = "wasm32"))]
pub mod proxy;

pub mod rng;

#[cfg(not(target_arch = "wasm32"))]
pub mod trace;

pub mod rand;

#[cfg(target_arch = "wasm32")]
mod wasm;
