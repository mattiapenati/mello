#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(target_arch = "wasm32")]
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

#[cfg(feature = "kvstorage")]
#[cfg_attr(docsrs, doc(cfg(feature = "kvstorage")))]
pub mod kvstorage;

pub mod csrf;

#[cfg(not(target_arch = "wasm32"))]
pub mod otel;

#[cfg(not(target_arch = "wasm32"))]
pub mod proxy;

pub mod rng;

#[cfg(not(target_arch = "wasm32"))]
pub mod trace;

pub mod rand;
