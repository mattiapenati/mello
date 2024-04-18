//! Debug related utilities

use sha2::{Digest, Sha256};

/// Display thas SHA256 of a slice.
pub(crate) struct DebugSha256<'a>(pub &'a [u8]);

impl<'a> std::fmt::Debug for DebugSha256<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(bytes) = self;

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();

        f.write_fmt(format_args!("sha256|{:064x?}", hash))
    }
}
