//! Agave-linked tooling for solana-thin.
//!
//! The vector generator lives in `main.rs` and does not use this library.
//! The library exists for [`oracle`], which the `diff-fuzz` binary drives.

pub mod oracle;
