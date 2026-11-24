//! Agave-linked tooling for solana-thin.
//!
//! The vector generator lives in `main.rs` and does not use this library.
//! The library exists for the differential harness the `diff-fuzz` binary
//! drives: [`oracle`] is Agave's verdict on a slot's shreds, [`harness`]
//! holds a case and the properties checked on it, [`corpus`] the named cases
//! and the generators.

pub mod corpus;
pub mod harness;
pub mod oracle;
