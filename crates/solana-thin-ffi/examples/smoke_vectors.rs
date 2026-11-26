//! Writes what the foreign-language smoke tests feed the binding: the
//! mainnet block of the Rust tests as plain files, for callers that have no
//! JSON parser and no prover.
//!
//! ```text
//! cargo run -p solana-thin-ffi --example smoke_vectors -- <directory>
//! ```
//!
//! The directory gets `set.bin` (the validator set), `proof.bin` (the
//! block's first transaction), `memo-proof.bin` (its first transaction with
//! a memo) and `expected.txt`, one `name=value` per line with bytes in hex.

#[path = "../tests/common/mod.rs"]
mod common;

use std::fs;
use std::path::PathBuf;

fn main() {
    let Some(directory) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: smoke_vectors <directory>");
        std::process::exit(2);
    };
    let v = common::vector();
    let write = |name: &str, contents: &[u8]| {
        let path = directory.join(name);
        fs::write(&path, contents).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    };
    fs::create_dir_all(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
    write("set.bin", &v.set);
    write("proof.bin", &v.proof);
    write("memo-proof.bin", &v.memo_proof);

    let memos: Vec<String> = v.memos.iter().map(hex::encode).collect();
    let expected = [
        ("shred_version", v.shred_version.to_string()),
        ("epoch", v.epoch.to_string()),
        ("slot", v.slot.to_string()),
        ("set_hash", hex::encode(&v.set_hash)),
        ("block_id", hex::encode(&v.block_id)),
        ("signature", hex::encode(&v.signature)),
        ("memo_signature", hex::encode(&v.memo_signature)),
        ("memos", memos.join(",")),
    ];
    let lines: String = expected
        .iter()
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect();
    write("expected.txt", lines.as_bytes());
}
