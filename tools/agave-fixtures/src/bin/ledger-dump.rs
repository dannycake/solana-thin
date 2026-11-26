//! Dumps the data shreds of a range of slots from an Agave ledger directory.
//!
//! This is the bridge between a real validator and `solana_thin::prover`: the
//! prover wants a slot's data shreds exactly as the node stores them, and
//! nothing in standard RPC serves those.
//!
//! ```text
//! ledger-dump <ledger dir> <first slot> <last slot> <out.jsonl>
//! ```
//!
//! One JSON object per line:
//!
//! ```text
//! {"slot":12,"parent_slot":11,"block_id":"<hex or null>","shreds":["<hex>",...]}
//! ```
//!
//! `block_id` is the double-Merkle root as Agave's blockstore computed it, so
//! the reader can compare it with the id it derives from the shreds. The
//! ledger is opened read-only, so this can run next to a live validator.

use {
    serde_json::json,
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_meta::BlockLocation,
        blockstore_options::{AccessType, BlockstoreOptions},
    },
    std::{
        env,
        fs::File,
        io::{BufWriter, Write},
        path::Path,
        process::exit,
    },
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: ledger-dump <ledger dir> <first slot> <last slot> <out.jsonl>");
        exit(2);
    }
    let first: u64 = args[2].parse().expect("first slot");
    let last: u64 = args[3].parse().expect("last slot");
    let blockstore = Blockstore::open_with_options(
        Path::new(&args[1]),
        BlockstoreOptions {
            access_type: AccessType::ReadOnly,
            ..BlockstoreOptions::default()
        },
    )
    .expect("open the ledger");
    let mut out = BufWriter::new(File::create(&args[4]).expect("create the output file"));

    let (mut slots, mut shreds_written) = (0u64, 0usize);
    for slot in first..=last {
        let Some(meta) = blockstore.meta(slot).expect("read slot meta") else {
            continue;
        };
        if !meta.is_full() {
            continue;
        }
        let shreds = blockstore
            .get_data_shreds_for_slot(slot, 0)
            .expect("read data shreds");
        let block_id = blockstore
            .get_double_merkle_root(slot, BlockLocation::Original)
            .expect("read the block id")
            .map(hex::encode);
        let line = json!({
            "slot": slot,
            "parent_slot": meta.parent_slot,
            "block_id": block_id,
            "shreds": shreds.iter().map(|s| hex::encode(s.payload())).collect::<Vec<_>>(),
        });
        writeln!(out, "{line}").expect("write");
        slots += 1;
        shreds_written += shreds.len();
    }
    out.flush().expect("flush");
    eprintln!("{slots} full slots, {shreds_written} data shreds");
}
