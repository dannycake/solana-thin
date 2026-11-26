//! What the fuzz targets share: the fixed world proofs are checked against, the starting inputs
//! `seed_corpus` writes, a way to parse one transaction from the front of a buffer through the
//! crate's public API, the comparison of a parsed transaction with what a validator's parser
//! read, and counters for differences that are allowed but worth seeing.

use solana_thin::block::{self, TxPosition};
use solana_thin::certificate::{encode_bitmap, BlockRef};
use solana_thin::testkit::{
    demo_world, entry_batch, footer_component, header_component, legacy_transaction, signature_for,
    simple_block, update_parent_component, v0_transaction, v1_transaction, TestValidators,
};
use solana_thin::transaction::Transaction;
use solana_thin::{prover, ClusterParams, ThinClient};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

/// The shred version `demo_world` signs for.
pub const SHRED_VERSION: u16 = 50093;

/// The validators `demo_world` uses. The testkit derives their keys from fixed seeds, so this is
/// the same set every time, and blocks signed here verify against the set `demo_world` returns.
fn validators() -> TestValidators {
    TestValidators::new(12, |i| 1_000 + i as u64)
}

/// A client that trusts `demo_world`'s validators for epoch 0, built once per process.
pub fn client() -> &'static ThinClient {
    static CLIENT: OnceLock<ThinClient> = OnceLock::new();
    CLIENT.get_or_init(|| {
        let world = demo_world();
        let mut client = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));
        client
            .trust_validator_set(0, world.set, &world.set_hash)
            .expect("the demo set hashes to its own hash");
        client
    })
}

/// Valid proofs for [`client`]: the demo proof, then blocks with several entry batches and all
/// three transaction encodings, a slow certificate, a proof without a footer, and one whose
/// certificate is for a child of the transaction's block.
pub fn seed_proofs() -> Vec<(&'static str, Vec<u8>)> {
    let validators = validators();
    assert_eq!(
        validators.set().hash(),
        demo_world().set_hash,
        "the testkit's demo validators changed: update validators() to match"
    );
    let fast = validators.ranks_reaching(8_000);
    let slow = validators.ranks_reaching(6_000);
    let genesis = BlockRef {
        slot: 99,
        id: [9; 32],
    };
    // Three batches. The second has two entries and a transaction too long for one shred, so
    // its proof opens a run of shreds; the third is found by walking past the first two.
    let long_memo = vec![b'm'; 1500];
    let batches = vec![
        vec![vec![
            legacy_transaction(10, &[b"first"]),
            v0_transaction(11, &[b"a", b"bc"]),
        ]],
        vec![
            vec![v1_transaction(12, &[b"xyz"])],
            vec![
                legacy_transaction(13, &[&long_memo]),
                v1_transaction(14, &[b"one", b"two"]),
            ],
        ],
        vec![vec![], vec![v0_transaction(15, &[b"last"])]],
    ];
    let parent = simple_block(100, genesis, SHRED_VERSION, &batches, None);
    let fast_cert = validators.fast_cert(parent.block(), &fast, SHRED_VERSION);
    let slow_cert = validators.slow_cert(parent.block(), &slow, &slow, SHRED_VERSION);
    // The child carries, in its footer, the certificate that finalized its parent.
    let child = simple_block(
        101,
        parent.block(),
        SHRED_VERSION,
        &[vec![vec![legacy_transaction(20, &[b"child"])]]],
        Some(&fast_cert),
    );
    let child_cert = validators.fast_cert(child.block(), &fast, SHRED_VERSION);

    let prove = |cert: &solana_thin::FinalityCert, chain: &[&prover::BlockData], seed, footer| {
        prover::prove(cert.clone(), chain, &signature_for(seed), footer)
            .expect("the transaction is in the block")
            .to_bytes()
            .expect("a small proof encodes")
    };
    vec![
        ("demo", demo_world().proof_bytes),
        ("first-batch-v0", prove(&fast_cert, &[&parent], 11, true)),
        ("second-batch-v1", prove(&fast_cert, &[&parent], 12, true)),
        ("second-entry-long", prove(&fast_cert, &[&parent], 13, true)),
        ("after-long-v1", prove(&fast_cert, &[&parent], 14, false)),
        ("third-batch-slow", prove(&slow_cert, &[&parent], 15, true)),
        ("no-footer", prove(&slow_cert, &[&parent], 10, false)),
        ("child-footer-cert", prove(&child_cert, &[&child], 20, true)),
        ("ancestor", prove(&child_cert, &[&child, &parent], 13, true)),
    ]
}

/// Transactions in each encoding the testkit writes.
pub fn seed_transactions() -> Vec<(String, Vec<u8>)> {
    let long = vec![7u8; 300];
    let mut out = Vec::new();
    for (seed, memos) in [
        (1u64, vec![&b"hello"[..]]),
        (2, vec![&b"a"[..], &b"bc"[..]]),
        (3, vec![]),
        (4, vec![&long[..]]),
    ] {
        out.push((format!("legacy-{seed}"), legacy_transaction(seed, &memos)));
        out.push((format!("v0-{seed}"), v0_transaction(seed, &memos)));
        out.push((format!("v1-{seed}"), v1_transaction(seed, &memos)));
    }
    out
}

/// Appends `count` items of `width` bytes, item `i` being the byte `i ^ salt` repeated: the
/// signatures and account keys of a [`wide_transaction`], each different from the next so that
/// a parser reading one in the place of another is caught.
fn wide_filler(out: &mut Vec<u8>, count: u8, width: usize, salt: u8) {
    for i in 0..count {
        out.extend(std::iter::repeat_n(i ^ salt, width));
    }
}

/// The encoding a [`wide_transaction`] is written in.
#[derive(Clone, Copy, PartialEq)]
enum Wide {
    Legacy,
    V0,
    V1,
}

/// A transaction that sanitizes, with `signers` signatures, `keys` account keys and
/// `instructions` instructions of one data byte each to the program at key 1. Written here and
/// not by the testkit, whose transactions have one signer and two keys.
fn wide_transaction(encoding: Wide, signers: u8, keys: u8, instructions: u8) -> Vec<u8> {
    assert!(signers >= 1 && keys >= 2 && signers <= keys);
    let mut out = Vec::new();
    if encoding == Wide::V1 {
        out.extend_from_slice(&[0x81, signers, 0, 0]);
        out.extend_from_slice(&0u32.to_le_bytes()); // no configuration values
        out.extend_from_slice(&[0xbb; 32]);
        out.extend_from_slice(&[instructions, keys]);
        wide_filler(&mut out, keys, 32, 0);
        for _ in 0..instructions {
            out.extend_from_slice(&[1, 0, 1, 0]); // program, no accounts, one byte of data
        }
        out.extend(std::iter::repeat_n(0x2a, usize::from(instructions)));
        wide_filler(&mut out, signers, 64, 0x55);
        return out;
    }
    // Counts here are compact-u16; every one this writes fits its first byte.
    assert!(signers < 0x80 && keys < 0x80 && instructions < 0x80);
    out.push(signers);
    wide_filler(&mut out, signers, 64, 0x55);
    if encoding == Wide::V0 {
        out.push(0x80);
    }
    out.extend_from_slice(&[signers, 0, 0, keys]);
    wide_filler(&mut out, keys, 32, 0);
    out.extend_from_slice(&[0xbb; 32]);
    out.push(instructions);
    for _ in 0..instructions {
        out.extend_from_slice(&[1, 0, 1, 0x2a]);
    }
    if encoding == Wide::V0 {
        out.push(0); // no address table lookups
    }
    out
}

/// Transactions past the limits Agave 4.4.1 holds one to and within what the parsers of 4.5
/// read: more than 12 signatures, and v1 messages with more than 64 account keys or
/// instructions, each just past the old limit and at the most its count can say.
pub fn seed_transactions_45() -> Vec<(String, Vec<u8>)> {
    [
        ("legacy-13-signatures", Wide::Legacy, 13, 13, 1),
        ("legacy-127-signatures", Wide::Legacy, 127, 127, 1),
        ("v0-13-signatures", Wide::V0, 13, 13, 1),
        ("v1-13-signatures", Wide::V1, 13, 13, 1),
        ("v1-127-signatures", Wide::V1, 127, 127, 1),
        ("v1-65-keys", Wide::V1, 1, 65, 1),
        // The most signatures and keys replay runs, where the parsers read on to 255.
        ("v1-12-signatures-96-keys", Wide::V1, 12, 96, 1),
        ("v1-255-keys", Wide::V1, 1, 255, 1),
        ("v1-65-instructions", Wide::V1, 1, 2, 65),
        ("v1-255-instructions", Wide::V1, 1, 2, 255),
        ("v1-255-of-each", Wide::V1, 255, 255, 255),
    ]
    .into_iter()
    .map(|(name, encoding, signers, keys, instructions)| {
        (
            name.to_string(),
            wide_transaction(encoding, signers, keys, instructions),
        )
    })
    .collect()
}

/// Signer bitmaps as the `bitmap` target reads them: validator count (`u16`), then the bitmap.
pub fn seed_bitmaps() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let cases: [(u16, &[usize]); 6] = [
        (12, &[0, 1, 2, 3, 4, 5, 6, 7, 8]),
        (8, &[7]),
        (9, &[8]),
        (672, &[0, 3, 9, 16, 671]),
        (10, &[]),
        (4, &[0, 5]),
    ];
    for (i, (count, ranks)) in cases.iter().enumerate() {
        let mut bytes = count.to_le_bytes().to_vec();
        bytes.extend_from_slice(&encode_bitmap(ranks));
        out.push((format!("base2-{i}"), bytes));
    }
    // The two-vector form: version 1, five symbols, one byte.
    out.push(("base3".into(), vec![8, 0, 1, 5, 0, 0x2d]));
    out
}

/// Block components as the `marker` target reads them: entry index, transaction index, then
/// the component's bytes.
pub fn seed_components() -> Vec<(String, Vec<u8>)> {
    let validators = validators();
    let block = BlockRef {
        slot: 41,
        id: [3; 32],
    };
    let fast = validators.fast_cert(block, &validators.ranks_reaching(8_000), SHRED_VERSION);
    let ranks = validators.ranks_reaching(6_000);
    let slow = validators.slow_cert(block, &ranks, &ranks, SHRED_VERSION);
    let batch = entry_batch(&[
        vec![legacy_transaction(1, &[b"x"]), v0_transaction(2, &[b"y"])],
        vec![],
        vec![v1_transaction(3, &[b"z"])],
    ]);
    let mut out = Vec::new();
    for (name, position, component) in [
        ("header", (0u8, 0u8), header_component(&block)),
        ("update-parent", (0, 0), update_parent_component(&block)),
        (
            "footer",
            (0, 0),
            footer_component([5; 32], 1, b"agent", None),
        ),
        (
            "footer-fast",
            (0, 0),
            footer_component([5; 32], 2, b"", Some(&fast)),
        ),
        (
            "footer-slow",
            (0, 0),
            footer_component([5; 32], 3, b"agent", Some(&slow)),
        ),
        ("tick", (0, 0), entry_batch(&[vec![]])),
        ("batch-first", (0, 0), batch.clone()),
        ("batch-second", (0, 1), batch.clone()),
        ("batch-last", (2, 0), batch),
    ] {
        let mut bytes = vec![position.0, position.1];
        bytes.extend_from_slice(&component);
        out.push((name.to_string(), bytes));
    }
    out
}

/// Encoded validator sets.
pub fn seed_validator_sets() -> Vec<(String, Vec<u8>)> {
    vec![
        ("demo".into(), validators().set().to_bytes()),
        (
            "three".into(),
            TestValidators::with_seed(7, 3, |_| 5).set().to_bytes(),
        ),
    ]
}

/// Parses one transaction from the front of `bytes`, the way the verifier meets one inside a
/// block, and returns it with the number of bytes it occupied.
///
/// `Transaction::read`, which does this, is private. The public way to reach it without
/// requiring the buffer to end where the transaction does is `block::transaction_at` on an
/// entry batch, so the bytes are wrapped in a batch of one entry holding one transaction. The
/// length is recomputed from the parts: `Transaction` does not report it.
pub fn parse_prefix(bytes: &[u8]) -> Option<(Transaction, usize)> {
    let mut batch = Vec::with_capacity(56 + bytes.len());
    batch.extend_from_slice(&1u64.to_le_bytes()); // one entry
    batch.extend_from_slice(&[0u8; 40]); // num_hashes and hash, not read
    batch.extend_from_slice(&1u64.to_le_bytes()); // one transaction
    batch.extend_from_slice(bytes);
    let position = TxPosition {
        entry: 0,
        transaction: 0,
    };
    let tx = block::transaction_at(&batch, position).ok()?;
    // Legacy and v0 put a one-byte count in front of the signatures; v1 puts the signatures,
    // uncounted, after the message.
    let count_byte = usize::from(bytes[0] & 0x80 == 0);
    let len = count_byte + 64 * tx.signatures.len() + tx.message.len();
    // The two public parsers must agree: what the walk consumed is a whole transaction.
    assert_eq!(
        Transaction::parse(&bytes[..len]).as_ref(),
        Ok(&tx),
        "transaction_at and Transaction::parse disagree on the same bytes"
    );
    Some((tx, len))
}

/// Fails unless `tx` holds these signatures, static account keys, blockhash and message bytes:
/// the parts each of the validator's parsers hands out, whichever release it is from.
pub fn assert_same_parts(
    tx: &Transaction,
    signatures: &[impl AsRef<[u8]>],
    account_keys: &[impl AsRef<[u8]>],
    recent_blockhash: &[u8],
    message: &[u8],
) {
    assert_eq!(tx.signatures.len(), signatures.len());
    for (ours, theirs) in tx.signatures.iter().zip(signatures) {
        assert_eq!(&ours[..], theirs.as_ref());
    }
    assert_eq!(tx.account_keys.len(), account_keys.len());
    for (ours, theirs) in tx.account_keys.iter().zip(account_keys) {
        assert_eq!(&ours[..], theirs.as_ref());
    }
    assert_eq!(&tx.recent_blockhash[..], recent_blockhash);
    assert_eq!(tx.message, message);
}

/// Fails unless `tx` holds these instructions, each given as its program index, its accounts
/// and its data. Tuples, because each release of the view has an instruction type of its own.
pub fn assert_same_instructions<'a>(
    tx: &Transaction,
    instructions: impl ExactSizeIterator<Item = (u8, &'a [u8], &'a [u8])>,
) {
    assert_eq!(tx.instructions.len(), instructions.len());
    for (ours, (program_id_index, accounts, data)) in tx.instructions.iter().zip(instructions) {
        assert_eq!(ours.program_id_index, program_id_index);
        assert_eq!(ours.accounts, accounts);
        assert_eq!(ours.data, data);
    }
}

/// Counts something a target sees but does not fail on. Printed when the run ends.
///
/// To look at one of the counted cases, name its label in `FUZZ_FAIL_ON` (comma separated):
/// the first input that would be counted there fails instead, and libFuzzer saves it. For
/// example `FUZZ_FAIL_ON=ours_only cargo +nightly fuzz run -O -a transaction_view`.
pub struct Counter {
    label: &'static str,
    count: AtomicU64,
    fatal: AtomicBool,
}

impl Counter {
    /// A counter printed as `label=count`.
    pub const fn new(label: &'static str) -> Self {
        Self {
            label,
            count: AtomicU64::new(0),
            fatal: AtomicBool::new(false),
        }
    }

    /// Adds one.
    pub fn bump(&self) {
        assert!(
            !self.fatal.load(Ordering::Relaxed),
            "{}: an allowed case, made a failure by FUZZ_FAIL_ON",
            self.label
        );
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

static TALLY: OnceLock<(&'static str, &'static [&'static Counter])> = OnceLock::new();

extern "C" {
    fn atexit(callback: extern "C" fn()) -> i32;
}

extern "C" fn print_tally() {
    if let Some((target, counters)) = TALLY.get() {
        let counts: Vec<String> = counters
            .iter()
            .map(|c| format!("{}={}", c.label, c.count.load(Ordering::Relaxed)))
            .collect();
        eprintln!("tally {target}: {}", counts.join(" "));
    }
}

/// Prints `counters` as one `tally <target>: ...` line when the process exits normally, and
/// applies `FUZZ_FAIL_ON` (see [`Counter`]). libFuzzer leaves through `exit` when its time is
/// up, so the line closes every clean run. Cheap to call on every input: only the first call
/// does anything.
pub fn tally_at_exit(target: &'static str, counters: &'static [&'static Counter]) {
    if TALLY.set((target, counters)).is_ok() {
        let fail_on = std::env::var("FUZZ_FAIL_ON").unwrap_or_default();
        for label in fail_on.split(',').filter(|label| !label.is_empty()) {
            let counter = counters
                .iter()
                .find(|c| c.label == label)
                .unwrap_or_else(|| {
                    panic!("FUZZ_FAIL_ON names {label}, which {target} does not count")
                });
            counter.fatal.store(true, Ordering::Relaxed);
        }
        // SAFETY: `atexit` is the C library's; the callback is a plain function that only
        // reads statics.
        unsafe {
            atexit(print_tally);
        }
    }
}

/// Decodes lowercase or uppercase hex, or nothing if it is not hex.
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}
