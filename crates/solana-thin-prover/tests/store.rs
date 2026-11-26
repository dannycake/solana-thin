//! The store directory: what goes in comes back, the cap holds, the oldest
//! blocks go first and their proofs stay.

mod common;

use common::*;
use solana_thin::BlockRef;
use solana_thin_prover::store::Store;
use solana_thin_prover::Anchor;
use std::fs;
use std::time::Duration;

fn anchor(chain: &Chain, slot: u64) -> Anchor {
    Anchor {
        certificate: chain.certificate(slot),
        links: Vec::new(),
    }
}

fn put(store: &Store, chain: &Chain, slot: u64) {
    let built = &chain.blocks[&slot];
    store
        .put_block(&built.block, &anchor(chain, slot), &built.payloads)
        .unwrap();
}

/// What one block of the test chain takes on disk.
fn block_size(chain: &Chain) -> u64 {
    let dir = directory("store-size");
    let store = Store::open(&dir, u64::MAX).unwrap();
    put(&store, chain, 100);
    store.usage().block_bytes
}

#[test]
fn what_is_put_comes_back() {
    let chain = Chain::linear(100..103);
    let dir = directory("store-round-trip");
    let store = Store::open(&dir, 64 << 20).unwrap();
    put(&store, &chain, 101);
    let stored = store.block(101).unwrap();
    assert_eq!(stored.block, chain.block(101));
    assert_eq!(stored.anchor, anchor(&chain, 101));
    assert_eq!(stored.shreds, chain.blocks[&101].payloads);
    assert_eq!(store.block(100), None);

    let signature = chain.signature(101, 0);
    assert_eq!(store.proof(&signature), None);
    store.put_proof(&signature, b"proof bytes").unwrap();
    assert_eq!(store.proof(&signature), Some(b"proof bytes".to_vec()));

    assert_eq!(store.certificate(101), None);
    store.put_certificate(&chain.certificate(101)).unwrap();
    assert_eq!(store.certificate(101), Some(chain.certificate(101)));

    let usage = store.usage();
    assert_eq!((usage.blocks, usage.kept), (1, 2));
    assert_eq!(usage.cap, 64 << 20);

    // A second process on the same directory finds all of it.
    let again = Store::open(&dir, 64 << 20).unwrap();
    assert_eq!(again.usage(), usage);
    assert_eq!(again.block(101), Some(stored));
    assert_eq!(again.certificate(101), Some(chain.certificate(101)));
}

#[test]
fn the_oldest_blocks_go_first_and_their_proofs_stay() {
    let chain = Chain::linear(100..106);
    let size = block_size(&chain);
    let dir = directory("store-eviction");
    // Room for three blocks and a little more.
    let store = Store::open(&dir, 3 * size + size / 2).unwrap();
    for slot in 100..106 {
        put(&store, &chain, slot);
        store
            .put_proof(&chain.signature(slot, 0), &[slot as u8; 500])
            .unwrap();
        assert!(store.usage().block_bytes + store.usage().kept_bytes <= 3 * size + size / 2);
    }
    for slot in 100..103 {
        assert_eq!(store.block(slot), None, "slot {slot}");
    }
    for slot in 103..106 {
        assert!(store.block(slot).is_some(), "slot {slot}");
    }
    // Every proof that was built is still served.
    for slot in 100..106 {
        assert_eq!(
            store.proof(&chain.signature(slot, 0)),
            Some(vec![slot as u8; 500])
        );
    }
    assert_eq!(store.usage().blocks, 3);
    assert_eq!(store.usage().kept, 6);
    assert_eq!(fs::read_dir(dir.join("blocks")).unwrap().count(), 3);
}

#[test]
fn proofs_take_at_most_half_the_cap() {
    let chain = Chain::linear(100..102);
    let dir = directory("store-proofs");
    let store = Store::open(&dir, 10_000).unwrap();
    let signature = |n: u8| [n; 64];
    for n in 0..8 {
        store.put_proof(&signature(n), &[n; 1_000]).unwrap();
    }
    // Five thousand bytes of proofs: the five newest.
    assert_eq!(store.usage().kept_bytes, 5_000);
    for n in 0..3 {
        assert_eq!(store.proof(&signature(n)), None);
    }
    for n in 3..8 {
        assert_eq!(store.proof(&signature(n)), Some(vec![n; 1_000]));
    }
    // A block larger than the cap is not kept at all, and costs no proof.
    put(&store, &chain, 100);
    assert_eq!(store.block(100), None);
    assert_eq!(store.usage().blocks, 0);
    assert_eq!(store.usage().kept, 5);
}

#[test]
fn writing_something_again_makes_it_the_newest() {
    let dir = directory("store-rewrite");
    let store = Store::open(&dir, 6_000).unwrap();
    for n in 0..3u8 {
        store.put_proof(&[n; 64], &[n; 1_000]).unwrap();
    }
    store.put_proof(&[0; 64], &[9; 1_000]).unwrap();
    assert_eq!(store.usage().kept_bytes, 3_000);
    store.put_proof(&[3; 64], &[3; 1_000]).unwrap();
    // The cap is 3,000 for proofs: the oldest is now the second one written.
    assert_eq!(store.proof(&[1; 64]), None);
    assert_eq!(store.proof(&[0; 64]), Some(vec![9; 1_000]));
}

#[test]
fn a_smaller_cap_on_reopening_evicts_by_age() {
    let chain = Chain::linear(100..104);
    let size = block_size(&chain);
    let dir = directory("store-reopen");
    let store = Store::open(&dir, 64 << 20).unwrap();
    for slot in 100..104 {
        put(&store, &chain, slot);
        // File times are what orders them after a restart.
        std::thread::sleep(Duration::from_millis(15));
    }
    drop(store);
    fs::write(dir.join("blocks").join("77.tmp"), b"half a write").unwrap();
    let store = Store::open(&dir, 2 * size).unwrap();
    assert_eq!(store.usage().blocks, 2);
    assert!(store.block(100).is_none() && store.block(101).is_none());
    assert!(store.block(102).is_some() && store.block(103).is_some());
    assert!(!dir.join("blocks").join("77.tmp").exists());
}

#[test]
fn a_damaged_file_reads_as_nothing() {
    let chain = Chain::linear(100..103);
    let dir = directory("store-damage");
    let store = Store::open(&dir, 64 << 20).unwrap();
    put(&store, &chain, 101);
    store.put_certificate(&chain.certificate(101)).unwrap();
    let path = dir.join("blocks").join("101.block");
    let good = fs::read(&path).unwrap();

    for damaged in [
        good[..good.len() - 1].to_vec(),
        good[..40].to_vec(),
        [&good[..], &[0u8]].concat(),
        b"something else entirely".to_vec(),
        Vec::new(),
    ] {
        fs::write(&path, damaged).unwrap();
        assert_eq!(store.block(101), None);
    }
    // A block filed under another slot's name.
    fs::write(dir.join("blocks").join("102.block"), &good).unwrap();
    assert_eq!(store.block(102), None);
    // A certificate filed under another slot's name, and a truncated one.
    let certificate = fs::read(dir.join("certs").join("101.cert")).unwrap();
    fs::write(dir.join("certs").join("100.cert"), &certificate).unwrap();
    assert_eq!(store.certificate(100), None);
    fs::write(dir.join("certs").join("101.cert"), &certificate[..50]).unwrap();
    assert_eq!(store.certificate(101), None);

    fs::write(&path, &good).unwrap();
    assert!(store.block(101).is_some());
    store.drop_block(101);
    assert_eq!(store.block(101), None);
    assert_eq!(store.usage().blocks, 0);
}

#[test]
fn a_shred_of_the_wrong_size_is_not_stored() {
    let chain = Chain::linear(100..101);
    let dir = directory("store-bad-shred");
    let store = Store::open(&dir, 64 << 20).unwrap();
    let block = BlockRef {
        slot: 100,
        id: [1; 32],
    };
    assert!(store
        .put_block(&block, &anchor(&chain, 100), &[vec![0; 1_202]])
        .is_err());
    assert_eq!(store.usage().blocks, 0);
}
