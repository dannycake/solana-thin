//! Rules from the check ledger (`docs/conformance.toml`) that had no test of
//! their own. Each is something a validator refuses and the verifier must
//! refuse too; the ledger row names the test.

mod common;

use common::*;
use solana_thin::block::{self, TxPosition};
use solana_thin::prover;
use solana_thin::shred::RawDataShred;
use solana_thin::testkit::*;
use solana_thin::transaction::Transaction;
use solana_thin::*;

/// A data shred is its first 1,203 bytes. Fewer is not a shred. More is the
/// same shred: a repair response appends a nonce, and a validator cuts the
/// packet to size before reading it (`from_payload` in Agave's
/// `ledger/src/shred/merkle.rs`).
#[test]
fn a_short_payload_is_not_a_shred_and_trailing_bytes_are_ignored() {
    let w = world();
    let payloads = BlockBuilder::new(2_000, w.blocks[2].block(), SHRED_VERSION)
        .header()
        .build();
    let shred = &payloads[0];
    assert_eq!(shred.len(), 1_203);
    let parsed = RawDataShred::parse(shred).unwrap();
    assert!(RawDataShred::parse(&shred[..1_202]).is_err());
    assert!(RawDataShred::parse(&[]).is_err());

    let mut with_nonce = shred.clone();
    with_nonce.extend_from_slice(&7u32.to_le_bytes());
    let longer = RawDataShred::parse(&with_nonce).unwrap();
    assert_eq!(longer.leaf_hash().unwrap(), parsed.leaf_hash().unwrap());
    assert_eq!(longer.shred, parsed.shred);
}

/// The shred version is inside what each shred hashes. The verifier does not
/// read it from the proof: it puts its own cluster's version there. So shreds
/// made on one cluster hash to a different block on another, even when the
/// certificate is one that other cluster's validators really signed.
#[test]
fn a_shred_from_another_cluster_does_not_open_this_block() {
    let w = world();
    let signature = signature_for(0);
    let proof = w.proof(0, &signature);
    assert!(w.client.verify_transaction(&proof).is_ok());

    let other_version = SHRED_VERSION + 1;
    let mut other = ThinClient::new(ClusterParams::mainnet(other_version));
    let set = w.validators.set();
    other
        .trust_validator_set(0, set.clone(), &set.hash())
        .unwrap();
    // The same validators sign the same block id on the other cluster.
    let cert = w.validators.fast_cert(
        w.blocks[0].block(),
        &w.validators.ranks_reaching(8_000),
        other_version,
    );
    assert!(other.verify_finality(&cert).is_ok());
    let replayed = prover::prove(cert, &[&w.blocks[0]], &signature, false).unwrap();
    assert_eq!(
        other.verify_transaction(&replayed),
        Err(Error::BlockIdMismatch)
    );
}

/// Markers carry three version or kind fields. A validator's parser refuses
/// any value it does not know, and so does this one.
#[test]
fn markers_with_unknown_versions_or_kinds_are_refused() {
    let parent = BlockRef {
        slot: 9,
        id: [4; 32],
    };
    let header = header_component(&parent);
    assert!(block::parse_marker(&header).is_ok());

    // Layout: 0u64, marker version u16, kind u8, length u16, then the body,
    // whose first byte is its own version.
    let with = |at: usize, value: u8| {
        let mut bytes = header.clone();
        bytes[at] = value;
        block::parse_marker(&bytes)
    };
    assert_eq!(with(8, 2), Err(Error::InvalidComponent("marker version")));
    assert_eq!(with(9, 1), Err(Error::InvalidComponent("marker version")));
    assert_eq!(with(10, 4), Err(Error::InvalidComponent("marker kind")));
    assert_eq!(with(10, 0xff), Err(Error::InvalidComponent("marker kind")));
    assert_eq!(
        with(13, 2),
        Err(Error::InvalidComponent("parent marker version"))
    );
    // The first eight bytes are an entry count; non-zero means not a marker.
    assert_eq!(with(0, 1), Err(Error::InvalidComponent("not a marker")));

    let footer = footer_component([1; 32], 5, b"x", None);
    let mut bad = footer.clone();
    bad[13] = 2;
    assert_eq!(
        block::parse_marker(&bad),
        Err(Error::InvalidComponent("footer version"))
    );

    // And a marker is never walked as an entry batch.
    assert!(block::transaction_at(
        &header,
        TxPosition {
            entry: 0,
            transaction: 0
        }
    )
    .is_err());
}

/// A transaction names how many signatures it requires. Bytes whose
/// signature list disagrees with that, or that carry more signatures than
/// account keys, are not a transaction a validator would deserialize.
#[test]
fn a_transaction_with_more_signatures_than_keys_is_not_one() {
    let good = legacy_transaction(11, &[b"memo"]);
    assert!(Transaction::parse(&good).is_ok());
    let (signature, message) = (&good[1..65], &good[65..]);

    // Two keys in the message (payer and the Memo program), three signatures.
    let mut three = vec![3u8];
    for _ in 0..3 {
        three.extend_from_slice(signature);
    }
    let mut claimed = message.to_vec();
    claimed[0] = 3;
    three.extend_from_slice(&claimed);
    assert_eq!(
        Transaction::parse(&three),
        Err(Error::UnsupportedTransaction)
    );

    // One signature present, two required.
    let mut two_required = good.clone();
    two_required[65] = 2;
    assert_eq!(
        Transaction::parse(&two_required),
        Err(Error::UnsupportedTransaction)
    );

    // No signatures at all.
    let mut none = vec![0u8];
    none.extend_from_slice(message);
    assert!(Transaction::parse(&none).is_err());
}
