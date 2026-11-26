//! From a signature and a slot hint to a proof, end to end: certificates
//! found in footers, blocks fetched by id from validators on loopback, and
//! every result checked by a verifier that has only the sets and the shred
//! version. Every way of being refused is here too.

mod common;

use common::*;
use solana_thin::testkit::{
    entry_batch, footer_component, legacy_transaction, signature_for, update_parent_component,
    BlockBuilder, RawBlock,
};
use solana_thin::{Error, Limits, TxProof};
use solana_thin_prover::prove::{Prover, ProverConfig};
use solana_thin_prover::{Anchor, Refusal, Schedule, Store, Trust};
use std::sync::Arc;

/// Verifies `proof` as a client would and returns the slot of the block
/// the transaction is in, the slot of the certified block, and the number
/// of parent links between them.
fn verified(
    chain: &Chain,
    epochs: &[u64],
    proof: &[u8],
    signature: &[u8; 64],
) -> (u64, u64, usize) {
    let client = chain.client(epochs);
    let decoded = TxProof::from_bytes(proof, client.limits()).unwrap();
    let verified = client.verify_signature(&decoded, signature).unwrap();
    assert!(verified.footer.is_some());
    (
        verified.block.slot,
        verified.finalized_by.block.slot,
        decoded.ancestry.len(),
    )
}

#[test]
fn a_transaction_is_proven_from_a_block_fetched_by_its_certified_id() {
    let chain = Chain::linear(100..104);
    let peers = [
        FakePeer::start(1, &chain, Behavior::Honest),
        FakePeer::start(2, &chain, Behavior::Honest),
    ];
    let mut prover = prover("prove-honest", &chain, &[0], &[&peers[0], &peers[1]]);
    let signature = chain.signature(101, 1);
    let proof = prover.prove(&signature, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (101, 101, 0));

    // The certificate came from the next block's footer, read by slot; the
    // block itself was only ever asked for by id.
    let by_slot: usize = peers.iter().map(|p| p.seen_by_kind().0).sum();
    let by_id: usize = peers.iter().map(|p| p.seen_by_kind().1).sum();
    assert!(by_slot > 0 && by_slot < 128);
    assert!(by_id >= 2 + 4 + 128);

    // The block, the proof and the certificate are kept, and the same
    // question again asks nobody.
    let store = prover.store();
    assert_eq!(store.block(101).unwrap().block, chain.block(101));
    assert_eq!(store.proof(&signature), Some(proof.clone()));
    assert_eq!(store.certificate(101), Some(chain.certificate(101)));
    let sent = prover.fetcher().net_stats().requests;
    assert_eq!(prover.prove(&signature, 101).unwrap(), proof);
    // Nor does another transaction of the block now held.
    let other = chain.signature(101, 2);
    let proof = prover.prove(&other, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &other), (101, 101, 0));
    assert_eq!(prover.fetcher().net_stats().requests, sent);
}

#[test]
fn a_restart_serves_from_the_directory() {
    let chain = Chain::linear(100..104);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut first = prover("prove-restart", &chain, &[0], &[&peer]);
    let signature = chain.signature(101, 0);
    let proof = first.prove(&signature, 101).unwrap();
    let store = first.store();
    drop(first);

    // The same directory, and peers that no longer answer.
    peer.behave(Behavior::Silent);
    let mut second = Prover::new(
        chain.trust(&[0]),
        store,
        fetcher(&[&peer], quick()),
        searching(),
    );
    assert_eq!(second.prove(&signature, 101).unwrap(), proof);
    let other = chain.signature(101, 2);
    let proof = second.prove(&other, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &other), (101, 101, 0));
    assert_eq!(second.fetcher().net_stats().requests, 0);
}

#[test]
fn a_certificate_for_a_later_block_reaches_back_through_parent_links() {
    // Only the last footer carries a certificate, for the block before it.
    let mut chain = Chain::new(432_000, 99);
    for slot in 100..103 {
        chain.push(slot, None);
    }
    chain.push(103, Some(102));
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-ancestry", &chain, &[0], &[&peer]);

    let certified = prover.certify(100).unwrap();
    assert_eq!(certified.block, chain.block(100));
    assert_eq!(certified.found_in, Some(103));
    assert_eq!(certified.anchor.certificate, chain.certificate(102));
    assert_eq!(certified.anchor.links.len(), 2);

    let signature = chain.signature(100, 0);
    let proof = prover.prove(&signature, 100).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (100, 102, 2));
    // Only the block proven was fetched: each block above it cost one
    // request for its parent link.
    assert_eq!(prover.store().usage().blocks, 1);
    assert!(prover.store().block(101).is_none() && prover.store().block(102).is_none());
}

#[test]
fn a_chain_longer_than_allowed_is_refused() {
    let mut chain = Chain::new(432_000, 99);
    for slot in 100..103 {
        chain.push(slot, None);
    }
    chain.push(103, Some(102));
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let store = Arc::new(Store::open(&directory("prove-too-long"), 64 << 20).unwrap());
    let config = ProverConfig {
        max_ancestry: 1,
        ..searching()
    };
    let mut prover = Prover::new(chain.trust(&[0]), store, fetcher(&[&peer], quick()), config);
    assert_eq!(
        prover.prove(&chain.signature(100, 0), 100).unwrap_err(),
        Refusal::AncestryTooLong {
            slot: 100,
            certified: chain.block(102),
            limit: 1
        }
    );
    // One link is within the limit.
    assert!(prover.prove(&chain.signature(101, 0), 101).is_ok());
}

#[test]
fn a_skipped_slot_is_not_in_the_finalized_chain() {
    let chain = Chain::linear([100, 101, 103, 104]);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-skipped", &chain, &[0], &[&peer]);
    assert_eq!(
        prover.prove(&chain.signature(101, 0), 102).unwrap_err(),
        Refusal::NotFinalized {
            slot: 102,
            certified: chain.block(103),
            between: (103, 101),
        }
    );
    assert_eq!(prover.store().usage().blocks, 0);
    // Across the gap, the block before it is still reached.
    let signature = chain.signature(101, 0);
    let proof = prover.prove(&signature, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (101, 101, 0));
}

#[test]
fn a_wrong_hint_costs_time_and_proves_nothing() {
    let chain = Chain::linear(100..106);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-wrong-hint", &chain, &[0], &[&peer]);
    let signature = chain.signature(101, 0);
    assert_eq!(
        prover.prove(&signature, 103).unwrap_err(),
        Refusal::NotInBlock { slot: 103 }
    );
    // A slot the cluster never reached.
    assert_eq!(
        prover.prove(&signature, 5_000).unwrap_err(),
        Refusal::NoCertificate {
            slot: 5_000,
            searched_to: 5_006,
            rejected: vec![]
        }
    );
    // Neither left anything behind that answers for the signature, and the
    // right hint still works.
    assert_eq!(prover.store().proof(&signature), None);
    let proof = prover.prove(&signature, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (101, 101, 0));
    // A transaction that never landed, with a hint that names a real block.
    assert_eq!(
        prover.prove(&signature_for(999_999), 101).unwrap_err(),
        Refusal::NotInBlock { slot: 101 }
    );
}

#[test]
fn the_newest_block_has_no_certificate_yet() {
    let chain = Chain::linear(100..103);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-tip", &chain, &[0], &[&peer]);
    assert_eq!(
        prover.prove(&chain.signature(102, 0), 102).unwrap_err(),
        Refusal::NoCertificate {
            slot: 102,
            searched_to: 108,
            rejected: vec![]
        }
    );
}

#[test]
fn an_abandoned_block_served_by_slot_is_never_kept() {
    let chain = Chain::linear(100..104);
    // Another block for slot 101, on the same parent, that lost.
    let abandoned = build(101, chain.block(100), &[7_000, 7_001], None);
    assert_ne!(abandoned.block, chain.block(101));
    let peers = [
        FakePeer::start(1, &chain, Behavior::Honest),
        FakePeer::start(2, &chain, Behavior::Honest),
    ];
    for peer in &peers {
        peer.hold(&abandoned);
        peer.serve_by_slot(&abandoned);
    }
    let mut prover = prover("prove-abandoned", &chain, &[0], &[&peers[0], &peers[1]]);

    // Its transaction is in a block every peer serves for the slot, and
    // that is not the block the validators finalized.
    assert_eq!(
        prover.prove(&signature_for(7_000), 101).unwrap_err(),
        Refusal::NotInBlock { slot: 101 }
    );
    let held = prover.store().block(101).unwrap();
    assert_eq!(held.block, chain.block(101));
    assert_eq!(held.shreds, chain.blocks[&101].payloads);
    let signature = chain.signature(101, 0);
    let proof = prover.prove(&signature, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (101, 101, 0));
    // The abandoned block was never asked for by id.
    for peer in &peers {
        assert!(peer.seen().iter().all(|request| match request {
            solana_thin_prover::wire::Request::ParentAndFecSetCount { block }
            | solana_thin_prover::wire::Request::FecSetRoot { block, .. }
            | solana_thin_prover::wire::Request::WindowIndexForBlockId { block, .. } =>
                *block != abandoned.block,
            _ => true,
        }));
    }
}

#[test]
fn a_certificate_the_set_did_not_sign_is_skipped() {
    let mut chain = Chain::linear(100..102);
    // The footer of slot 102 carries a certificate for slot 101 signed by
    // one validator of five: a notarization at best.
    let validators = chain.validators(0);
    let weak = validators.fast_cert(chain.block(101), &[4], VERSION);
    chain.push_with(102, Some(&weak));
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-weak-certificate", &chain, &[0], &[&peer]);
    let signature = chain.signature(101, 0);
    let Refusal::NoCertificate {
        slot: 101,
        searched_to: 107,
        rejected,
    } = prover.prove(&signature, 101).unwrap_err()
    else {
        panic!("a weak certificate certifies nothing");
    };
    assert!(matches!(
        rejected[..],
        [(102, Error::InsufficientStake { .. })]
    ));
    assert_eq!(prover.store().usage().blocks, 0);
    assert_eq!(prover.store().certificate(101), None);

    // One block later a real certificate arrives, for slot 102, and the
    // weak one is passed over.
    chain.push(103, Some(102));
    let peer = FakePeer::start(2, &chain, Behavior::Honest);
    let mut later = common::prover("prove-weak-then-real", &chain, &[0], &[&peer]);
    let proof = later.prove(&signature, 101).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (101, 102, 1));
}

#[test]
fn a_certificate_from_another_cluster_is_skipped() {
    let mut chain = Chain::linear(100..102);
    let validators = chain.validators(0);
    let foreign = validators.fast_cert(
        chain.block(101),
        &validators.ranks_reaching(8_000),
        VERSION + 1,
    );
    chain.push_with(102, Some(&foreign));
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-foreign-certificate", &chain, &[0], &[&peer]);
    let Refusal::NoCertificate { rejected, .. } =
        prover.prove(&chain.signature(101, 0), 101).unwrap_err()
    else {
        panic!("another cluster's certificate certifies nothing");
    };
    assert_eq!(rejected, [(102, Error::SignatureMismatch)]);
}

/// Epochs of 32 slots, and a chain that crosses from epoch 1 into epoch 2
/// at slot 64. Each footer carries the certificate for the block before.
fn across_a_boundary(last: u64) -> Chain {
    let mut chain = Chain::new(32, 59);
    for slot in 60..=last {
        chain.push(slot, Some(slot - 1));
    }
    chain
}

#[test]
fn around_an_epoch_boundary_the_missing_set_is_named() {
    // The tip is the first block of epoch 2, whose footer carries the
    // certificate for the last block of epoch 1.
    let chain = across_a_boundary(64);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let signature = chain.signature(63, 0);

    let mut only_new = prover("prove-boundary-new", &chain, &[2], &[&peer]);
    let refusal = only_new.prove(&signature, 63).unwrap_err();
    assert_eq!(
        refusal,
        Refusal::EpochNotPinned {
            epoch: 1,
            slot: 63,
            pinned: vec![2]
        }
    );
    let said = refusal.to_string();
    assert!(
        said.contains("epoch 1") && said.contains("pinned: 2"),
        "{said}"
    );

    let mut both = prover("prove-boundary-both", &chain, &[1, 2], &[&peer]);
    let proof = both.prove(&signature, 63).unwrap();
    assert_eq!(verified(&chain, &[1], &proof, &signature), (63, 63, 0));
}

#[test]
fn the_old_epochs_set_alone_cannot_reach_into_the_new_one() {
    let chain = across_a_boundary(67);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut only_old = prover("prove-boundary-old", &chain, &[1], &[&peer]);
    assert_eq!(
        only_old.prove(&chain.signature(64, 0), 64).unwrap_err(),
        Refusal::EpochNotPinned {
            epoch: 2,
            slot: 64,
            pinned: vec![1]
        }
    );
    // What the old set can vouch for, it still does.
    let signature = chain.signature(62, 0);
    let proof = only_old.prove(&signature, 62).unwrap();
    assert_eq!(verified(&chain, &[1], &proof, &signature), (62, 62, 0));
}

#[test]
fn the_new_epochs_set_reaches_back_across_the_boundary() {
    // With only epoch 2's set, the certificate for slot 63 cannot be
    // checked. The one for slot 64 can, and slot 63 is its parent.
    let chain = across_a_boundary(67);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut only_new = prover("prove-boundary-reach", &chain, &[2], &[&peer]);
    let signature = chain.signature(63, 0);
    let proof = only_new.prove(&signature, 63).unwrap();
    assert_eq!(verified(&chain, &[2], &proof, &signature), (63, 64, 1));
}

#[test]
fn files_planted_in_the_store_are_not_believed() {
    let chain = Chain::linear(100..104);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-planted", &chain, &[0], &[&peer]);
    let store = prover.store();
    let real = Anchor {
        certificate: chain.certificate(101),
        links: vec![],
    };

    // A block file whose shreds are another block's.
    let abandoned = build(101, chain.block(100), &[7_000], None);
    store
        .put_block(&chain.block(101), &real, &abandoned.payloads)
        .unwrap();
    // A proof filed under another transaction's signature.
    let signature = chain.signature(101, 0);
    let other = chain.signature(101, 1);
    assert_eq!(
        prover.prove(&signature_for(7_000), 101).unwrap_err(),
        Refusal::NotInBlock { slot: 101 }
    );
    assert_eq!(
        store.block(101).unwrap().shreds,
        chain.blocks[&101].payloads
    );
    let proof_of_other = prover.prove(&other, 101).unwrap();
    store.put_proof(&signature, &proof_of_other).unwrap();
    let proof = prover.prove(&signature, 101).unwrap();
    assert_ne!(proof, proof_of_other);
    assert_eq!(verified(&chain, &[0], &proof, &signature), (101, 101, 0));

    // A block file whose shreds are right and whose anchor is not: a
    // certificate for another block.
    let wrong = Anchor {
        certificate: chain.certificate(100),
        links: vec![],
    };
    store
        .put_block(&chain.block(102), &wrong, &chain.blocks[&102].payloads)
        .unwrap();
    let signature = chain.signature(102, 0);
    let proof = prover.prove(&signature, 102).unwrap();
    assert_eq!(verified(&chain, &[0], &proof, &signature), (102, 102, 0));
    assert_eq!(
        store.block(102).unwrap().anchor.certificate,
        chain.certificate(102)
    );
}

#[test]
fn a_block_that_switched_parent_is_fetched_and_refused() {
    let mut chain = Chain::linear(100..101);
    // A block whose leader switched parent part way, to the same parent:
    // certified like any other, and nothing in it can be proven.
    let parent = chain.block(100);
    let transaction = |seed| vec![legacy_transaction(seed, &[b"x"])];
    let payloads = BlockBuilder::new(101, parent, VERSION)
        .header()
        .component(&entry_batch(&[transaction(1)]))
        .component(&update_parent_component(&parent))
        .component(&entry_batch(&[transaction(2)]))
        .component(&footer_component([1; 32], 1, b"testkit", None))
        .build();
    let block = RawBlock::from_shreds(&payloads).unwrap().block(&parent);
    chain.adopt(Built {
        block,
        parent,
        payloads,
        signatures: vec![signature_for(1), signature_for(2)],
    });
    chain.push(102, Some(101));
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let mut prover = prover("prove-update-parent", &chain, &[0], &[&peer]);
    assert_eq!(
        prover.prove(&signature_for(2), 101).unwrap_err(),
        Refusal::Unprovable {
            block,
            error: Error::UpdateParentBlock
        }
    );
    assert_eq!(prover.store().usage().blocks, 0);
}

#[test]
fn a_proof_the_verifier_would_refuse_is_not_returned() {
    let chain = Chain::linear(100..103);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    // A prover whose clients take proofs of at most 500 bytes.
    let mut trust = Trust::new(vec![chain.set_file(0)], None, Schedule::Flat(432_000)).unwrap();
    trust.set_limits(Limits::default().with_max_proof_bytes(500));
    let store = Arc::new(Store::open(&directory("prove-rejected"), 64 << 20).unwrap());
    let mut prover = Prover::new(
        Arc::new(trust),
        store,
        fetcher(&[&peer], quick()),
        searching(),
    );
    let signature = chain.signature(101, 0);
    assert_eq!(
        prover.prove(&signature, 101).unwrap_err(),
        Refusal::ProofRejected {
            block: chain.block(101),
            error: Error::LimitExceeded("proof size")
        }
    );
    assert_eq!(prover.store().proof(&signature), None);
}

#[test]
fn a_store_that_cannot_be_written_is_reported() {
    let chain = Chain::linear(100..103);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let dir = directory("prove-store-gone");
    let store = Arc::new(Store::open(&dir, 64 << 20).unwrap());
    let mut prover = Prover::new(
        chain.trust(&[0]),
        store,
        fetcher(&[&peer], quick()),
        searching(),
    );
    std::fs::remove_dir_all(dir.join("blocks")).unwrap();
    let refusal = prover.prove(&chain.signature(101, 0), 101).unwrap_err();
    assert!(matches!(refusal, Refusal::Store(_)), "{refusal}");
    assert!(refusal.is_temporary());
}

#[test]
fn with_no_peers_nothing_is_asked() {
    let chain = Chain::linear(100..103);
    let mut prover = prover("prove-no-peers", &chain, &[0], &[]);
    assert_eq!(
        prover.prove(&chain.signature(101, 0), 101).unwrap_err(),
        Refusal::NoPeers
    );
}

#[test]
fn peers_that_stop_serving_mid_block_leave_nothing_behind() {
    let chain = Chain::linear(100..103);
    let peer = FakePeer::start(1, &chain, Behavior::WithholdsShreds);
    let mut prover = prover("prove-incomplete", &chain, &[0], &[&peer]);
    let refusal = prover.prove(&chain.signature(101, 0), 101).unwrap_err();
    assert!(matches!(
        refusal,
        Refusal::Incomplete {
            what: "shreds",
            have: 0,
            total: 128,
            ..
        }
    ));
    assert!(refusal.is_temporary());
    assert_eq!(prover.store().usage().blocks, 0);
    // The same question once the peer serves again.
    peer.behave(Behavior::Honest);
    assert!(prover.prove(&chain.signature(101, 0), 101).is_ok());
}

#[test]
fn every_transaction_of_a_fetched_block_proves() {
    let chain = Chain::linear(100..104);
    let peers = [
        FakePeer::start(1, &chain, Behavior::Duplicates),
        FakePeer::start(2, &chain, Behavior::Lossy),
        FakePeer::start(3, &chain, Behavior::CorruptShreds),
        FakePeer::start(4, &chain, Behavior::Silent),
    ];
    let mut prover = prover("prove-all", &chain, &[0], &peers.iter().collect::<Vec<_>>());
    let held = prover.fetch(102).unwrap();
    assert_eq!(held.block, chain.block(102));
    assert_eq!(held.found_in, Some(103));
    assert_eq!(held.shreds, 128);
    assert_eq!(held.signatures, chain.blocks[&102].signatures);
    let stats = held.fetch.unwrap();
    assert!(stats.rejected >= 3 && stats.requests > 128, "{stats:?}");

    let proven = prover.prove_all(102).unwrap();
    assert_eq!(proven.proof_sizes.len(), 3);
    assert!(proven.failures.is_empty());
    // Held now: asking again fetches nothing.
    let again = prover.fetch(102).unwrap();
    assert!(again.fetch.is_none() && again.found_in.is_none());
}
