//! The honest path: every transaction of every block can be proven, by every
//! route the proof format allows.

mod common;

use common::*;
use solana_thin::testkit::*;
use solana_thin::transaction::MessageVersion;
use solana_thin::*;

#[test]
fn every_transaction_of_every_block_is_provable() {
    let w = world();
    let mut proven = 0;
    for (i, block) in w.blocks.iter().enumerate() {
        for signature in block.signatures() {
            let proof = w.proof(i, &signature);
            let verified = w.client.verify_signature(&proof, &signature).unwrap();
            assert_eq!(verified.block, block.block());
            assert_eq!(verified.parent, block.parent());
            assert_eq!(verified.finalized_by.block, block.block());
            assert_eq!(verified.finalized_by.finality, Finality::Fast);

            // The encoded form says the same thing.
            let bytes = proof.to_bytes().unwrap();
            assert_eq!(proof.encoded_len(), Ok(bytes.len()));
            assert_eq!(
                TxProof::from_bytes(&bytes, &Limits::default()).unwrap(),
                proof
            );
            assert_eq!(w.client.verify_transaction_bytes(&bytes).unwrap(), verified);
            proven += 1;
        }
    }
    assert_eq!(proven, 5 + 150 + 4 + 1);
}

#[test]
fn a_certificate_for_a_descendant_finalizes_its_ancestors() {
    let w = world();
    let signature = signature_for(2);
    let cert = w.fast_cert(2);
    let chain = [&w.blocks[2], &w.blocks[1], &w.blocks[0]];
    let proof = prover::prove(cert, &chain, &signature, false).unwrap();
    assert_eq!(proof.ancestry.len(), 2);
    let verified = w.client.verify_signature(&proof, &signature).unwrap();
    assert_eq!(verified.block, w.blocks[0].block());
    assert_eq!(verified.finalized_by.block, w.blocks[2].block());
}

#[test]
fn slow_finality_is_accepted_when_both_halves_reach_sixty_percent() {
    let w = world();
    let block = w.blocks[2].block();
    let sixty = w.validators.ranks_reaching(6_000);
    // Two different 60% groups: the top ranks notarize, the bottom ranks finalize.
    let all: Vec<usize> = (0..w.validators.len()).collect();
    let mut bottom = Vec::new();
    let mut stake = 0u128;
    let total = u128::from(w.validators.set().total_stake());
    for rank in all.iter().rev() {
        if stake * 10 >= total * 6 {
            break;
        }
        stake += u128::from(w.validators.set().validators()[*rank].stake);
        bottom.push(*rank);
    }
    bottom.sort();
    let cert = w
        .validators
        .slow_cert(block, &sixty, &bottom, SHRED_VERSION);
    let finalized = w.client.verify_finality(&cert).unwrap();
    assert_eq!(finalized.finality, Finality::Slow);

    let signature = signature_for(900);
    let proof = prover::prove(cert, &[&w.blocks[2]], &signature, false).unwrap();
    w.client.verify_signature(&proof, &signature).unwrap();
}

#[test]
fn all_three_transaction_encodings_are_walked() {
    let w = world();
    for (seed, version, memo) in [
        (500, MessageVersion::Legacy, &b"legacy"[..]),
        (501, MessageVersion::V0, b"second memo"),
        (502, MessageVersion::V1, b"v1"),
        (503, MessageVersion::Legacy, b"anchor:0123456789abcdef"),
    ] {
        let signature = signature_for(seed);
        let verified = w
            .client
            .verify_signature(&w.proof(1, &signature), &signature)
            .unwrap();
        assert_eq!(verified.transaction.version, version);
        assert!(verified.has_memo(memo));
        assert!(!verified.has_memo(b"something else"));
    }
}

#[test]
fn the_footer_gives_block_time_and_the_next_certificate() {
    let w = world();
    let signature = signature_for(503);
    let proof = prover::prove(w.fast_cert(1), &[&w.blocks[1]], &signature, true).unwrap();
    let verified = w.client.verify_signature(&proof, &signature).unwrap();
    let footer = verified.footer.clone().expect("proof opened the footer");
    assert_eq!(
        verified.block_time_nanos(),
        Some(1_792_590_840_000_000_000 + 1002 * 400_000_000)
    );
    assert_eq!(footer.user_agent, b"testkit");

    // The leader embedded a certificate for block 1. It is handed back
    // unverified; checking it is one more call.
    let embedded = footer.finality.expect("block 2 carries a certificate");
    let finalized = w.client.verify_finality(&embedded).unwrap();
    assert_eq!(finalized.block, w.blocks[0].block());
}

#[test]
fn resigned_shreds_verify_too() {
    let w = world();
    let parent = w.blocks[2].block();
    let txs: Vec<Vec<u8>> = (0..40).map(|i| sized_transaction(7000 + i, 250)).collect();
    let payloads = BlockBuilder::new(1004, parent, SHRED_VERSION)
        .resigned(true)
        .header()
        .component(&entry_batch(&[txs]))
        .component(&footer_component([1; 32], 5, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    let block = prover::BlockData::from_shreds(&payloads).unwrap();
    let cert = w.validators.fast_cert(
        block.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    for signature in block.signatures() {
        let proof = prover::prove(cert.clone(), &[&block], &signature, true).unwrap();
        w.client.verify_signature(&proof, &signature).unwrap();
    }
}

#[test]
fn proofs_stay_small() {
    let w = world();
    // A transaction in a small batch: certificate, header shred, boundary
    // shred and one data shred.
    let small = w.proof(0, &signature_for(0)).to_bytes().unwrap();
    assert!(small.len() < 2_000, "small proof is {} bytes", small.len());

    // The last transaction of a batch that spans two FEC sets has to carry
    // the whole batch in front of it. That is the worst case for this block.
    let last = w.proof(1, &signature_for(249)).to_bytes().unwrap();
    let first = w.proof(1, &signature_for(100)).to_bytes().unwrap();
    assert!(
        first.len() < 3_000,
        "first-in-batch proof is {} bytes",
        first.len()
    );
    // The batch itself is about 47 KB; the proof adds under 10% to that.
    let batch: usize = w.blocks[1].components().nth(1).unwrap().1.len();
    assert!(
        last.len() < batch + batch / 10,
        "last-in-batch proof is {} bytes",
        last.len()
    );
    assert!(first.len() < last.len());
    println!("proof sizes: small batch {}, first of large batch {}, last of large batch {} (batch {batch})",
        small.len(), first.len(), last.len());

    // An ancestry link costs well under 200 bytes.
    let cert = w.fast_cert(2);
    let chain = [&w.blocks[2], &w.blocks[1], &w.blocks[0]];
    let chained = prover::prove(cert, &chain, &signature_for(0), false)
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(chained.len() - small.len() < 400);
}
