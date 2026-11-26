//! Randomized and boundary-case blocks: whatever the shape of a block, every
//! transaction in it is provable, and nothing that is not in it is.

mod common;

use common::*;
use solana_thin::prover::BlockData;
use solana_thin::testkit::*;
use solana_thin::*;

/// A small deterministic generator, so failures reproduce.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_transaction(rng: &mut Rng, seed: u64) -> Vec<u8> {
    let memo = vec![rng.next() as u8 | 1; rng.below(900) as usize];
    let second = vec![0x33; rng.below(40) as usize];
    match rng.below(3) {
        0 => legacy_transaction(seed, &[&memo]),
        1 => v0_transaction(seed, &[&memo, &second]),
        _ => v1_transaction(seed, &[&second, &memo]),
    }
}

#[test]
fn random_blocks_prove_every_transaction_and_nothing_else() {
    let w = world();
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let mut seed = 10_000;
    let mut parent = w.blocks[2].block();
    let mut total = 0;
    for round in 0..12 {
        let slot = parent.slot + 1 + rng.below(3);
        let mut batches = Vec::new();
        let mut expected = Vec::new();
        for _ in 0..1 + rng.below(4) {
            let mut batch = Vec::new();
            for _ in 0..1 + rng.below(5) {
                let mut entry = Vec::new();
                // Up to ~60 transactions: enough to cross FEC sets sometimes.
                let most = if rng.below(4) == 0 { 60 } else { 6 };
                for _ in 0..rng.below(most) {
                    entry.push(random_transaction(&mut rng, seed));
                    expected.push(signature_for(seed));
                    seed += 1;
                }
                batch.push(entry);
            }
            batches.push(batch);
        }
        let block = simple_block(slot, parent, SHRED_VERSION, &batches, None);
        assert_eq!(block.signatures(), expected, "round {round}");
        let cert = w.validators.fast_cert(
            block.block(),
            &w.validators.ranks_reaching(8_000),
            SHRED_VERSION,
        );
        for signature in &expected {
            let proof = prover::prove(cert.clone(), &[&block], signature, round % 2 == 0).unwrap();
            let bytes = proof.to_bytes().unwrap();
            let verified = w.client.verify_transaction_bytes(&bytes).unwrap();
            assert_eq!(verified.transaction.signature(), Some(signature));
            assert_eq!(verified.block, block.block());
            total += 1;
        }
        // A signature from an earlier round is not in this block.
        if let Some(old) = seed.checked_sub(expected.len() as u64 + 1) {
            assert_eq!(
                prover::prove(cert, &[&block], &signature_for(old), false).unwrap_err(),
                Error::SignatureNotFound
            );
        }
        parent = block.block();
    }
    assert!(total > 150, "only {total} transactions generated");
}

/// Components whose length lands exactly on, one under, and one over a shred
/// and a FEC set boundary.
#[test]
fn boundaries_between_shreds_and_fec_sets() {
    let w = world();
    const BODY: usize = 963;
    let parent = w.blocks[2].block();
    // One entry holding one filler transaction and one probe at the very end.
    for (case, target) in [
        BODY - 1,
        BODY,
        BODY + 1,
        2 * BODY,
        32 * BODY - 1,
        32 * BODY,
        32 * BODY + 1,
        33 * BODY,
        64 * BODY,
        64 * BODY + 1,
    ]
    .into_iter()
    .enumerate()
    {
        let probe = legacy_transaction(77, &[b"probe"]);
        // Fill with transactions so the batch is exactly `target` bytes long.
        let overhead = 8 + 40 + 8 + probe.len();
        let mut fill = target - overhead;
        let mut entry = Vec::new();
        let mut seed = 20_000;
        while fill > 0 {
            // A legacy transaction with an n-byte memo is 137 + len(shortvec(n)) + n bytes.
            let take = fill.min(1_000);
            let memo_len = (0..=take)
                .rev()
                .find(|n| legacy_transaction(seed, &[&vec![1u8; *n]]).len() <= take)
                .filter(|n| legacy_transaction(seed, &[&vec![1u8; *n]]).len() == take);
            let Some(memo_len) = memo_len else {
                // Leave room so the remainder can be hit exactly next time.
                let tx = legacy_transaction(seed, &[&vec![1u8; take - 300]]);
                fill -= tx.len();
                entry.push(tx);
                seed += 1;
                continue;
            };
            let tx = legacy_transaction(seed, &[&vec![1u8; memo_len]]);
            fill -= tx.len();
            entry.push(tx);
            seed += 1;
        }
        entry.push(probe);
        let batch = entry_batch(&[entry]);
        assert_eq!(batch.len(), target, "case {case}");

        let payloads = BlockBuilder::new(2_000 + case as u64, parent, SHRED_VERSION)
            .header()
            .component(&batch)
            .component(&footer_component([0; 32], 9, b"", None))
            .component(&entry_batch(&[vec![]]))
            .build();
        let block = BlockData::from_shreds(&payloads).unwrap();
        let cert = w.validators.fast_cert(
            block.block(),
            &w.validators.ranks_reaching(8_000),
            SHRED_VERSION,
        );
        for signature in block.signatures() {
            let proof = prover::prove(cert.clone(), &[&block], &signature, true).unwrap();
            let verified = w.client.verify_signature(&proof, &signature).unwrap();
            assert!(verified.footer.is_some(), "case {case}");
        }
        // The probe is the last transaction: its proof needs every shred of
        // the batch and not one more.
        let proof = prover::prove(cert, &[&block], &signature_for(77), false).unwrap();
        let shreds: usize = proof
            .block
            .sets
            .iter()
            .filter(|s| s.set > 0)
            .map(|s| s.shreds.len())
            .sum();
        assert_eq!(shreds, target.div_ceil(BODY), "case {case}");
    }
}

/// A leader can flag `DATA_COMPLETE` on any shred it likes, but a validator
/// throws away a shred that carries the flag anywhere except the end of a FEC
/// set, so such a block is never completed, let alone finalized. The
/// verifier refuses the shred the same way, and the honest prover will not
/// index the block.
#[test]
fn data_complete_is_only_honored_at_the_end_of_a_fec_set() {
    let w = world();
    let parent = w.blocks[2].block();
    let first = entry_batch(&[vec![
        legacy_transaction(1, &[&[7u8; 900]]),
        legacy_transaction(2, &[b"a"]),
    ]]);
    let second = entry_batch(&[vec![legacy_transaction(3, &[b"second component"])]]);

    // Two batches inside one FEC set: the first takes two shreds and is
    // flagged complete there; the second starts at the third.
    let mut builder = BlockBuilder::new(3_000, parent, SHRED_VERSION).header();
    let start = builder.next_index();
    let mut joined = first.clone();
    joined.resize(2 * 963, 0);
    joined.extend_from_slice(&second);
    builder = builder.component(&joined);
    {
        let shred = builder.shred_mut(start + 1);
        shred.flags |= solana_thin::shred::FLAG_DATA_COMPLETE;
        shred.size = (88 + first.len() - 963) as u16;
        shred.body.truncate(first.len() - 963);
    }
    let payloads = builder
        .component(&footer_component([0; 32], 9, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    let refused = Error::InvalidShred("data-complete off the end of a FEC set");
    assert_eq!(BlockData::from_shreds(&payloads).unwrap_err(), refused);

    // A dishonest prover opens it anyway. The second batch really is there,
    // at a boundary the flag really marks, under a valid certificate.
    let raw = RawBlock::from_shreds(&payloads).unwrap();
    assert!(raw.component_starts().contains(&(start + 2)));
    let cert = w.validators.fast_cert(
        raw.block(&parent),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let all: std::collections::BTreeSet<u32> = (0..raw.shred_count()).collect();
    for (component_start, transaction) in [(start + 2, 0), (start, 0), (start, 1)] {
        let proof = TxProof {
            finality: cert.clone(),
            ancestry: vec![],
            block: raw.open(&parent, &all),
            component_start,
            position: TxPosition {
                entry: 0,
                transaction,
            },
            footer_start: None,
        };
        assert_eq!(w.client.verify_transaction(&proof), Err(refused.clone()));
    }
}

/// A proof may open more of a block than it needs. Whatever the extra shreds
/// hold, the answer for the same claim is the same: the verifier reads only
/// what the claim points at, and reads it the same way.
#[test]
fn opening_more_of_the_block_changes_nothing() {
    let w = world();
    for (i, block) in w.blocks.iter().enumerate() {
        let all: std::collections::BTreeSet<u32> = (0..block.shred_count()).collect();
        for signature in block.signatures() {
            let minimal = w.proof(i, &signature);
            let verified = w.client.verify_transaction(&minimal).unwrap();
            let mut full = minimal.clone();
            full.block = block.open(&all);
            assert!(full.to_bytes().unwrap().len() > minimal.to_bytes().unwrap().len());
            assert_eq!(w.client.verify_transaction(&full).unwrap(), verified);
        }
    }
}
