//! Every way we know to fool a Solana light client, tried against this one.
//!
//! Each test builds a concrete attack, shows (where it helps) that the attack
//! works against a verifier that skips one check, and then asserts that the
//! real client rejects it and for which reason.

mod common;

use common::*;
use solana_thin::block::{self, TxPosition};
use solana_thin::certificate::{encode_bitmap, finalize_payload, notarize_payload};
use solana_thin::prover::BlockData;
use solana_thin::shred::FLAG_DATA_COMPLETE;
use solana_thin::testkit::*;
use solana_thin::*;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// A fast certificate and a plain notarization are the same signature over the
/// same bytes. Only the stake behind it differs. A client that checks the
/// signature and forgets the 80% line accepts blocks that can still be skipped.
#[test]
fn a_notarization_is_not_finality() {
    let w = world();
    let block = w.blocks[0].block();
    for bps in [6_000, 7_000, 7_900] {
        let ranks = w.validators.ranks_reaching(bps);
        let cert = w.validators.fast_cert(block, &ranks, SHRED_VERSION);
        // Drop one signer if the helper overshot 80%.
        let cert = match w.client.verify_finality(&cert) {
            Ok(_) => w
                .validators
                .fast_cert(block, &ranks[..ranks.len() - 1], SHRED_VERSION),
            Err(_) => cert,
        };
        assert!(
            matches!(
                w.client.verify_finality(&cert),
                Err(Error::InsufficientStake {
                    required_bps: 8_000,
                    ..
                })
            ),
            "{bps} bps of notarize votes must not finalize"
        );
    }
    let enough = w.validators.ranks_reaching(8_000);
    assert!(w
        .client
        .verify_finality(&w.validators.fast_cert(block, &enough, SHRED_VERSION))
        .is_ok());
}

/// Finalize votes name a slot, not a block. If a leader produced two blocks in
/// one slot, the real finalize aggregate for that slot is true of whichever
/// one was notarized. Pairing it with the other block must fail.
#[test]
fn finalize_votes_do_not_choose_a_block() {
    let w = world();
    let real = w.blocks[2].block();
    let twin = BlockRef {
        slot: real.slot,
        id: [0x66; 32],
    };
    let all: Vec<usize> = (0..w.validators.len()).collect();

    // The honest network: everyone notarized and finalized `real`.
    let honest = w.validators.slow_cert(real, &all, &all, SHRED_VERSION);
    assert!(w.client.verify_finality(&honest).is_ok());
    let FinalityCert::Slow {
        finalize, notar, ..
    } = honest
    else {
        unreachable!()
    };

    // 1. Take the real finalize aggregate, no notarization for the twin at all:
    //    reuse the real notarize aggregate under the twin's name.
    let relabeled = FinalityCert::Slow {
        block: twin,
        finalize: finalize.clone(),
        notar,
    };
    assert_eq!(
        w.client.verify_finality(&relabeled),
        Err(Error::SignatureMismatch)
    );

    // 2. The attacker controls a minority that really did notarize the twin.
    let minority = &all[..5];
    let weak = FinalityCert::Slow {
        block: twin,
        finalize,
        notar: w
            .validators
            .aggregate(minority, &notarize_payload(&twin, SHRED_VERSION)),
    };
    assert!(matches!(
        w.client.verify_finality(&weak),
        Err(Error::InsufficientStake {
            required_bps: 6_000,
            ..
        })
    ));
}

/// A finalize aggregate alone, presented as if it were a fast certificate.
#[test]
fn a_finalize_aggregate_is_not_a_fast_certificate() {
    let w = world();
    let block = w.blocks[0].block();
    let all: Vec<usize> = (0..w.validators.len()).collect();
    let cert = FinalityCert::Fast {
        block,
        notar: w
            .validators
            .aggregate(&all, &finalize_payload(block.slot, SHRED_VERSION)),
    };
    assert_eq!(
        w.client.verify_finality(&cert),
        Err(Error::SignatureMismatch)
    );
}

/// The same validators run testnets and survive cluster restarts with the same
/// keys. The shred version in the signed bytes keeps their votes apart.
#[test]
fn votes_from_another_cluster_do_not_count() {
    let w = world();
    let block = w.blocks[0].block();
    let all: Vec<usize> = (0..w.validators.len()).collect();
    let foreign = w.validators.fast_cert(block, &all, SHRED_VERSION + 1);
    assert_eq!(
        w.client.verify_finality(&foreign),
        Err(Error::SignatureMismatch)
    );
}

/// A certificate is only as good as the validator set it is checked against.
/// One from another epoch must not be checked against this epoch's set, and a
/// set the caller did not pin must not be usable at all.
#[test]
fn certificates_are_bound_to_their_epochs_validators() {
    let mut w = world();
    let later = BlockRef {
        slot: 432_000 * 3 + 5,
        id: [7; 32],
    };
    let all: Vec<usize> = (0..w.validators.len()).collect();
    let cert = w.validators.fast_cert(later, &all, SHRED_VERSION);
    assert_eq!(w.client.verify_finality(&cert), Err(Error::UnknownEpoch(3)));

    // An attacker's own validators, all signing happily.
    let attackers = TestValidators::with_seed(99, 20, |_| 1_000_000);
    let forged = attackers.fast_cert(w.blocks[0].block(), &all, SHRED_VERSION);
    assert_eq!(
        w.client.verify_finality(&forged),
        Err(Error::SignatureMismatch)
    );

    // They cannot get their set pinned under the honest set's hash...
    let honest_hash = w.validators.set().hash();
    assert_eq!(
        w.client
            .trust_validator_set(0, attackers.set(), &honest_hash),
        Err(Error::ValidatorSetHashMismatch)
    );
    // ...and the honest set stays in force.
    assert_eq!(
        w.client.verify_finality(&forged),
        Err(Error::SignatureMismatch)
    );
}

/// Stake is counted from the bitmap, so the bitmap must name exactly the keys
/// in the aggregate. Claiming extra signers, or the two-vector bitmap form
/// that validators refuse for finality, must fail.
#[test]
fn the_bitmap_cannot_claim_more_than_signed() {
    let w = world();
    let block = w.blocks[0].block();
    let seventy = w.validators.ranks_reaching(7_000);
    let FinalityCert::Fast { notar, .. } = w.validators.fast_cert(block, &seventy, SHRED_VERSION)
    else {
        unreachable!()
    };

    let all: Vec<usize> = (0..w.validators.len()).collect();
    let mut inflated = notar.clone();
    inflated.bitmap = encode_bitmap(&all);
    let cert = FinalityCert::Fast {
        block,
        notar: inflated,
    };
    assert_eq!(
        w.client.verify_finality(&cert),
        Err(Error::SignatureMismatch)
    );

    let mut base3 = notar.clone();
    base3.bitmap[0] = 1;
    let cert = FinalityCert::Fast {
        block,
        notar: base3,
    };
    assert_eq!(w.client.verify_finality(&cert), Err(Error::InvalidBitmap));

    let mut out_of_range = notar;
    out_of_range.bitmap = encode_bitmap(&[w.validators.len()]);
    let cert = FinalityCert::Fast {
        block,
        notar: out_of_range,
    };
    assert_eq!(w.client.verify_finality(&cert), Err(Error::RankOutOfRange));
}

/// The rogue-key attack. With BLS aggregation, anyone who may add an unchecked
/// public key to the set can pick it so that it cancels every honest key out
/// of the aggregate, and then sign alone for the whole set.
///
/// On chain this is prevented by proofs of possession at key registration. A
/// light client inherits that protection only if its validator set really is
/// the on-chain one, which is what pinning the hash is for.
#[test]
fn a_rogue_key_forges_everything_if_an_unpinned_set_is_trusted() {
    let mut w = world();
    let block = BlockRef {
        slot: 1500,
        id: [0xbd; 32],
    };

    // The attacker knows one secret key, `x`, and every honest public key.
    let attacker = TestValidators::with_seed(1234, 1, |_| 1);
    let honest = w.validators.set();
    let honest_keys: Vec<blst::min_pk::PublicKey> = honest
        .validators()
        .iter()
        .map(|v| blst::min_pk::PublicKey::uncompress(&v.bls_pubkey).unwrap())
        .collect();
    let refs: Vec<&blst::min_pk::PublicKey> = honest_keys.iter().collect();
    let sum = blst::min_pk::AggregatePublicKey::aggregate(&refs, false)
        .unwrap()
        .to_public_key();
    // Negating a compressed point is flipping its sign bit.
    let mut negated = sum.compress();
    negated[0] ^= 0x20;
    let negated = blst::min_pk::PublicKey::uncompress(&negated).unwrap();
    let x_key = blst::min_pk::PublicKey::uncompress(&attacker.pubkey(0)).unwrap();
    // rogue = x·G − Σ honest. Honest keys plus the rogue key sum to x·G.
    let rogue = blst::min_pk::AggregatePublicKey::aggregate(&[&x_key, &negated], false)
        .unwrap()
        .to_public_key()
        .compress();

    let mut validators = honest.validators().to_vec();
    validators.push(Validator {
        bls_pubkey: rogue,
        stake: 1,
    });
    let poisoned = ValidatorSet::from_unordered(validators).unwrap();
    let everyone: Vec<usize> = (0..poisoned.len()).collect();
    let forged = FinalityCert::Fast {
        block,
        notar: Aggregate {
            // One signature, by the attacker alone.
            signature: attacker
                .sign(0, &notarize_payload(&block, SHRED_VERSION))
                .compress(),
            bitmap: encode_bitmap(&everyone),
        },
    };

    // Against the pinned, honest set the forgery is nothing.
    assert!(w.client.verify_finality(&forged).is_err());

    // The attacker cannot pin the poisoned set: its hash is not the honest one.
    let honest_hash = honest.hash();
    assert_eq!(
        w.client
            .trust_validator_set(0, poisoned.clone(), &honest_hash),
        Err(Error::ValidatorSetHashMismatch)
    );

    // But a caller who pins whatever a server hands them has lost everything:
    // a certificate "signed" by 100% of stake for a block that does not exist.
    let poisoned_hash = poisoned.hash();
    w.client
        .trust_validator_set(0, poisoned, &poisoned_hash)
        .unwrap();
    assert_eq!(w.client.verify_finality(&forged).unwrap().block, block);
}

// ---------------------------------------------------------------------------
// Stale-set mode (the `unsound-stale-set` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "unsound-stale-set")]
mod stale_set_mode {
    use super::*;

    fn stale_world() -> (World, BlockRef) {
        let mut w = world();
        w.client.set_stale_policy(Some(StalePolicy {
            max_epochs: 2,
            drift_bps_per_epoch: 900,
        }));
        let block = BlockRef {
            slot: 432_000 + 9,
            id: [0x51; 32],
        };
        (w, block)
    }

    fn known(w: &World) -> Vec<Candidate> {
        (0..w.validators.len())
            .map(|rank| Candidate {
                bls_pubkey: w.validators.pubkey(rank),
                proof_of_possession: None,
            })
            .collect()
    }

    /// In stale mode the key list for the new epoch comes from an untrusted
    /// source, so the rogue-key attack is live. A key the client has never seen
    /// must prove possession or the certificate is refused outright.
    #[test]
    fn stale_mode_refuses_unknown_keys_without_proof_of_possession() {
        let (mut w, block) = stale_world();
        let attacker = TestValidators::with_seed(1234, 1, |_| 1);

        let honest_keys: Vec<blst::min_pk::PublicKey> = (0..w.validators.len())
            .map(|r| blst::min_pk::PublicKey::uncompress(&w.validators.pubkey(r)).unwrap())
            .collect();
        let refs: Vec<&blst::min_pk::PublicKey> = honest_keys.iter().collect();
        let mut negated = blst::min_pk::AggregatePublicKey::aggregate(&refs, false)
            .unwrap()
            .to_public_key()
            .compress();
        negated[0] ^= 0x20;
        let negated = blst::min_pk::PublicKey::uncompress(&negated).unwrap();
        let x_key = blst::min_pk::PublicKey::uncompress(&attacker.pubkey(0)).unwrap();
        let rogue = blst::min_pk::AggregatePublicKey::aggregate(&[&x_key, &negated], false)
            .unwrap()
            .to_public_key()
            .compress();

        let mut candidates = known(&w);
        candidates.push(Candidate {
            bls_pubkey: rogue,
            proof_of_possession: None,
        });
        let everyone: Vec<usize> = (0..candidates.len()).collect();
        let forged = FinalityCert::Fast {
            block,
            notar: Aggregate {
                signature: attacker
                    .sign(0, &notarize_payload(&block, SHRED_VERSION))
                    .compress(),
                bitmap: encode_bitmap(&everyone),
            },
        };

        w.client
            .add_candidate_set(1, CandidateSet::new(candidates.clone()).unwrap());
        assert_eq!(
            w.client.verify_finality(&forged),
            Err(Error::MissingProofOfPossession)
        );

        // The attacker cannot produce the proof: it would need the rogue key's
        // secret. Its own key's proof, or one for another account, does not fit.
        let last = candidates.len() - 1;
        candidates[last].proof_of_possession = Some(attacker.proof_of_possession(0, [1; 32]));
        w.client
            .add_candidate_set(1, CandidateSet::new(candidates).unwrap());
        assert_eq!(
            w.client.verify_finality(&forged),
            Err(Error::MissingProofOfPossession)
        );
    }

    /// Keys the client does not already trust may sign, if they prove possession,
    /// but they carry no weight. An attacker cannot vote itself into a majority.
    #[test]
    fn stale_mode_gives_new_keys_no_weight() {
        let (mut w, block) = stale_world();
        let newcomers = TestValidators::with_seed(77, 30, |_| 9_000_000);
        let mut candidates: Vec<Candidate> = (0..newcomers.len())
            .map(|rank| Candidate {
                bls_pubkey: newcomers.pubkey(rank),
                proof_of_possession: Some(newcomers.proof_of_possession(rank, [rank as u8; 32])),
            })
            .collect();
        candidates.extend(known(&w));
        w.client
            .add_candidate_set(1, CandidateSet::new(candidates).unwrap());

        // All thirty newcomers sign. Valid signature, valid proofs, zero stake.
        let ranks: Vec<usize> = (0..newcomers.len()).collect();
        let cert = newcomers.fast_cert(block, &ranks, SHRED_VERSION);
        assert!(matches!(
            w.client.verify_finality(&cert),
            Err(Error::InsufficientStake { signed: 0, .. })
        ));
    }

    /// Listing an honest key twice would let one real signature count double:
    /// twice the signature verifies against twice the key.
    #[test]
    fn stale_mode_refuses_a_key_listed_twice() {
        let (w, _) = stale_world();
        let mut candidates = known(&w);
        candidates.push(candidates[0].clone());
        assert_eq!(
            CandidateSet::new(candidates).unwrap_err(),
            Error::DuplicateValidator
        );
    }

    /// Old stake is an estimate of new stake, so stale mode demands more of it,
    /// and gives up entirely past the configured distance.
    #[test]
    fn stale_mode_raises_the_bar_with_distance() {
        let (mut w, block) = stale_world();
        for epoch in 1..=3 {
            w.client
                .add_candidate_set(epoch, CandidateSet::new(known(&w)).unwrap());
        }
        let cert_at = |w: &World, epoch: u64, bps: u32| {
            let block = BlockRef {
                slot: 432_000 * epoch + 9,
                id: block.id,
            };
            w.validators
                .fast_cert(block, &w.validators.ranks_reaching(bps), SHRED_VERSION)
        };
        // One epoch out: 80% is not enough, 89% is.
        assert!(matches!(
            w.client.verify_finality(&cert_at(&w, 1, 8_000)),
            Err(Error::InsufficientStake {
                required_bps: 8_900,
                ..
            })
        ));
        assert!(w.client.verify_finality(&cert_at(&w, 1, 8_900)).is_ok());
        // Two epochs out: 98%.
        assert!(matches!(
            w.client.verify_finality(&cert_at(&w, 2, 9_000)),
            Err(Error::InsufficientStake {
                required_bps: 9_800,
                ..
            })
        ));
        assert!(w.client.verify_finality(&cert_at(&w, 2, 10_000)).is_ok());
        // Three epochs out: past max_epochs.
        assert_eq!(
            w.client.verify_finality(&cert_at(&w, 3, 10_000)),
            Err(Error::TooStale)
        );
        // With the policy off, none of it applies.
        w.client.set_stale_policy(None);
        assert_eq!(
            w.client.verify_finality(&cert_at(&w, 1, 10_000)),
            Err(Error::UnknownEpoch(1))
        );
    }
}

// ---------------------------------------------------------------------------
// Inclusion
// ---------------------------------------------------------------------------

/// The attack that breaks "find these bytes in the block" proofs.
///
/// A server that wants you to believe your payment landed does not need to
/// land it. It can put your signed transaction's bytes inside the data of a
/// transaction of its own. The bytes are then in a finalized block, correctly
/// Merkle-proven, and were never executed.
///
/// Here the attacker is even the leader, so it also lines the fake up on a
/// shred boundary to make it look like the start of a batch.
#[test]
fn a_transaction_embedded_in_another_transactions_data_is_not_included() {
    let w = world();
    let victim = legacy_transaction(4242, &[b"pay the merchant 100"]);
    let victim_signature = signature_for(4242);

    // A fake "entry batch" holding only the victim's transaction.
    let fake_batch = entry_batch(&[vec![victim.clone()]]);

    // The carrier's memo is filler followed by the fake batch. Search for the
    // filler length that puts the fake batch at the start of a shred body.
    const BODY: usize = 963;
    let (component, offset) = (0..BODY)
        .find_map(|filler| {
            let mut memo = vec![0x2e; filler];
            memo.extend_from_slice(&fake_batch);
            let carrier = legacy_transaction(1, &[&memo]);
            let batch = entry_batch(&[vec![
                sized_transaction(2, 500),
                carrier,
                sized_transaction(3, 200),
            ]]);
            let at = batch
                .windows(fake_batch.len())
                .position(|window| window == fake_batch)?;
            (at % BODY == 0).then_some((batch, at))
        })
        .expect("some filler length aligns the payload");

    let payloads = BlockBuilder::new(1004, w.blocks[2].block(), SHRED_VERSION)
        .header()
        .component(&component)
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    let data = BlockData::from_shreds(&payloads).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );

    // The victim's bytes really are in the finalized block...
    assert!(component
        .windows(victim.len())
        .any(|window| window == victim));
    // ...and a verifier that starts parsing where it is told to finds a
    // perfectly good transaction there.
    let first = TxPosition {
        entry: 0,
        transaction: 0,
    };
    let naive = block::transaction_at(&component[offset..], first).unwrap();
    assert_eq!(naive.signature(), &victim_signature);

    // The honest prover does not think the victim's transaction is in the block.
    assert!(!data.signatures().contains(&victim_signature));
    assert_eq!(
        prover::prove(cert.clone(), &[&data], &victim_signature, false).unwrap_err(),
        Error::SignatureNotFound
    );

    // A dishonest prover opens the right shreds and claims the batch starts at
    // the aligned one.
    let fake_start = 32 + (offset / BODY) as u32;
    let needed: BTreeSet<u32> = [0, fake_start - 1, fake_start, fake_start + 1].into();
    let proof = TxProof {
        finality: cert.clone(),
        ancestry: vec![],
        block: data.open(&needed),
        component_start: fake_start,
        position: first,
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&proof),
        Err(Error::NotComponentStart)
    );

    // Hiding the previous shred does not help: then the start cannot be shown.
    let needed: BTreeSet<u32> = [0, fake_start, fake_start + 1].into();
    let mut hidden = proof.clone();
    hidden.block = data.open(&needed);
    // (Shred `fake_start - 1` is only absent if it is not in the opened run.)
    if fake_start - 1 != 32 {
        assert_eq!(
            w.client.verify_transaction(&hidden),
            Err(Error::MissingShred(fake_start - 1))
        );
    }

    // And no position in the real component yields the victim's transaction.
    for (position, _) in block::transactions(&component).unwrap() {
        let proof = TxProof {
            finality: cert.clone(),
            ancestry: vec![],
            block: data.open(&(0..data.shred_count()).collect()),
            component_start: 32,
            position,
            footer_start: None,
        };
        let verified = w.client.verify_transaction(&proof).unwrap();
        assert_ne!(verified.transaction.signature(), &victim_signature);
        assert_eq!(
            w.client.verify_signature(&proof, &victim_signature),
            Err(Error::SignatureNotFound)
        );
    }
}

/// The boundary flag lives inside the hashed shred. Setting it in the proof
/// changes the leaf, and the proof no longer reaches the block id.
#[test]
fn the_component_boundary_flag_cannot_be_forged() {
    let w = world();
    let data = &w.blocks[1];
    // The large batch starts at shred 32 and runs through two FEC sets, so
    // shred 63 is the last of a set and still in the middle of the batch.
    let needed: BTreeSet<u32> = [0, 63, 64, 65].into();
    let mut block = data.open(&needed);
    let proof = |block: BlockProof| TxProof {
        finality: w.fast_cert(1),
        ancestry: vec![],
        block,
        component_start: 64,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&proof(block.clone())),
        Err(Error::NotComponentStart)
    );
    let run = block.sets.iter_mut().find(|s| s.set == 1).unwrap();
    let shred_63 = &mut run.shreds[63 - 32 - usize::from(run.first)];
    shred_63.flags |= FLAG_DATA_COMPLETE;
    assert_eq!(
        w.client.verify_transaction(&proof(block)),
        Err(Error::BlockIdMismatch)
    );

    // Anywhere else in a FEC set the flag is not even a candidate: a
    // validator throws such a shred away, and so does the verifier, before
    // it hashes anything. Nor can a component start mid-set.
    let needed: BTreeSet<u32> = [0, 39, 40, 41].into();
    let mut block = data.open(&needed);
    let mid = |block: BlockProof| TxProof {
        component_start: 40,
        ..proof(block)
    };
    assert_eq!(
        w.client.verify_transaction(&mid(block.clone())),
        Err(Error::NotComponentStart)
    );
    let run = block.sets.iter_mut().find(|s| s.set == 1).unwrap();
    let shred_39 = &mut run.shreds[39 - 32 - usize::from(run.first)];
    shred_39.flags |= FLAG_DATA_COMPLETE;
    assert_eq!(
        w.client.verify_transaction(&mid(block)),
        Err(Error::InvalidShred(
            "data-complete off the end of a FEC set"
        ))
    );
}

/// With fast leader handover a leader may start a block on one parent, then
/// switch with an UpdateParent marker. Validators throw away everything before
/// the marker and execute only what follows. Transactions in the discarded
/// part are in the finalized block's bytes, in a real batch, at a real
/// boundary, and never ran.
#[test]
fn a_transaction_in_an_abandoned_block_prefix_is_not_included() {
    let w = world();
    let first_parent = w.blocks[2].block();
    let final_parent = w.blocks[1].block();
    let doomed = legacy_transaction(31337, &[b"never executed"]);
    let kept = legacy_transaction(31338, &[b"executed"]);

    let payloads = BlockBuilder::new(1004, first_parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![doomed]]))
        .component(&update_parent_component(&final_parent))
        .component(&entry_batch(&[vec![kept]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();

    // An honest prover will not touch the block.
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap_err(),
        Error::UpdateParentBlock
    );

    // A dishonest one indexes it with the parent the block ended on, which is
    // the parent its id commits to, and so the id validators certified.
    let data = BlockData::from_shreds_with_final_parent(&payloads, final_parent).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    assert!(w.client.verify_finality(&cert).is_ok());

    for seed in [31337, 31338] {
        let proof = prover::prove(cert.clone(), &[&data], &signature_for(seed), false).unwrap();
        // Every Merkle path in this proof is valid. The header gives it away:
        // it names a parent the block id does not.
        assert_eq!(
            w.client.verify_transaction(&proof),
            Err(Error::UpdateParentBlock)
        );
    }
}

/// The same attack with the header hidden from validators.
///
/// A validator refuses an UpdateParent that names the header's own parent,
/// which is why "header parent equals tree parent" can stand for "no switch
/// happened". But its blockstore only looks for the header in shred 0 by
/// itself. Spread the header over shreds 0 and 1 and the blockstore sees no
/// header, so an UpdateParent to the *same* parent is accepted, the tree
/// commits to that parent, and the prefix is thrown away. A verifier that
/// reads the header from the whole first component sees header and tree
/// agree, and accepts a transaction that never ran.
#[test]
fn a_header_split_across_shreds_does_not_hide_an_abandoned_prefix() {
    let w = world();
    let parent = w.blocks[2].block();
    let doomed = legacy_transaction(31337, &[b"never executed"]);
    let kept = legacy_transaction(31338, &[b"executed"]);

    let mut builder = BlockBuilder::new(1004, parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![doomed]]))
        .component(&update_parent_component(&parent))
        .component(&entry_batch(&[vec![kept]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]));

    // Move the last 34 of the header's 54 bytes into shred 1.
    let header = header_component(&parent);
    assert_eq!(header.len(), 54);
    let untrimmed = |bytes: &[u8]| {
        let zeros = bytes.iter().rev().take_while(|b| **b == 0).count();
        bytes[..bytes.len() - zeros].to_vec()
    };
    let first = builder.shred_mut(0);
    first.size = 88 + 20;
    first.body = untrimmed(&header[..20]);
    let second = builder.shred_mut(1);
    second.size = 88 + 34;
    second.body = untrimmed(&header[20..]);
    let payloads = builder.build();

    // An honest prover finds no header where a validator would look.
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap_err(),
        Error::UpdateParentBlock
    );

    let data = BlockData::from_shreds_with_final_parent(&payloads, parent).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    assert!(w.client.verify_finality(&cert).is_ok());

    // The whole first component still reads as a header naming the tree's
    // parent. That is what makes the attack work on a careless verifier.
    let whole: Vec<u8> = data.components().next().unwrap().1.to_vec();
    assert_eq!(
        block::parse_marker(&whole).unwrap(),
        block::Marker::Header { parent }
    );

    // Open the split header, the boundary before the doomed batch, and the
    // batch itself. Every Merkle path is valid.
    let needed: BTreeSet<u32> = [0, 1, 31, 32].into_iter().collect();
    let proof = TxProof {
        finality: cert,
        ancestry: vec![],
        block: data.open(&needed),
        component_start: 32,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction_bytes(&proof.to_bytes()),
        Err(Error::InvalidComponent(
            "block does not start with a header"
        ))
    );
}

/// A valid opening of one block, attached to a valid certificate for another.
#[test]
fn shreds_of_one_block_do_not_open_another() {
    let w = world();
    let signature = signature_for(0);
    let mut proof = w.proof(0, &signature);
    proof.finality = w.fast_cert(1);
    // The parent link is checked first and already fails to reach the id.
    assert_eq!(
        w.client.verify_transaction(&proof),
        Err(Error::BlockIdMismatch)
    );

    // Same slot, same shreds, different shred version: the leaves differ.
    let mut other_cluster = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION + 1));
    let foreign = TestValidators::new(20, |i| 1_000_000 + 37_000 * (i as u64 % 7));
    let hash = foreign.set().hash();
    other_cluster
        .trust_validator_set(0, foreign.set(), &hash)
        .unwrap();
    let block = w.blocks[0].block();
    let all: Vec<usize> = (0..foreign.len()).collect();
    let mut proof = w.proof(0, &signature);
    proof.finality = foreign.fast_cert(block, &all, SHRED_VERSION + 1);
    assert!(other_cluster.verify_finality(&proof.finality).is_ok());
    assert_eq!(
        other_cluster.verify_transaction(&proof),
        Err(Error::BlockIdMismatch)
    );
}

/// Shreds cannot be slid to another position, another FEC set, or presented
/// twice; and a FEC set index past the real count is refused even though the
/// tree's padding makes the hashes work.
#[test]
fn shreds_only_verify_where_they_really_are() {
    let w = world();
    let signature = signature_for(120);
    let good = w.proof(1, &signature);
    assert!(w.client.verify_transaction(&good).is_ok());
    let count = good.block.parent.fec_set_count;

    let tamper = |f: &dyn Fn(&mut TxProof)| {
        let mut proof = good.clone();
        f(&mut proof);
        w.client.verify_transaction(&proof)
    };

    // Slide a run one shred to the right within its set.
    assert!(tamper(&|p| p.block.sets[1].first += 1).is_err());
    // Claim a run belongs to the next FEC set.
    assert!(tamper(&|p| p.block.sets[1].set += 1).is_err());
    // Claim a FEC set beyond the block.
    assert_eq!(
        tamper(&|p| p.block.sets[1].set = count),
        Err(Error::InvalidShred("FEC set outside the block"))
    );
    // Supply the same FEC set twice.
    assert_eq!(
        tamper(&|p| {
            let dup = p.block.sets[0].clone();
            p.block.sets.push(dup);
        }),
        Err(Error::DuplicateShred)
    );
    // Lie about how many FEC sets the block has.
    assert!(tamper(&|p| p.block.parent.fec_set_count += 1).is_err());
    assert!(tamper(&|p| p.block.parent.fec_set_count -= 1).is_err());
    // Lie about the parent.
    assert_eq!(
        tamper(&|p| p.block.parent.parent.id[0] ^= 1),
        Err(Error::BlockIdMismatch)
    );
    // Change one byte of transaction data.
    assert_eq!(
        tamper(&|p| {
            let shred = p.block.sets[1].shreds.last_mut().unwrap();
            shred.body[10] ^= 1;
        }),
        Err(Error::BlockIdMismatch)
    );
    // Swap the chained root.
    assert_eq!(
        tamper(&|p| p.block.sets[1].chained_root[0] ^= 1),
        Err(Error::BlockIdMismatch)
    );
    // Present a coding shred's variant byte.
    assert_eq!(
        tamper(&|p| p.block.sets[1].shreds[0].variant = 0x66),
        Err(Error::InvalidShred("variant"))
    );
    // Drop a sibling, add a sibling.
    assert!(tamper(&|p| {
        p.block.sets[1].siblings.pop();
    })
    .is_err());
    assert!(tamper(&|p| p.block.sets[1].siblings.push([0; 20])).is_err());
    assert!(tamper(&|p| p.block.sets[1].path.push([0; 20])).is_err());
    assert!(tamper(&|p| {
        p.block.sets[1].path.pop();
    })
    .is_err());
}

/// What the proof must contain, it must contain.
#[test]
fn incomplete_proofs_are_refused() {
    let w = world();
    // The last transaction of the large batch: its component spans two FEC sets.
    let signature = signature_for(249);
    let good = w.proof(1, &signature);
    assert_eq!(good.block.sets.len(), 3);
    let tamper = |f: &dyn Fn(&mut TxProof)| {
        let mut proof = good.clone();
        f(&mut proof);
        w.client.verify_transaction(&proof)
    };

    // No header shred: the block might have an abandoned prefix.
    assert_eq!(
        tamper(&|p| {
            p.block.sets.retain(|s| s.set != 0);
        }),
        Err(Error::MissingShred(0))
    );
    // The component is cut short of the transaction.
    assert_eq!(
        tamper(&|p| {
            p.block.sets.pop();
        }),
        Err(Error::Truncated)
    );
    // The component's first shred is missing altogether.
    assert_eq!(
        tamper(&|p| {
            p.block.sets.remove(1);
        }),
        Err(Error::MissingShred(32))
    );
    // The header is not an entry batch.
    assert_eq!(
        tamper(&|p| p.component_start = 0),
        Err(Error::InvalidComponent("not an entry batch"))
    );
    // Positions past the end.
    assert_eq!(
        tamper(&|p| p.position.entry = 99),
        Err(Error::TransactionNotFound)
    );
    // A footer that is not a footer.
    assert_eq!(
        tamper(&|p| p.footer_start = Some(32)),
        Err(Error::InvalidComponent("not a marker"))
    );
    // The proof is for a transaction, just not the one asked about.
    assert_eq!(
        w.client.verify_signature(&good, &signature_for(248)),
        Err(Error::SignatureNotFound)
    );
}

/// The dishonest prover the other tests stand on: `RawBlock` opens any shreds
/// under any claimed parent and checks nothing. Under the true parent it
/// produces exactly the honest proof. Under any other, the block id it
/// commits to is not the one validators certified.
#[test]
fn a_raw_opening_is_honest_only_under_the_true_parent() {
    let w = world();
    let parent = w.blocks[2].block();
    let payloads = BlockBuilder::new(1010, parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![legacy_transaction(77, &[b"raw"])]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    let honest = BlockData::from_shreds(&payloads).unwrap();
    let raw = RawBlock::from_shreds(&payloads).unwrap();
    assert_eq!(raw.block(&parent), honest.block());
    assert_eq!(
        raw.component_starts(),
        honest
            .components()
            .map(|(start, _)| start)
            .collect::<Vec<_>>()
    );

    let cert = w.validators.fast_cert(
        honest.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let proof = prover::prove(cert.clone(), &[&honest], &signature_for(77), false).unwrap();
    let needed: BTreeSet<u32> = [0, 31, 32].into_iter().collect();
    let by_hand = TxProof {
        finality: cert,
        ancestry: vec![],
        block: raw.open(&parent, &needed),
        component_start: 32,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(by_hand, proof);
    assert!(w.client.verify_transaction(&by_hand).is_ok());

    let other = w.blocks[1].block();
    assert_ne!(raw.block(&other), honest.block());
    let lying = TxProof {
        block: raw.open(&other, &needed),
        ..by_hand
    };
    assert_eq!(
        w.client.verify_transaction(&lying),
        Err(Error::BlockIdMismatch)
    );
}

/// The abandoned-prefix attack once more, through the one hole in the rule
/// that stops it.
///
/// A validator refuses an UpdateParent naming the header's own parent, but it
/// treats a header whose parent id is all zeros as no header: it cannot tell
/// that from an id that was never set. So on a block whose parent is a
/// cluster's first block, a leader can switch to the same parent, the tree
/// commits to it, the header agrees, and the prefix is thrown away. The
/// verifier has no way to see the switch, so it proves nothing in any block
/// with such a parent.
#[test]
fn a_zero_parent_id_does_not_hide_an_abandoned_prefix() {
    let w = world();
    let parent = BlockRef {
        slot: 0,
        id: [0; 32],
    };
    let doomed = legacy_transaction(31337, &[b"never executed"]);
    let kept = legacy_transaction(31338, &[b"executed"]);
    let payloads = BlockBuilder::new(4, parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![doomed]]))
        .component(&update_parent_component(&parent))
        .component(&entry_batch(&[vec![kept]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();

    let raw = RawBlock::from_shreds(&payloads).unwrap();
    let cert = w.validators.fast_cert(
        raw.block(&parent),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    assert!(w.client.verify_finality(&cert).is_ok());
    // Header in shred 0, the boundary, and the doomed batch: every path valid,
    // header and tree in agreement.
    let needed: BTreeSet<u32> = [0, 31, 32].into_iter().collect();
    let proof = TxProof {
        finality: cert.clone(),
        ancestry: vec![],
        block: raw.open(&parent, &needed),
        component_start: 32,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&proof),
        Err(Error::ZeroParentId)
    );

    // The price: an honest block on the same parent is refused too, and the
    // honest prover says so rather than build a proof nobody will accept.
    let honest = BlockBuilder::new(4, parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![legacy_transaction(5, &[b"fine"])]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    let data = BlockData::from_shreds(&honest).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    assert_eq!(
        prover::prove(cert, &[&data], &signature_for(5), false).unwrap_err(),
        Error::ZeroParentId
    );
}

/// Every data shred says how many slots back its parent is, and a validator
/// kills a slot whose shreds name a different parent slot than its header.
/// A block whose shreds disagree with the parent it commits to is therefore
/// not a finalized block, whatever else is right about the proof.
#[test]
fn shreds_must_name_the_parent_the_block_commits_to() {
    let w = world();
    let parent = w.blocks[2].block();
    let mut builder = BlockBuilder::new(1010, parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![legacy_transaction(88, &[b"x"])]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]));
    for index in 0..builder.next_index() {
        builder.shred_mut(index).parent_offset += 1;
    }
    let payloads = builder.build();
    let raw = RawBlock::from_shreds(&payloads).unwrap();
    let cert = w.validators.fast_cert(
        raw.block(&parent),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let needed: BTreeSet<u32> = [0, 31, 32].into_iter().collect();
    let proof = TxProof {
        finality: cert,
        ancestry: vec![],
        block: raw.open(&parent, &needed),
        component_start: 32,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&proof),
        Err(Error::InvalidShred(
            "parent offset does not name the block's parent"
        ))
    );
}

// ---------------------------------------------------------------------------
// Ancestry
// ---------------------------------------------------------------------------

/// Finality flows from a block to its ancestors only. A fork that shares the
/// same parent, or a block after the certified one, gains nothing.
#[test]
fn only_real_ancestors_inherit_finality() {
    let w = world();
    let b1 = &w.blocks[0];
    let b2 = &w.blocks[1];
    let b3 = &w.blocks[2];

    // A sibling of block 2: same parent, never finalized.
    let fork_tx = legacy_transaction(6000, &[b"on the losing fork"]);
    let fork = simple_block(
        1001,
        b1.block(),
        SHRED_VERSION,
        &[vec![vec![fork_tx]]],
        None,
    );
    let cert_b3 = w.fast_cert(2);

    // The prover itself refuses a chain that does not connect.
    assert_eq!(
        prover::prove(cert_b3.clone(), &[b3, &fork], &signature_for(6000), false).unwrap_err(),
        Error::BrokenAncestry
    );

    // Hand-built: block 3's real parent link, then the fork's shreds.
    let (block, component_start, position, _) =
        fork.prove_transaction(&signature_for(6000), false).unwrap();
    let forged = TxProof {
        finality: cert_b3.clone(),
        ancestry: vec![b3.parent_link()],
        block,
        component_start,
        position,
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&forged),
        Err(Error::BlockIdMismatch)
    );

    // Hand-built: a link that claims the fork is block 3's parent.
    let mut lying_link = b3.parent_link();
    lying_link.parent = fork.block();
    let mut forged2 = forged.clone();
    forged2.ancestry = vec![lying_link];
    assert_eq!(
        w.client.verify_transaction(&forged2),
        Err(Error::BlockIdMismatch)
    );

    // A certificate for block 1 says nothing about its child.
    let (block, component_start, position, _) =
        b2.prove_transaction(&signature_for(500), false).unwrap();
    let upward = TxProof {
        finality: w.fast_cert(0),
        ancestry: vec![],
        block: block.clone(),
        component_start,
        position,
        footer_start: None,
    };
    // (Caught early: block 2 names block 1 as its parent, and a block cannot
    // be its own parent's slot.)
    assert_eq!(
        w.client.verify_transaction(&upward),
        Err(Error::InvalidParent)
    );

    // Nor can a "parent" be in a later slot than its child.
    let mut backwards = b2.parent_link();
    backwards.parent.slot = b2.block().slot;
    assert_eq!(backwards.verify(&b2.block()), Err(Error::InvalidParent));

    // Skipping a link breaks the chain.
    let chain = [b3, b2, b1];
    let mut skipping = prover::prove(cert_b3, &chain, &signature_for(0), false).unwrap();
    skipping.ancestry.remove(0);
    assert!(w.client.verify_transaction(&skipping).is_err());
}

/// No block has more than 1,024 FEC sets, and validators refuse a parent
/// leaf that claims more. A proof that claims more is refused before any
/// hashing is done on its say-so.
#[test]
fn a_block_cannot_claim_more_fec_sets_than_consensus_allows() {
    let w = world();
    let child = w.blocks[1].block();
    let mut link = w.blocks[1].parent_link();
    assert!(link.verify(&child).is_ok());
    link.fec_set_count = MAX_FEC_SETS_PER_SLOT + 1;
    assert_eq!(
        link.verify(&child),
        Err(Error::LimitExceeded("FEC set count"))
    );
    link.fec_set_count = 0;
    assert_eq!(
        link.verify(&child),
        Err(Error::LimitExceeded("FEC set count"))
    );
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// The decoder is the first thing hostile bytes touch.
#[test]
fn hostile_bytes_never_panic_and_never_over_allocate() {
    let w = world();
    let bytes = w.proof(0, &signature_for(1)).to_bytes();
    let limits = Limits::default();

    // Every prefix.
    for len in 0..bytes.len() {
        assert!(
            TxProof::from_bytes(&bytes[..len], &limits).is_err(),
            "prefix {len}"
        );
    }
    // Trailing garbage.
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        TxProof::from_bytes(&long, &limits),
        Err(Error::TrailingBytes)
    );
    // Wrong magic and version.
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert_eq!(
        TxProof::from_bytes(&bad, &limits),
        Err(Error::Malformed("magic"))
    );
    let mut bad = bytes.clone();
    bad[3] = 2;
    assert_eq!(
        TxProof::from_bytes(&bad, &limits),
        Err(Error::UnsupportedVersion(2))
    );
    // Size limit.
    let tiny = Limits {
        max_proof_bytes: 100,
        ..limits
    };
    assert_eq!(
        TxProof::from_bytes(&bytes, &tiny),
        Err(Error::LimitExceeded("proof size"))
    );
    // Counts that promise more than the input holds.
    let mut pseudo = 0x9e3779b97f4a7c15u64;
    for _ in 0..2_000 {
        let mut noise = b"STP\x01".to_vec();
        for _ in 0..64 {
            pseudo ^= pseudo << 13;
            pseudo ^= pseudo >> 7;
            pseudo ^= pseudo << 17;
            noise.extend_from_slice(&pseudo.to_le_bytes());
        }
        let _ = TxProof::from_bytes(&noise, &limits);
        let _ = w.client.verify_transaction_bytes(&noise);
    }
}

/// Flip every bit of a valid proof, one at a time. Each mutant must either be
/// rejected or still tell the truth: the transaction it returns really is at
/// the position it returns, in the block it returns.
#[test]
fn no_single_bit_flip_produces_a_false_statement() {
    let w = world();
    let data = &w.blocks[0];
    let truth: Vec<(TxPosition, [u8; 64])> = data
        .components()
        .filter(|(start, _)| *start == 32)
        .flat_map(|(_, bytes)| block::transactions(bytes).unwrap())
        .map(|(position, tx)| (position, *tx.signature()))
        .collect();
    assert_eq!(truth.len(), 5);

    let signature = signature_for(3);
    let proof = prover::prove(w.fast_cert(0), &[data], &signature, true).unwrap();
    let bytes = proof.to_bytes();
    let (mut rejected, mut survived) = (0, 0);
    for byte in 0..bytes.len() {
        for bit in 0..8 {
            let mut mutant = bytes.clone();
            mutant[byte] ^= 1 << bit;
            match w.client.verify_transaction_bytes(&mutant) {
                Err(_) => rejected += 1,
                Ok(verified) => {
                    survived += 1;
                    assert_eq!(verified.block, data.block(), "byte {byte} bit {bit}");
                    assert_eq!(verified.component_start, 32);
                    assert!(
                        truth.contains(&(verified.position, *verified.transaction.signature())),
                        "byte {byte} bit {bit} proved a transaction that is not there"
                    );
                }
            }
        }
    }
    // Survivors exist (a flipped position can point at another real
    // transaction; unused bitmap bits are ignored) but they are rare.
    assert!(
        rejected > survived * 50,
        "{rejected} rejected, {survived} survived"
    );
    println!("bit flips: {rejected} rejected, {survived} still true");
}
