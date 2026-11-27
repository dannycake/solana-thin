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

/// Five validators whose stake adds up to 10,000, so that a basis point is
/// one lamport: some subsets land exactly on 60% and 80%, and others one
/// lamport short. Ranks, by stake: 5,999, 2,000, 1,999, 1, 1.
fn lamport_exact() -> (TestValidators, ThinClient) {
    let validators = TestValidators::new(5, |i| [5_999, 1, 1_999, 1, 2_000][i]);
    let set = validators.set();
    let stakes: Vec<u64> = set.validators().iter().map(|v| v.stake).collect();
    assert_eq!(stakes, [5_999, 2_000, 1_999, 1, 1]);
    let mut client = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));
    client
        .trust_validator_set(0, set.clone(), &set.hash())
        .unwrap();
    (validators, client)
}

fn short_of(signed: u64, required_bps: u32) -> Result<Finality> {
    Err(Error::InsufficientStake {
        signed,
        total: 10_000,
        required_bps,
    })
}

/// The thresholds are 80% for a fast certificate and 60% for each half of a
/// slow one, of the pinned stake, and reaching one exactly is enough. One
/// lamport under is not: 79.99% of notarize votes is a block that can still
/// be skipped.
#[test]
fn certificate_thresholds_are_exact_to_the_lamport() {
    let (validators, client) = lamport_exact();
    let block = BlockRef {
        slot: 77,
        id: [0x77; 32],
    };
    let fast = |ranks: &[usize]| {
        client
            .verify_finality(&validators.fast_cert(block, ranks, SHRED_VERSION))
            .map(|finalized| finalized.finality)
    };
    let slow = |notar: &[usize], finalize: &[usize]| {
        client
            .verify_finality(&validators.slow_cert(block, notar, finalize, SHRED_VERSION))
            .map(|finalized| finalized.finality)
    };

    // Fast: 8,000 of 10,000 and not 7,999.
    assert_eq!(fast(&[0, 1, 3]), Ok(Finality::Fast));
    assert_eq!(fast(&[0, 1]), short_of(7_999, 8_000));
    assert_eq!(fast(&[0, 3]), short_of(6_000, 8_000));

    // Slow: 6,000 of 10,000 in each half and not 5,999 in either.
    assert_eq!(slow(&[0, 3], &[0, 4]), Ok(Finality::Slow));
    assert_eq!(slow(&[0], &[0, 4]), short_of(5_999, 6_000));
    assert_eq!(slow(&[0, 3], &[0]), short_of(5_999, 6_000));
}

/// A slow certificate is two aggregates and needs both: 60% notarizing the
/// block, and 60% finalizing its slot. Drop the check on either half and it
/// is a notarization, or a vote about some block or other, dressed as
/// finality.
#[test]
fn a_slow_certificate_needs_both_of_its_halves() {
    let (validators, client) = lamport_exact();
    let block = BlockRef {
        slot: 77,
        id: [0x77; 32],
    };
    let everyone = [0, 1, 2, 3, 4];
    let enough = [0, 3];
    let verdict = |cert: &FinalityCert| {
        client
            .verify_finality(cert)
            .map(|finalized| finalized.finality)
    };
    let good = validators.slow_cert(block, &enough, &enough, SHRED_VERSION);
    assert_eq!(verdict(&good), Ok(Finality::Slow));
    let FinalityCert::Slow {
        finalize, notar, ..
    } = good.clone()
    else {
        unreachable!()
    };
    let with_finalize = |finalize: Aggregate| FinalityCert::Slow {
        block,
        finalize,
        notar: notar.clone(),
    };
    let with_notar = |notar: Aggregate| FinalityCert::Slow {
        block,
        finalize: finalize.clone(),
        notar,
    };

    // The notarize half is fine in all of these. The finalize half is:
    // short of 60%;
    let short = validators.aggregate(&[0], &finalize_payload(block.slot, SHRED_VERSION));
    assert_eq!(verdict(&with_finalize(short)), short_of(5_999, 6_000));
    // signed by everyone, for another slot;
    let other_slot =
        validators.aggregate(&everyone, &finalize_payload(block.slot + 1, SHRED_VERSION));
    assert_eq!(
        verdict(&with_finalize(other_slot)),
        Err(Error::SignatureMismatch)
    );
    // signed by everyone, on another cluster;
    let other_cluster =
        validators.aggregate(&everyone, &finalize_payload(block.slot, SHRED_VERSION + 1));
    assert_eq!(
        verdict(&with_finalize(other_cluster)),
        Err(Error::SignatureMismatch)
    );
    // the notarize aggregate over again;
    assert_eq!(
        verdict(&with_finalize(notar.clone())),
        Err(Error::SignatureMismatch)
    );
    // signed by nobody.
    let nobody = Aggregate {
        signature: finalize.signature,
        bitmap: encode_bitmap(&[]),
    };
    assert_eq!(verdict(&with_finalize(nobody)), Err(Error::NoSigners));

    // And the other way around: everyone finalized the slot, and the block
    // itself has under 60%, or 60% for a different block.
    let good_finalize = with_notar(notar.clone());
    assert_eq!(verdict(&good_finalize), Ok(Finality::Slow));
    let short = validators.aggregate(&[0], &notarize_payload(&block, SHRED_VERSION));
    assert_eq!(verdict(&with_notar(short)), short_of(5_999, 6_000));
    let twin = BlockRef {
        slot: block.slot,
        id: [0x78; 32],
    };
    let for_twin = validators.aggregate(&enough, &notarize_payload(&twin, SHRED_VERSION));
    assert_eq!(
        verdict(&with_notar(for_twin)),
        Err(Error::SignatureMismatch)
    );

    // Sixty percent of notarize votes without the finalize half is a
    // notarization. Presented as a fast certificate it is short of 80%.
    assert_eq!(
        verdict(&FinalityCert::Fast { block, notar }),
        short_of(6_000, 8_000)
    );
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

/// Which validator set judges a certificate follows from the epoch schedule
/// the caller gave. Numbers that are not a schedule a cluster can have used
/// to overflow into some other epoch, and with it some other epoch's
/// validators. They are refused, and nothing is verified with them.
#[test]
fn cluster_parameters_no_cluster_has_verify_nothing() {
    let w = world();
    let set = w.validators.set();
    let signature = signature_for(0);
    let proof = w.proof(0, &signature);
    let refused = |change: &dyn Fn(&mut ClusterParams), why: &'static str| {
        let mut params = ClusterParams::mainnet(SHRED_VERSION);
        change(&mut params);
        assert_eq!(params.validate(), Err(Error::InvalidClusterParams(why)));
        let mut client = ThinClient::new(params);
        // Every epoch these numbers could be taken to mean.
        for epoch in [0, 4, 1_004, u64::MAX] {
            client
                .trust_validator_set(epoch, set.clone(), &set.hash())
                .unwrap();
        }
        assert_eq!(
            client.verify_finality(&w.fast_cert(0)),
            Err(Error::InvalidClusterParams(why))
        );
        assert_eq!(
            client.verify_signature(&proof, &signature),
            Err(Error::InvalidClusterParams(why))
        );
    };
    // One slot per epoch, counted from the last epoch there is: block 1's
    // slot, 1000, wrapped around to epoch 999.
    refused(
        &|p| {
            p.slots_per_epoch = 1;
            p.first_normal_epoch = u64::MAX;
        },
        "slots per epoch",
    );
    refused(&|p| p.slots_per_epoch = 0, "slots per epoch");
    // A first full-length epoch that the epoch length does not lead to.
    refused(&|p| p.first_normal_epoch = u64::MAX, "warm-up schedule");
    refused(&|p| p.first_normal_slot = 524_256, "warm-up schedule");

    // The same proof under the schedule the cluster really has.
    assert!(w.client.verify_signature(&proof, &signature).is_ok());
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

    // Nor can a correctly hashed set displace the one already pinned.
    let poisoned_hash = poisoned.hash();
    assert_eq!(
        w.client
            .trust_validator_set(0, poisoned.clone(), &poisoned_hash),
        Err(Error::EpochAlreadyPinned(0))
    );
    assert!(w.client.verify_finality(&forged).is_err());

    // But a caller who pins whatever a server hands them has lost everything:
    // a certificate "signed" by 100% of stake for a block that does not exist.
    let mut careless = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));
    careless
        .trust_validator_set(0, poisoned, &poisoned_hash)
        .unwrap();
    assert_eq!(careless.verify_finality(&forged).unwrap().block, block);
}

// ---------------------------------------------------------------------------
// Validator-set loading
// ---------------------------------------------------------------------------

/// The encoding of a set of `count` validators whose keys are not curve
/// points at all. Anything that decompresses a key refuses the first one.
fn junk_set_bytes(count: usize) -> Vec<u8> {
    let mut bytes = (count as u32).to_le_bytes().to_vec();
    for i in 0..count {
        bytes.extend_from_slice(&[0xff; 48]);
        bytes.extend_from_slice(&((count - i) as u64).to_le_bytes());
    }
    bytes
}

/// The set hash, taken over an encoded set without decoding it.
fn pin_of(set_bytes: &[u8]) -> Hash {
    merkle::sha256(&[b"solana-thin/validator-set/v1", set_bytes])
}

/// A validator set can be fetched from anywhere, so the bytes are hostile
/// until they match the pin. Checking a key costs a subgroup check; a server
/// that hands out a full-size set of well-formed keys under the wrong hash
/// must not be able to make the client pay for all of them. The pin is
/// compared first, over the bytes, and only bytes that match are decoded.
#[test]
fn a_validator_set_is_compared_with_its_pin_before_any_curve_work() {
    let w = world();
    let mut client = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));

    // Junk keys under a pin they do not hash to: refused for the hash. Had a
    // key been looked at first, the answer would be `InvalidPublicKey`.
    let junk = junk_set_bytes(validator_set::MAX_VALIDATORS);
    assert_eq!(
        client.trust_validator_set_bytes(0, &junk, &[0x42; 32]),
        Err(Error::ValidatorSetHashMismatch)
    );
    // Under their own hash they are decoded, and the keys are what fails.
    assert_eq!(
        client.trust_validator_set_bytes(0, &junk, &pin_of(&junk)),
        Err(Error::InvalidPublicKey)
    );
    // More bytes than the largest set are not hashed either: one validator
    // too many, or the largest set with a single byte after it.
    let oversized = junk_set_bytes(validator_set::MAX_VALIDATORS + 1);
    assert_eq!(
        client.trust_validator_set_bytes(0, &oversized, &pin_of(&oversized)),
        Err(Error::LimitExceeded("validator count"))
    );
    let mut one_byte_over = junk.clone();
    one_byte_over.push(0);
    assert_eq!(
        client.trust_validator_set_bytes(0, &one_byte_over, &pin_of(&one_byte_over)),
        Err(Error::LimitExceeded("validator count"))
    );
    assert!(client.validator_set(0).is_none());
    assert_eq!(
        client.verify_finality(&w.fast_cert(0)),
        Err(Error::UnknownEpoch(0))
    );

    // The real set under the real pin.
    let set = w.validators.set();
    assert_eq!(pin_of(&set.to_bytes()), set.hash());
    client
        .trust_validator_set_bytes(0, &set.to_bytes(), &set.hash())
        .unwrap();
    assert_eq!(client.validator_set(0).unwrap().hash(), set.hash());
    assert!(client.validator_set(1).is_none());
    assert!(client.verify_finality(&w.fast_cert(0)).is_ok());
}

/// The set pinned for an epoch decides every certificate of that epoch. If a
/// later call could swap it, the trust root would be whichever call came
/// last. Pinning the same set again is harmless and does nothing; pinning a
/// different one is refused, however well it hashes to its own pin.
#[test]
fn a_pinned_epoch_cannot_be_given_another_set() {
    let mut w = world();
    let block = w.blocks[0].block();
    let all: Vec<usize> = (0..w.validators.len()).collect();
    let honest = w.validators.set();
    let attackers = TestValidators::with_seed(99, 20, |_| 1_000_000);
    let theirs = attackers.set();
    let forged = attackers.fast_cert(block, &all, SHRED_VERSION);

    // The same set again, by either route.
    assert_eq!(
        w.client
            .trust_validator_set(0, honest.clone(), &honest.hash()),
        Ok(())
    );
    assert_eq!(
        w.client
            .trust_validator_set_bytes(0, &honest.to_bytes(), &honest.hash()),
        Ok(())
    );

    // Another set under its own, correct hash.
    assert_eq!(
        w.client
            .trust_validator_set(0, theirs.clone(), &theirs.hash()),
        Err(Error::EpochAlreadyPinned(0))
    );
    assert_eq!(
        w.client
            .trust_validator_set_bytes(0, &theirs.to_bytes(), &theirs.hash()),
        Err(Error::EpochAlreadyPinned(0))
    );
    // From bytes, that is decided before any key is checked.
    let junk = junk_set_bytes(3);
    assert_eq!(
        w.client.trust_validator_set_bytes(0, &junk, &pin_of(&junk)),
        Err(Error::EpochAlreadyPinned(0))
    );

    // The first set is still the one in force.
    assert_eq!(w.client.validator_set(0).unwrap().hash(), honest.hash());
    assert!(w.client.verify_finality(&w.fast_cert(0)).is_ok());
    assert_eq!(
        w.client.verify_finality(&forged),
        Err(Error::SignatureMismatch)
    );

    // An epoch nothing is pinned for takes whatever it is given first.
    w.client
        .trust_validator_set(1, theirs.clone(), &theirs.hash())
        .unwrap();
    assert_eq!(w.client.validator_set(1).unwrap().hash(), theirs.hash());
}

/// A client that runs for a long time pins a set per epoch and needs to let
/// go of old ones. What it lets go of, it no longer verifies anything with.
#[test]
fn a_forgotten_epoch_verifies_nothing() {
    let w = world();
    let all: Vec<usize> = (0..w.validators.len()).collect();
    let set = w.validators.set();
    let mut client = ThinClient::new(ClusterParams::mainnet(SHRED_VERSION));
    for epoch in [0, 1, 2, 5] {
        client
            .trust_validator_set(epoch, set.clone(), &set.hash())
            .unwrap();
    }
    assert_eq!(client.pinned_epochs().collect::<Vec<_>>(), [0, 1, 2, 5]);
    let verdict = |client: &ThinClient, epoch: u64| {
        let block = BlockRef {
            slot: 432_000 * epoch + 7,
            id: [epoch as u8; 32],
        };
        client
            .verify_finality(&w.validators.fast_cert(block, &all, SHRED_VERSION))
            .map(|finalized| finalized.block)
    };
    for epoch in [0, 1, 2, 5] {
        assert!(verdict(&client, epoch).is_ok());
    }

    // Everything before epoch 2 goes; epoch 2 itself stays.
    assert_eq!(client.forget_epochs_before(2), 2);
    assert_eq!(client.pinned_epochs().collect::<Vec<_>>(), [2, 5]);
    assert_eq!(verdict(&client, 0), Err(Error::UnknownEpoch(0)));
    assert_eq!(verdict(&client, 1), Err(Error::UnknownEpoch(1)));
    assert!(verdict(&client, 2).is_ok());
    assert!(verdict(&client, 5).is_ok());
    assert_eq!(client.forget_epochs_before(2), 0);

    // One epoch on its own.
    let forgotten = client.forget_validator_set(5).expect("epoch 5 was pinned");
    assert_eq!(forgotten.hash(), set.hash());
    assert!(client.forget_validator_set(5).is_none());
    assert_eq!(verdict(&client, 5), Err(Error::UnknownEpoch(5)));
    assert!(verdict(&client, 2).is_ok());

    // Forgetting is also the only way to change an epoch's set.
    let other = TestValidators::with_seed(99, 20, |_| 1_000_000).set();
    client
        .trust_validator_set(5, other.clone(), &other.hash())
        .unwrap();
    assert_eq!(client.validator_set(5).unwrap().hash(), other.hash());
    assert_eq!(verdict(&client, 5), Err(Error::SignatureMismatch));
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
    assert_eq!(naive.signature(), Some(&victim_signature));

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
        assert_ne!(verified.transaction.signature(), Some(&victim_signature));
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

/// With fast leader handover a block may start on one parent and then switch
/// with an UpdateParent marker. The verifier cannot prove which part of such a
/// block ran, so it refuses the block; a transaction in the discarded part
/// must not verify, even though its bytes sit in a real batch at a real
/// boundary.
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

    // Without fast leader handover an honest prover will not touch the block;
    // with it, the prover indexes the block to prove its executed suffix, on
    // the parent the block ended on.
    #[cfg(not(feature = "fast-leader-handover"))]
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap_err(),
        Error::UpdateParentBlock
    );
    #[cfg(feature = "fast-leader-handover")]
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap().parent(),
        final_parent
    );

    // A dishonest prover indexes it with the parent the block ended on, which
    // is the parent its id commits to, and so the id validators certified.
    let data = BlockData::from_shreds_with_final_parent(&payloads, final_parent).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    assert!(w.client.verify_finality(&cert).is_ok());
    let prove = |seed| prover::prove(cert.clone(), &[&data], &signature_for(seed), false).unwrap();

    // Without the feature the verifier refuses the whole switched block,
    // whichever part of it the claim names: the header names a parent the
    // block id does not, and that is as far as it reads.
    #[cfg(not(feature = "fast-leader-handover"))]
    for seed in [31337, 31338] {
        assert_eq!(
            w.client.verify_transaction(&prove(seed)),
            Err(Error::UpdateParentBlock)
        );
    }

    // With the feature the abandoned-prefix transaction is still refused, and
    // the executed-suffix one proves, reported on the parent the block ended on.
    #[cfg(feature = "fast-leader-handover")]
    {
        assert_eq!(
            w.client.verify_transaction(&prove(31337)),
            Err(Error::AbandonedPrefix)
        );
        let verified = w.client.verify_transaction(&prove(31338)).unwrap();
        assert_eq!(verified.block, data.block());
        assert_eq!(verified.parent, final_parent);
        assert_eq!(verified.component_start, 96);
        assert!(verified.has_memo(b"executed"));
    }
}

/// The same shape with the header split across shreds.
///
/// The verifier mirrors Agave's rule that an UpdateParent must not name the
/// header's own parent, which is why "header parent equals tree parent" can
/// stand for "no switch happened". That rule stands on the header being read
/// from shred 0 alone. Spread the header over shreds 0 and 1 and a verifier
/// that read it from the whole first component would see header and tree agree
/// on a block whose prefix was abandoned, and accept a transaction that never
/// ran. The verifier reads the header from shred 0 alone and refuses the block.
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

    // An honest prover finds no header where a validator would look, and
    // refuses the block: without the feature for the switch it does see, with
    // it for the missing header the switch must be checked against. Only a
    // dishonest prover gets further, and the verifier below refuses it.
    #[cfg(not(feature = "fast-leader-handover"))]
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap_err(),
        Error::UpdateParentBlock
    );
    #[cfg(feature = "fast-leader-handover")]
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap_err(),
        Error::InvalidComponent("block does not start with a header")
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

    // Open the header's two shreds, the boundary before the doomed batch, and
    // the batch itself. Every Merkle path is valid.
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
        w.client
            .verify_transaction_bytes(&proof.to_bytes().unwrap()),
        Err(Error::InvalidComponent(
            "block does not start with a header"
        ))
    );
}

// ---------------------------------------------------------------------------
// Fast leader handover (feature `fast-leader-handover`)
// ---------------------------------------------------------------------------
//
// With the feature on, the verifier proves a transaction in the executed
// suffix of a block that switched parent mid-way, and keeps refusing the
// abandoned prefix. These tests build each shape that must be refused and the
// one that must be accepted. The differential oracle (`tools/agave-fixtures`)
// is the real acceptance gate; these pin the behavior with no Agave in the
// build.

/// The whole point of the feature: a transaction after the `UpdateParent`
/// marker proves, on the parent the block ended on, and one before it does not.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_transaction_in_the_executed_suffix_proves() {
    let w = world();
    let header_parent = w.blocks[2].block(); // H, slot 1003
    let final_parent = w.blocks[1].block(); // P, slot 1002
    let prefix = vec![vec![vec![legacy_transaction(1, &[b"doomed"])]]];
    let suffix = vec![vec![vec![
        legacy_transaction(2, &[b"kept-a"]),
        legacy_transaction(3, &[b"kept-b"]),
    ]]];
    // slot 1004 is first in its leader window (1004 % 4 == 0).
    let block = update_parent_block(
        1004,
        header_parent,
        final_parent,
        SHRED_VERSION,
        &prefix,
        &suffix,
        None,
    );
    assert_eq!(block.parent(), final_parent);
    let cert = w.validators.fast_cert(
        block.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );

    // Every executed-suffix transaction proves, with its footer, on P.
    for (seed, memo) in [(2u64, &b"kept-a"[..]), (3, &b"kept-b"[..])] {
        let proof = prover::prove(cert.clone(), &[&block], &signature_for(seed), true).unwrap();
        let verified = w.client.verify_transaction(&proof).unwrap();
        assert_eq!(verified.block, block.block());
        assert_eq!(verified.parent, final_parent);
        assert_eq!(verified.component_start, 96);
        assert!(verified.has_memo(memo));
        // The footer that rode along is the one in the executed suffix.
        assert!(verified.footer.is_some());
    }

    // The abandoned-prefix transaction, proved over the same block, is refused.
    let prefix_proof = prover::prove(cert.clone(), &[&block], &signature_for(1), false).unwrap();
    assert_eq!(
        w.client.verify_transaction(&prefix_proof),
        Err(Error::AbandonedPrefix)
    );

    // And a prefix claim that also opens the marker, to pass the switch check
    // only to be caught at the component, is refused all the same.
    let needed: BTreeSet<u32> = [0, 31, 32, 63, 64].into_iter().collect();
    let prefix_claim = TxProof {
        finality: cert,
        ancestry: vec![],
        block: block.open(&needed),
        component_start: 32,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&prefix_claim),
        Err(Error::AbandonedPrefix)
    );
}

/// A small switch block and a certificate for it, for the refusal tests. The
/// suffix transaction has signature `signature_for(2)`.
#[cfg(feature = "fast-leader-handover")]
fn switched_in(
    w: &World,
    slot: u64,
    header_parent: BlockRef,
    final_parent: BlockRef,
) -> (BlockData, FinalityCert) {
    let prefix = vec![vec![vec![legacy_transaction(1, &[b"doomed"])]]];
    let suffix = vec![vec![vec![legacy_transaction(2, &[b"kept"])]]];
    let block = update_parent_block(
        slot,
        header_parent,
        final_parent,
        SHRED_VERSION,
        &prefix,
        &suffix,
        None,
    );
    let cert = w.validators.fast_cert(
        block.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    (block, cert)
}

/// A suffix proof, whichever shape the block is.
#[cfg(feature = "fast-leader-handover")]
fn suffix_proof(block: &BlockData, cert: &FinalityCert) -> TxProof {
    prover::prove(cert.clone(), &[block], &signature_for(2), false).unwrap()
}

/// A switch is legal only in the first slot of a leader window, so a verifier
/// refuses one whose slot is not a multiple of four.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_switch_outside_the_first_slot_of_a_window_is_refused() {
    let w = world();
    // 1005 % 4 == 1: not the first slot of a window.
    let (block, cert) = switched_in(&w, 1005, w.blocks[2].block(), w.blocks[1].block());
    assert_eq!(
        w.client.verify_transaction(&suffix_proof(&block, &cert)),
        Err(Error::UpdateParentBlock)
    );
    // Nor does the honest prover index such a block, which Agave refuses to
    // keep (`UpdateParentNotFirstInLeaderWindow`).
    let payloads = BlockBuilder::new(1005, w.blocks[2].block(), SHRED_VERSION)
        .header()
        .component(&update_parent_component(&w.blocks[1].block()))
        .component(&entry_batch(&[vec![legacy_transaction(2, &[b"x"])]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    assert_eq!(
        BlockData::from_shreds(&payloads).unwrap_err(),
        Error::UpdateParentBlock
    );
}

/// The parent the block commits to must be a real block: a switch onto a
/// zero (genesis) id cannot be told from no switch at all, so it is refused.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_switch_onto_a_zero_parent_id_is_refused() {
    let w = world();
    let genesis = BlockRef {
        slot: 0,
        id: [0; 32],
    };
    let (block, cert) = switched_in(&w, 1004, w.blocks[2].block(), genesis);
    // The honest prover will not even build a proof for a zero-parent block.
    assert_eq!(
        prover::prove(cert.clone(), &[&block], &signature_for(2), false).unwrap_err(),
        Error::ZeroParentId
    );
    // A dishonest prover that opens the suffix and the marker anyway is still
    // refused: the switch onto a zero parent cannot be told from none.
    let needed: BTreeSet<u32> = [0, 63, 64, 95, 96].into_iter().collect();
    let proof = TxProof {
        finality: cert,
        ancestry: vec![],
        block: block.open(&needed),
        component_start: 96,
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
}

/// A switch may only move replay to an older parent: one naming a newer slot
/// than the header's parent is refused.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_switch_to_a_newer_parent_slot_is_refused() {
    let w = world();
    // Header on slot 1002, marker to slot 1003: forward, not back.
    let (block, cert) = switched_in(&w, 1004, w.blocks[1].block(), w.blocks[2].block());
    assert_eq!(
        w.client.verify_transaction(&suffix_proof(&block, &cert)),
        Err(Error::UpdateParentBlock)
    );
}

/// The opened marker must name the parent the block's id commits to. A block
/// whose marker names a third parent is not the block the certificate is for.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_marker_that_names_another_parent_is_refused() {
    let w = world();
    let header_parent = w.blocks[2].block();
    let marker_names = w.blocks[0].block(); // slot 1000
    let committed = w.blocks[1].block(); // slot 1002, what the id commits to
    let payloads = BlockBuilder::new(1004, header_parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![legacy_transaction(1, &[b"doomed"])]]))
        .component(&update_parent_component(&marker_names))
        .component(&entry_batch(&[vec![legacy_transaction(2, &[b"kept"])]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    let block = BlockData::from_shreds_with_final_parent(&payloads, committed).unwrap();
    let cert = w.validators.fast_cert(
        block.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    assert_eq!(
        w.client.verify_transaction(&suffix_proof(&block, &cert)),
        Err(Error::UpdateParentBlock)
    );
}

/// A suffix proof that does not open the marker cannot establish the switch,
/// so the verifier cannot tell the suffix from an abandoned prefix and refuses.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_switch_proof_without_the_marker_is_refused() {
    let w = world();
    let (block, cert) = switched_in(&w, 1004, w.blocks[2].block(), w.blocks[1].block());
    // The suffix component (96) and the shred before it, but not the marker (64).
    let needed: BTreeSet<u32> = [0, 95, 96].into_iter().collect();
    let proof = TxProof {
        finality: cert,
        ancestry: vec![],
        block: block.open(&needed),
        component_start: 96,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: None,
    };
    assert_eq!(
        w.client.verify_transaction(&proof),
        Err(Error::UpdateParentBlock)
    );
}

/// A footer in the abandoned prefix never ran; a suffix proof that points its
/// footer at one is refused, even though the transaction itself is in the suffix.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_footer_in_the_abandoned_prefix_is_refused() {
    let w = world();
    let header_parent = w.blocks[2].block();
    let final_parent = w.blocks[1].block();
    let payloads = BlockBuilder::new(1004, header_parent, SHRED_VERSION)
        .header() // component 0
        .component(&entry_batch(&[vec![legacy_transaction(1, &[b"doomed"])]])) // 32
        .component(&footer_component([0xde; 32], 7, b"decoy", None)) // 64, decoy footer
        .component(&update_parent_component(&final_parent)) // 96, marker (u = 96)
        .component(&entry_batch(&[vec![legacy_transaction(2, &[b"kept"])]])) // 128
        .component(&footer_component([0; 32], 1, b"", None)) // 160, real footer
        .component(&entry_batch(&[vec![]])) // 192, tick
        .build();
    let block = BlockData::from_shreds_with_final_parent(&payloads, final_parent).unwrap();
    let cert = w.validators.fast_cert(
        block.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );

    // The suffix transaction alone proves, carrying the real (suffix) footer.
    let honest = prover::prove(cert.clone(), &[&block], &signature_for(2), true).unwrap();
    let verified = w.client.verify_transaction(&honest).unwrap();
    assert_eq!(verified.footer.as_ref().unwrap().bank_hash, [0; 32]);

    // Point the same suffix claim at the decoy footer in the prefix: refused.
    let needed: BTreeSet<u32> = [0, 63, 64, 95, 96, 127, 128].into_iter().collect();
    let decoy = TxProof {
        finality: cert,
        ancestry: vec![],
        block: block.open(&needed),
        component_start: 128,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: Some(64),
    };
    assert_eq!(
        w.client.verify_transaction(&decoy),
        Err(Error::AbandonedPrefix)
    );
}

/// `marker` cut across the first two shreds of one FEC set (20 bytes, then the
/// rest), padded out to the end of the set, its last shred `DATA_COMPLETE`.
#[cfg(feature = "fast-leader-handover")]
fn split_marker(builder: BlockBuilder, marker: &[u8]) -> BlockBuilder {
    let mut shreds = vec![builder.shred(&marker[..20]), builder.shred(&marker[20..])];
    for _ in 2..32 {
        shreds.push(builder.shred(&[]));
    }
    shreds.last_mut().unwrap().flags |= FLAG_DATA_COMPLETE;
    builder.push_shreds(shreds)
}

/// A block with a decoy UpdateParent cut across shreds 64 and 65, and a real
/// one whole in shred 128 (or later, with `between`):
///
/// ```text
///   0 header (slot 1003)     96 batch [doomed]   128 UpdateParent, whole
///  32 batch [prefix]        (between)            160 batch [kept]
///  64 UpdateParent, split                        192 footer, 224 tick
/// ```
///
/// A validator's blockstore reads a marker from the first shred of its FEC
/// set alone, so it sees only the real marker and replays from there.
#[cfg(feature = "fast-leader-handover")]
fn split_decoy_block(w: &World, between: Option<Vec<u8>>) -> (Vec<Vec<u8>>, BlockRef) {
    let header_parent = w.blocks[2].block();
    let final_parent = w.blocks[1].block();
    let mut b = BlockBuilder::new(1004, header_parent, SHRED_VERSION)
        .header()
        .component(&entry_batch(&[vec![legacy_transaction(1, &[b"prefix"])]]));
    b = split_marker(b, &update_parent_component(&final_parent));
    b = b.component(&entry_batch(&[vec![legacy_transaction(2, &[b"doomed"])]]));
    if let Some(extra) = between {
        b = b.component(&extra);
    }
    let payloads = b
        .component(&update_parent_component(&final_parent))
        .component(&entry_batch(&[vec![legacy_transaction(3, &[b"kept"])]]))
        .component(&footer_component([0; 32], 1, b"", None))
        .component(&entry_batch(&[vec![]]))
        .build();
    (payloads, final_parent)
}

#[cfg(feature = "fast-leader-handover")]
fn first_transaction(
    cert: FinalityCert,
    block: BlockProof,
    start: u32,
    footer: Option<u32>,
) -> TxProof {
    TxProof {
        finality: cert,
        ancestry: vec![],
        block,
        component_start: start,
        position: TxPosition {
            entry: 0,
            transaction: 0,
        },
        footer_start: footer,
    }
}

/// An UpdateParent cut across two shreds is no marker to a validator, which
/// reads one from a single shred. Read across shreds, it would be a switch
/// point earlier than the real one, and a transaction between the two, never
/// executed, would be in the "suffix". The verifier reads a marker from its
/// shred alone: shown only the split one, it finds no marker; shown the real
/// one too, it places the claim in the abandoned prefix.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_marker_split_across_shreds_is_not_a_switch_point() {
    let w = world();
    let (payloads, final_parent) = split_decoy_block(&w, None);
    let data = BlockData::from_shreds_with_final_parent(&payloads, final_parent).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let claim = |needed: &[u32]| {
        let needed: BTreeSet<u32> = needed.iter().copied().collect();
        first_transaction(cert.clone(), data.open(&needed), 96, None)
    };
    // The header, the split marker, and the doomed batch after it.
    assert_eq!(
        w.client
            .verify_transaction(&claim(&[0, 63, 64, 65, 95, 96])),
        Err(Error::UpdateParentBlock)
    );
    // And the real marker.
    assert_eq!(
        w.client
            .verify_transaction(&claim(&[0, 63, 64, 65, 95, 96, 127, 128])),
        Err(Error::AbandonedPrefix)
    );
}

/// The same split marker, with a footer between it and the real marker. A
/// verifier that took the split marker for the switch point would report that
/// footer, which never ran, as the block's.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_footer_after_a_split_marker_is_not_the_blocks_footer() {
    let w = world();
    let decoy = footer_component([0xde; 32], 7, b"decoy", None);
    // 0 header, 32 prefix, 64 split marker, 96 doomed, 128 decoy footer,
    // 160 real marker, 192 kept, 224 footer, 256 tick.
    let (payloads, final_parent) = split_decoy_block(&w, Some(decoy));
    let data = BlockData::from_shreds_with_final_parent(&payloads, final_parent).unwrap();
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let claim = |needed: &[u32]| {
        let needed: BTreeSet<u32> = needed.iter().copied().collect();
        first_transaction(cert.clone(), data.open(&needed), 192, Some(128))
    };
    assert_eq!(
        w.client
            .verify_transaction(&claim(&[0, 63, 64, 65, 95, 127, 128, 191, 192])),
        Err(Error::UpdateParentBlock)
    );
    assert_eq!(
        w.client
            .verify_transaction(&claim(&[0, 63, 64, 65, 127, 128, 159, 160, 191, 192])),
        Err(Error::AbandonedPrefix)
    );
}

/// The block a validator keeps, the honest prover keeps too: it reads markers
/// as the blockstore does, finds the one real switch, and proves what ran.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_block_with_a_split_marker_proves_its_executed_suffix() {
    let w = world();
    let (payloads, final_parent) = split_decoy_block(&w, None);
    let data = BlockData::from_shreds(&payloads).unwrap();
    assert_eq!(data.parent(), final_parent);
    let cert = w.validators.fast_cert(
        data.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let proof = prover::prove(cert.clone(), &[&data], &signature_for(3), true).unwrap();
    let verified = w.client.verify_transaction(&proof).unwrap();
    assert!(verified.has_memo(b"kept"));
    assert_eq!(verified.parent, final_parent);
    // Every shred opened: the claim still proves, and the doomed one does not.
    let everything: BTreeSet<u32> = (0..data.shred_count()).collect();
    assert!(w
        .client
        .verify_transaction(&first_transaction(
            cert.clone(),
            data.open(&everything),
            160,
            None
        ))
        .is_ok());
    assert_eq!(
        w.client
            .verify_transaction(&first_transaction(cert, data.open(&everything), 96, None)),
        Err(Error::AbandonedPrefix)
    );
}

/// A leader that switches parent will usually put the abandoned transactions
/// back in the suffix, so one signature can be in a switched block twice. The
/// honest prover proves the copy that ran, and lists only what ran.
#[cfg(feature = "fast-leader-handover")]
#[test]
fn a_transaction_repeated_after_the_switch_proves_where_it_ran() {
    let w = world();
    let repeated = legacy_transaction(42, &[b"rebroadcast"]);
    let abandoned = legacy_transaction(43, &[b"abandoned"]);
    let block = update_parent_block(
        1004,
        w.blocks[2].block(),
        w.blocks[1].block(),
        SHRED_VERSION,
        &[vec![vec![repeated.clone(), abandoned]]],
        &[vec![vec![repeated]]],
        None,
    );
    let cert = w.validators.fast_cert(
        block.block(),
        &w.validators.ranks_reaching(8_000),
        SHRED_VERSION,
    );
    let proof = prover::prove(cert, &[&block], &signature_for(42), true).unwrap();
    let verified = w.client.verify_transaction(&proof).unwrap();
    assert!(verified.has_memo(b"rebroadcast"));
    assert_eq!(block.signatures(), vec![signature_for(42)]);
    // One only in the abandoned prefix is proven nowhere.
    assert_eq!(
        w.client.verify_transaction(
            &prover::prove(proof.finality, &[&block], &signature_for(43), true).unwrap()
        ),
        Err(Error::AbandonedPrefix)
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

/// A run of opened shreds lies inside one FEC set: at least one shred, and
/// none past the thirty-second. The run that ends exactly on the last shred
/// is a real one.
#[test]
fn a_run_of_shreds_stays_inside_its_fec_set() {
    let w = world();
    // The last transaction of the large batch: one of its FEC sets is opened
    // whole, another only in part.
    let good = w.proof(1, &signature_for(249));
    assert!(w.client.verify_transaction(&good).is_ok());
    let whole = good
        .block
        .sets
        .iter()
        .position(|set| set.first == 0 && set.shreds.len() == 32)
        .expect("a FEC set opened whole");
    let partial = good
        .block
        .sets
        .iter()
        .position(|set| set.shreds.len() < 31)
        .expect("a FEC set opened in part");
    let outside = Err(Error::InvalidShred("run outside its FEC set"));
    let tamper = |f: &dyn Fn(&mut TxProof)| {
        let mut proof = good.clone();
        f(&mut proof);
        w.client.verify_transaction(&proof).map(|_| ())
    };

    // No shreds at all.
    assert_eq!(tamper(&|p| p.block.sets[partial].shreds.clear()), outside);
    assert_eq!(
        tamper(&|p| {
            p.block.sets[partial].shreds.clear();
            p.block.sets[partial].first = 31;
        }),
        outside
    );
    // All thirty-two, claimed to start at the second position.
    assert_eq!(tamper(&|p| p.block.sets[whole].first = 1), outside);
    // A shorter run slid until its last shred is one past the end.
    let len = good.block.sets[partial].shreds.len() as u8;
    assert_eq!(
        tamper(&|p| p.block.sets[partial].first = 32 - len + 1),
        outside
    );
    // Slid to end exactly on the last shred it is inside the set, and is
    // refused for what it is: shreds that are not at that position.
    let moved = tamper(&|p| p.block.sets[partial].first = 32 - len);
    assert!(moved.is_err());
    assert_ne!(moved, outside);
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

    // No header shred: the verifier cannot show the block ran from its start.
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

/// The abandoned-prefix shape once more, through the one hole in the rule
/// that stops it.
///
/// The rule that an UpdateParent must not name the header's own parent cannot
/// stand on a header whose parent id is all zeros: that id reads the same as
/// one that was never set. On a block built on a cluster's first block the
/// verifier thus cannot tell a parent switch from none, so it proves nothing
/// in any block with such a parent.
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

    // The price: an honest block built on a cluster's first block is refused
    // too, and the honest prover says so rather than build a proof nobody will
    // accept.
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
    let mut backward = b2.parent_link();
    backward.parent.slot = b2.block().slot;
    assert_eq!(backward.verify(&b2.block()), Err(Error::InvalidParent));

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

    // The limit itself is a block that can exist. Build the tree of a block
    // with exactly that many FEC sets, and of one with one more: both parent
    // links are honest, and only the count separates them.
    let link_of = |fec_set_count: u32| {
        let parent = BlockRef {
            slot: 5,
            id: [5; 32],
        };
        let mut leaves: Vec<Hash> = (0..fec_set_count)
            .map(|set| merkle::sha256(&[b"FEC set root", &set.to_le_bytes()]))
            .collect();
        leaves.push(merkle::sha256(&[
            &parent.slot.to_le_bytes(),
            &parent.id,
            &fec_set_count.to_le_bytes(),
        ]));
        let tree = merkle::Tree::new(leaves);
        let child = BlockRef {
            slot: 6,
            id: tree.root(),
        };
        let link = ParentLink {
            parent,
            fec_set_count,
            path: tree.path(fec_set_count as usize),
        };
        link.verify(&child)
    };
    assert_eq!(MAX_FEC_SETS_PER_SLOT, 1024);
    assert_eq!(link_of(1), Ok(()));
    assert_eq!(link_of(1023), Ok(()));
    assert_eq!(link_of(1024), Ok(()));
    assert_eq!(link_of(1025), Err(Error::LimitExceeded("FEC set count")));
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// The decoder is the first thing hostile bytes touch.
#[test]
fn hostile_bytes_never_panic_and_never_over_allocate() {
    let w = world();
    let bytes = w.proof(0, &signature_for(1)).to_bytes().unwrap();
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
    let tiny = limits.with_max_proof_bytes(100);
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

/// A client's limits are its own, whatever route a proof takes to it. The
/// documented route decodes the bytes and hands over the decoded proof; a
/// limit that only the all-in-one route applied would be no limit there.
/// Each limit is exact: a proof right on it passes, one past it does not.
#[test]
fn the_clients_limits_apply_however_a_proof_arrives() {
    let mut w = world();
    // Until told otherwise: 8 MiB and 4,096 links.
    assert_eq!(w.client.limits(), &Limits::default());
    assert_eq!(
        (
            Limits::default().max_proof_bytes,
            Limits::default().max_ancestry
        ),
        (8_388_608, 4_096)
    );
    let signature = signature_for(0);
    let chain = [&w.blocks[2], &w.blocks[1], &w.blocks[0]];
    let proof = prover::prove(w.fast_cert(2), &chain, &signature, false).unwrap();
    let bytes = proof.to_bytes().unwrap();
    assert_eq!(proof.ancestry.len(), 2);
    assert_eq!(proof.encoded_len(), Ok(bytes.len()));
    assert!(bytes.len() > 1024);

    // By every route: the decoded proof, the same with a signature to match,
    // the bytes in one call, and the bytes decoded under the client's limits.
    let verdicts = |client: &ThinClient| {
        [
            client.verify_transaction(&proof).map(|_| ()),
            client.verify_signature(&proof, &signature).map(|_| ()),
            client.verify_transaction_bytes(&bytes).map(|_| ()),
            TxProof::from_bytes(&bytes, client.limits()).map(|_| ()),
        ]
    };
    let size = Err(Error::LimitExceeded("proof size"));
    let ancestry = Err(Error::LimitExceeded("ancestry length"));
    for (max_proof_bytes, max_ancestry, verdict) in [
        (bytes.len(), 2, Ok(())),
        (bytes.len() - 1, 2, size.clone()),
        (bytes.len(), 1, ancestry.clone()),
        (usize::MAX, 0, ancestry),
        (0, usize::MAX, size.clone()),
        (1024, 0, size),
    ] {
        let limits = Limits::default()
            .with_max_proof_bytes(max_proof_bytes)
            .with_max_ancestry(max_ancestry);
        assert_eq!(
            (limits.max_proof_bytes, limits.max_ancestry),
            (max_proof_bytes, max_ancestry)
        );
        w.client.set_limits(limits);
        assert_eq!(w.client.limits(), &limits);
        assert_eq!(
            verdicts(&w.client),
            [(); 4].map(|_| verdict.clone()),
            "{max_proof_bytes} bytes, {max_ancestry} links"
        );
    }

    // A proof that could not be written down has no size to compare, and is
    // refused for that.
    w.client.set_limits(
        Limits::default()
            .with_max_proof_bytes(usize::MAX)
            .with_max_ancestry(usize::MAX),
    );
    let mut unwritable = proof.clone();
    unwritable.block.parent.path = vec![[0; 20]; 256];
    assert_eq!(
        unwritable.encoded_len(),
        Err(Error::TooLargeToEncode("Merkle path"))
    );
    assert_eq!(
        w.client.verify_transaction(&unwritable),
        Err(Error::TooLargeToEncode("Merkle path"))
    );
}

/// The format carries its counts in one or two bytes. A proof built in memory
/// can hold more than that, and writing the count modulo 256 or 65,536 would
/// produce bytes that decode to a different proof. Such a proof is not
/// encoded at all; at the largest count that fits, it round-trips.
#[test]
fn a_proof_too_large_for_the_format_is_not_encoded() {
    let w = world();
    let good = w.proof(0, &signature_for(3));
    let limits = Limits::default()
        .with_max_proof_bytes(usize::MAX)
        .with_max_ancestry(usize::MAX);

    // (what is too long, the largest count that fits, how to make it that long)
    type Grow = fn(&mut TxProof, usize);
    let cases: [(&str, usize, Grow); 8] = [
        ("ancestry length", 65_535, |p, n| {
            p.ancestry = vec![p.block.parent.clone(); n]
        }),
        ("FEC set count", 65_535, |p, n| {
            p.block.sets = vec![p.block.sets[0].clone(); n]
        }),
        ("shred count", 255, |p, n| {
            let shred = p.block.sets[0].shreds[0].clone();
            p.block.sets[0].shreds = vec![shred; n]
        }),
        ("shred body", 65_535, |p, n| {
            p.block.sets[0].shreds[0].body = vec![1; n]
        }),
        ("Merkle path", 255, |p, n| {
            p.block.sets[0].siblings = vec![[0; 20]; n]
        }),
        ("Merkle path", 255, |p, n| {
            p.block.sets[0].path = vec![[0; 20]; n]
        }),
        ("Merkle path", 255, |p, n| {
            p.block.parent.path = vec![[0; 20]; n]
        }),
        ("signer bitmap", 65_535, |p, n| {
            let FinalityCert::Fast { notar, .. } = &mut p.finality else {
                unreachable!()
            };
            notar.bitmap = vec![0; n]
        }),
    ];
    for (what, most, grow) in cases {
        let mut proof = good.clone();
        grow(&mut proof, most + 1);
        assert_eq!(
            proof.to_bytes(),
            Err(Error::TooLargeToEncode(what)),
            "{what}"
        );

        let mut proof = good.clone();
        grow(&mut proof, most);
        let bytes = proof.to_bytes().unwrap();
        match TxProof::from_bytes(&bytes, &limits) {
            Ok(decoded) => assert_eq!(decoded, proof, "{what}"),
            // More shreds than a FEC set holds: written faithfully, and
            // refused on the way back in.
            Err(error) => assert_eq!((what, error), ("shred count", Error::Malformed(what))),
        }
    }

    // Both aggregates of a slow certificate.
    let block = w.blocks[0].block();
    let all: Vec<usize> = (0..w.validators.len()).collect();
    for half in 0..2 {
        let mut proof = good.clone();
        proof.finality = w.validators.slow_cert(block, &all, &all, SHRED_VERSION);
        let FinalityCert::Slow {
            finalize, notar, ..
        } = &mut proof.finality
        else {
            unreachable!()
        };
        [finalize, notar][half].bitmap = vec![0; 65_536];
        assert_eq!(
            proof.to_bytes(),
            Err(Error::TooLargeToEncode("signer bitmap"))
        );
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
        .map(|(position, tx)| (position, *tx.signature().unwrap()))
        .collect();
    assert_eq!(truth.len(), 5);

    let signature = signature_for(3);
    let proof = prover::prove(w.fast_cert(0), &[data], &signature, true).unwrap();
    let bytes = proof.to_bytes().unwrap();
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
                        truth.contains(&(
                            verified.position,
                            *verified.transaction.signature().unwrap()
                        )),
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

/// A certificate passed around on its own reads back as itself, and only as
/// itself: one byte more or less, or an unknown kind, is refused.
#[test]
fn a_certificate_alone_has_one_encoding() {
    let tv = TestValidators::new(4, |i| 10 + i as u64);
    let block = BlockRef {
        slot: 77,
        id: [3; 32],
    };
    let fast = tv.fast_cert(block, &[0, 1, 2, 3], 1);
    let slow = tv.slow_cert(block, &[0, 1, 2], &[1, 2, 3], 1);
    for cert in [fast, slow] {
        let bytes = cert.to_bytes().unwrap();
        assert_eq!(FinalityCert::from_bytes(&bytes), Ok(cert.clone()));
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(FinalityCert::from_bytes(&long), Err(Error::TrailingBytes));
        assert_eq!(
            FinalityCert::from_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        );
        let mut kind = bytes.clone();
        kind[0] = 2;
        assert_eq!(
            FinalityCert::from_bytes(&kind),
            Err(Error::Malformed("certificate kind"))
        );
    }
}
