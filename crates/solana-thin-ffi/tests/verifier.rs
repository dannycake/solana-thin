//! The binding as a foreign caller drives it: bytes in, records and typed
//! errors out, against a real mainnet block.

mod common;

use common::{vector, Vector};
use solana_thin::ValidatorSet;
use solana_thin_ffi::{Finality, Verifier, VerifyError};
use std::sync::{Arc, OnceLock};

fn mainnet() -> &'static Vector {
    static VECTOR: OnceLock<Vector> = OnceLock::new();
    VECTOR.get_or_init(vector)
}

/// A mainnet verifier with the block's epoch pinned.
fn pinned(v: &Vector) -> Arc<Verifier> {
    let verifier = Verifier::mainnet(v.shred_version);
    verifier
        .pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    verifier
}

/// The same set without its last validator: a valid set with another hash.
fn another_set(v: &Vector) -> (Vec<u8>, Vec<u8>) {
    let mut validators = ValidatorSet::from_bytes(&v.set)
        .unwrap()
        .validators()
        .to_vec();
    validators.pop();
    let set = ValidatorSet::from_ranked(validators).unwrap();
    (set.to_bytes(), set.hash().to_vec())
}

#[test]
fn a_mainnet_proof_verifies_and_the_answer_says_what_was_found() {
    let v = mainnet();
    let verified = pinned(v).verify_transaction(v.proof.to_vec()).unwrap();
    assert_eq!(verified.slot, 473_100_911);
    assert_eq!(verified.slot, v.slot);
    assert_eq!(verified.block_id, v.block_id);
    assert_eq!(verified.epoch, 1095);
    assert_eq!(verified.transaction_id, v.signature);
    assert_eq!(verified.finality, Finality::Fast);
    // The leader's clock: the block was made in November 2026.
    let seconds = verified.block_time_nanos.unwrap() / 1_000_000_000;
    assert!((1_793_500_000..1_796_100_000).contains(&seconds));
    assert!(verified.memos.is_empty());
}

#[test]
fn memos_come_back_as_the_bytes_the_verifier_read() {
    let v = mainnet();
    let verified = pinned(v).verify_transaction(v.memo_proof.to_vec()).unwrap();
    assert_eq!(verified.transaction_id, v.memo_signature);
    assert!(!verified.memos.is_empty());
    assert_eq!(verified.memos, v.memos);
}

#[test]
fn a_proof_is_held_to_the_signature_asked_for() {
    let v = mainnet();
    let verifier = pinned(v);
    let verified = verifier
        .verify_signature(v.proof.to_vec(), v.signature.to_vec())
        .unwrap();
    assert_eq!(verified.transaction_id, v.signature);
    assert_eq!(
        verified,
        verifier.verify_transaction(v.proof.to_vec()).unwrap()
    );

    // A sound proof, for another transaction of the same block.
    let wrong = verifier.verify_signature(v.proof.to_vec(), v.memo_signature.to_vec());
    assert!(
        matches!(wrong, Err(VerifyError::WrongTransaction { .. })),
        "{wrong:?}"
    );

    // A signature of the wrong length is the caller's mistake, and is said
    // to be before the proof is looked at.
    for proof in [v.proof.to_vec(), b"not a proof".to_vec()] {
        let short = verifier.verify_signature(proof, v.signature[..63].to_vec());
        assert_eq!(
            short,
            Err(VerifyError::InvalidParameters {
                detail: "the expected signature is 63 bytes, not 64".into()
            })
        );
    }
}

#[test]
fn nothing_verifies_until_the_epoch_of_the_proof_is_pinned() {
    let v = mainnet();
    let verifier = Verifier::mainnet(v.shred_version);
    let unpinned = VerifyError::EpochNotPinned {
        detail: "no trusted validator set for epoch 1095".into(),
        epoch: Some(1095),
    };
    assert_eq!(
        verifier.verify_transaction(v.proof.to_vec()),
        Err(unpinned.clone())
    );

    // The epoch a set is pinned for is the caller's word and nothing else:
    // the right set under the next epoch does not vouch for this proof.
    verifier
        .pin_validator_set(v.epoch + 1, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    assert_eq!(verifier.verify_transaction(v.proof.to_vec()), Err(unpinned));

    verifier
        .pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    assert!(verifier.verify_transaction(v.proof.to_vec()).is_ok());
}

#[test]
fn a_set_is_pinned_only_under_its_own_hash() {
    let v = mainnet();
    let verifier = Verifier::mainnet(v.shred_version);
    let (other_set, other_hash) = another_set(v);

    let mismatch = verifier.pin_validator_set(v.epoch, v.set.to_vec(), other_hash.to_vec());
    assert_eq!(
        mismatch,
        Err(VerifyError::InvalidValidatorSet {
            detail: "validator set does not match the pinned hash".into()
        })
    );
    let short = verifier.pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash[..31].to_vec());
    assert_eq!(
        short,
        Err(VerifyError::InvalidParameters {
            detail: "the pinned hash is 31 bytes, not 32".into()
        })
    );
    let cut = verifier.pin_validator_set(
        v.epoch,
        v.set[..v.set.len() - 1].to_vec(),
        v.set_hash.to_vec(),
    );
    assert!(
        matches!(cut, Err(VerifyError::InvalidValidatorSet { .. })),
        "{cut:?}"
    );
    assert_eq!(verifier.pinned_epochs(), Vec::<u64>::new());

    // Pinning the same set again changes nothing. A different set for an
    // epoch that has one is refused, and the first stays.
    verifier
        .pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    verifier
        .pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    let second = verifier.pin_validator_set(v.epoch, other_set.to_vec(), other_hash.to_vec());
    assert_eq!(
        second,
        Err(VerifyError::InvalidParameters {
            detail: "a different validator set is already pinned for epoch 1095".into()
        })
    );
    assert_eq!(verifier.pinned_epochs(), vec![v.epoch]);
    assert!(verifier.verify_transaction(v.proof.to_vec()).is_ok());
}

#[test]
fn pinned_epochs_are_listed_and_forgotten() {
    let v = mainnet();
    let verifier = Verifier::mainnet(v.shred_version);
    for epoch in [1097, 1094, v.epoch] {
        verifier
            .pin_validator_set(epoch, v.set.to_vec(), v.set_hash.to_vec())
            .unwrap();
    }
    assert_eq!(verifier.pinned_epochs(), vec![1094, 1095, 1097]);

    assert!(verifier.forget_epoch(1097));
    assert!(!verifier.forget_epoch(1097));
    assert_eq!(verifier.pinned_epochs(), vec![1094, 1095]);

    assert_eq!(verifier.forget_epochs_before(1095), 1);
    assert_eq!(verifier.pinned_epochs(), vec![1095]);
    assert!(verifier.verify_transaction(v.proof.to_vec()).is_ok());

    assert_eq!(verifier.forget_epochs_before(u64::MAX), 1);
    assert_eq!(verifier.pinned_epochs(), Vec::<u64>::new());
    let forgotten = verifier.verify_transaction(v.proof.to_vec());
    assert!(
        matches!(
            forgotten,
            Err(VerifyError::EpochNotPinned {
                epoch: Some(1095),
                ..
            })
        ),
        "{forgotten:?}"
    );

    // A forgotten epoch can be pinned again, with another set if need be.
    let (other_set, other_hash) = another_set(v);
    verifier
        .pin_validator_set(v.epoch, other_set.to_vec(), other_hash.to_vec())
        .unwrap();
    assert_eq!(verifier.pinned_epochs(), vec![1095]);
}

#[test]
fn refusals_arrive_as_kinds_with_the_reason_in_words() {
    let v = mainnet();
    let verifier = pinned(v);

    let cut = verifier.verify_transaction(v.proof[..v.proof.len() - 1].to_vec());
    assert_eq!(
        cut,
        Err(VerifyError::Malformed {
            detail: "input ended early".into()
        })
    );

    let mut bent = v.proof.clone();
    let middle = bent.len() / 2;
    bent[middle] ^= 1;
    assert_eq!(
        verifier.verify_transaction(bent.to_vec()),
        Err(VerifyError::ProofRejected {
            detail: "data does not belong to the certified block".into()
        })
    );

    let mut newer = v.proof.clone();
    newer[3] = 9;
    assert_eq!(
        verifier.verify_transaction(newer.to_vec()),
        Err(VerifyError::Unsupported {
            detail: "unsupported proof format version 9".into()
        })
    );

    // The same keys sign on every cluster; the shred version is what tells
    // their votes apart.
    let elsewhere = Verifier::mainnet(v.shred_version + 1);
    elsewhere
        .pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    assert_eq!(
        elsewhere.verify_transaction(v.proof.to_vec()),
        Err(VerifyError::CertificateRejected {
            detail: "aggregate signature does not verify".into()
        })
    );

    // A set that is one validator short puts every signer at the wrong rank.
    let (other_set, other_hash) = another_set(v);
    let misled = Verifier::mainnet(v.shred_version);
    misled
        .pin_validator_set(v.epoch, other_set.to_vec(), other_hash.to_vec())
        .unwrap();
    let refused = misled.verify_transaction(v.proof.to_vec());
    assert!(
        matches!(refused, Err(VerifyError::CertificateRejected { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_verifier_is_made_for_one_cluster_and_its_epoch_schedule() {
    let v = mainnet();

    // Mainnet spelled out is mainnet.
    let flat = Verifier::without_warmup(v.shred_version, 432_000).unwrap();
    flat.pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    assert_eq!(
        flat.verify_transaction(v.proof.to_vec()).unwrap().epoch,
        1095
    );

    // On a cluster that began with warm-up epochs the same slot is in
    // another epoch, so the set pinned for 1095 is not the one asked for.
    let warm = Verifier::with_warmup(v.shred_version, 432_000).unwrap();
    warm.pin_validator_set(v.epoch, v.set.to_vec(), v.set_hash.to_vec())
        .unwrap();
    assert_eq!(
        warm.verify_transaction(v.proof.to_vec()),
        Err(VerifyError::EpochNotPinned {
            detail: "no trusted validator set for epoch 1107".into(),
            epoch: Some(1107),
        })
    );

    // An epoch length no cluster can have.
    for made in [
        Verifier::without_warmup(v.shred_version, 31),
        Verifier::with_warmup(v.shred_version, 31),
    ] {
        assert_eq!(
            made.err(),
            Some(VerifyError::InvalidParameters {
                detail: "cluster parameters are not valid: slots per epoch".into()
            })
        );
    }
}

#[test]
fn one_verifier_answers_several_threads() {
    let v = mainnet();
    let verifier = pinned(v);
    let expected = verifier.verify_transaction(v.proof.to_vec()).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..8 {
                    assert_eq!(
                        verifier.verify_transaction(v.proof.to_vec()).unwrap(),
                        expected
                    );
                }
            });
        }
        scope.spawn(|| {
            verifier
                .pin_validator_set(v.epoch + 2, v.set.to_vec(), v.set_hash.to_vec())
                .unwrap();
            assert!(verifier.forget_epoch(v.epoch + 2));
        });
    });
    assert_eq!(verifier.pinned_epochs(), vec![v.epoch]);
}
