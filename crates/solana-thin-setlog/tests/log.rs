//! What a log has to be before a client pins from it, and each way it can
//! fail to be that.

mod common;

use common::*;
use solana_thin_setlog::*;

/// Three signers; a client that wants two of them.
fn signers() -> [SigningKey; 3] {
    [key(1), key(2), key(3)]
}

#[test]
fn a_good_log_gives_a_hash_per_epoch() {
    let [a, b, c] = signers();
    let records = three_epochs(&[&a, &c]);
    let log = verify(&records, &public_keys(&[a, b, c]), 2).unwrap();
    assert_eq!(log.cluster(), "testnet");
    assert_eq!(log.len(), 3);
    assert!(!log.is_empty());
    let pins: Vec<(u64, Hash)> = log.pins().iter().map(|(e, p)| (*e, p.set_hash)).collect();
    assert_eq!(pins, [(10, [1; 32]), (11, [2; 32]), (12, [3; 32])]);
    assert_eq!(
        log.pin(11),
        Some(&Pin {
            set_hash: [2; 32],
            validators: 400,
            shred_version: 9
        })
    );
    assert_eq!(log.pin(13), None);
    assert_eq!(log.head(), &records[2].record().hash());
}

#[test]
fn a_log_file_round_trips() {
    let records = three_epochs(&[&key(1), &key(2)]);
    let text = to_text(&records);
    assert_eq!(text.lines().count(), 3);
    assert!(text.ends_with('\n'));
    assert_eq!(parse(&text), Ok(records));
    assert_eq!(parse(""), Ok(vec![]));
}

#[test]
fn a_file_cut_inside_a_line_or_holding_a_blank_one_is_refused() {
    let text = to_text(&three_epochs(&[&key(1)]));
    let no_final_newline = text.strip_suffix('\n').unwrap();
    assert_eq!(
        parse(no_final_newline),
        Err(Error::InvalidRecord {
            index: 2,
            error: Box::new(Error::Truncated)
        })
    );
    let cut = &text[..text.len() - 40];
    assert!(matches!(
        parse(cut),
        Err(Error::InvalidRecord { index: 2, .. })
    ));
    let blank = text.replacen('\n', "\n\n", 1);
    assert!(matches!(
        parse(&blank),
        Err(Error::InvalidRecord { index: 1, error }) if matches!(*error, Error::Json(_))
    ));
    let windows = text.replace('\n', "\r\n");
    assert!(matches!(
        parse(&windows),
        Err(Error::InvalidRecord { index: 0, .. })
    ));
}

#[test]
fn an_empty_log_pins_nothing_and_says_so() {
    assert_eq!(
        verify(&[], &public_keys(&signers()), 1),
        Err(Error::EmptyLog)
    );
    assert_eq!(check_links(&[]), Err(Error::EmptyLog));
}

#[test]
fn a_missing_record_breaks_the_chain() {
    let a = key(1);
    let keys = [a.public_key()];
    let records = three_epochs(&[&a]);

    let without_middle = [records[0].clone(), records[2].clone()];
    assert_eq!(
        verify(&without_middle, &keys, 1),
        Err(Error::BrokenLink { index: 1 })
    );
    // A log that starts after its first record does not start at zero.
    assert_eq!(
        verify(&records[1..], &keys, 1),
        Err(Error::BrokenLink { index: 0 })
    );
    let reordered = [records[0].clone(), records[2].clone(), records[1].clone()];
    assert_eq!(
        verify(&reordered, &keys, 1),
        Err(Error::BrokenLink { index: 1 })
    );
}

/// A record signed in good faith, but on top of a different history.
#[test]
fn a_record_from_another_history_does_not_link() {
    let a = key(1);
    let mut records = three_epochs(&[&a]);
    let elsewhere = chain(
        &[&a],
        &[&|prev| record(10, 7, prev), &|prev| record(11, 2, prev)],
    );
    records[1] = elsewhere[1].clone();
    assert_eq!(
        verify(&records, &[a.public_key()], 1),
        Err(Error::BrokenLink { index: 1 })
    );
}

/// The attack the log exists to stop: someone who holds no signing key
/// swaps in the hash of a set they control.
#[test]
fn a_forged_hash_fails_the_signatures() {
    let [a, b, c] = signers();
    let records = three_epochs(&[&a, &b]);
    let forged = Record::new(
        "testnet",
        9,
        11,
        [0x66; 32],
        400,
        records[1].record().sources().to_vec(),
        *records[1].record().prev(),
    )
    .unwrap();
    let line = with_stale_signatures(&records[1], forged);
    let mut tampered = records.clone();
    tampered[1] = SignedRecord::from_json(&line).unwrap();
    assert_eq!(
        verify(&tampered, &public_keys(&[a, b, c]), 2),
        Err(Error::InvalidSignature { index: 1 })
    );
    assert_eq!(
        check_links(&tampered),
        Err(Error::InvalidSignature { index: 1 })
    );
}

/// With the signatures removed the forged record has nothing wrong in it;
/// it just is not signed.
#[test]
fn a_record_nobody_signed_is_refused() {
    let [a, b, c] = signers();
    let mut records = three_epochs(&[&a, &b]);
    let unsigned = SignedRecord::unsigned(records[1].record().clone());
    records[1] = unsigned;
    assert_eq!(
        verify(&records, &public_keys(&[a, b, c]), 2),
        Err(Error::TooFewSignatures {
            index: 1,
            have: 0,
            need: 2
        })
    );
}

#[test]
fn signatures_below_the_threshold_are_refused() {
    let [a, b, c] = signers();
    let keys = public_keys(&[key(1), key(2), key(3)]);

    // One record of three is short by a signature.
    let mut records = three_epochs(&[&a, &b]);
    records[2] = signed(records[2].record().clone(), &[&a]);
    assert_eq!(
        verify(&records, &keys, 2),
        Err(Error::TooFewSignatures {
            index: 2,
            have: 1,
            need: 2
        })
    );
    assert!(verify(&records, &keys, 1).is_ok());

    // Any two of the three will do, and a third does no harm.
    for pair in [[&a, &b], [&a, &c], [&b, &c]] {
        assert!(verify(&three_epochs(&pair), &keys, 2).is_ok());
    }
    assert!(verify(&three_epochs(&[&a, &b, &c]), &keys, 2).is_ok());
    assert!(verify(&three_epochs(&[&a, &b, &c]), &keys, 3).is_ok());
}

#[test]
fn a_signature_from_a_key_that_is_not_listed_does_not_count() {
    let [a, b, _] = signers();
    let stranger = key(99);
    let records = three_epochs(&[&a, &stranger]);
    let keys = public_keys(&[key(1), key(2), key(3)]);
    assert_eq!(
        verify(&records, &keys, 2),
        Err(Error::TooFewSignatures {
            index: 0,
            have: 1,
            need: 2
        })
    );
    // Its presence is no objection either.
    assert!(verify(&three_epochs(&[&a, &b, &stranger]), &keys, 2).is_ok());
    // A client that lists only the stranger gets nothing from the others.
    assert_eq!(
        verify(&three_epochs(&[&a, &b]), &[stranger.public_key()], 1),
        Err(Error::TooFewSignatures {
            index: 0,
            have: 0,
            need: 1
        })
    );
}

#[test]
fn a_bad_signature_is_refused_even_from_a_stranger() {
    let [a, b, _] = signers();
    let stranger = key(99);
    let mut records = three_epochs(&[&a, &b]);
    // The stranger's signature is for a different record.
    let theirs = signed(record(11, 0x55, *records[1].record().prev()), &[&stranger]);
    let line = with_signatures_of(&records[1], &[&records[1], &theirs]);
    records[1] = SignedRecord::from_json(&line).unwrap();
    assert_eq!(records[1].signatures().len(), 3);
    assert_eq!(
        verify(&records, &public_keys(&[a, b]), 2),
        Err(Error::InvalidSignature { index: 1 })
    );
}

#[test]
fn one_signer_cannot_count_twice() {
    let a = key(1);
    let line = signed(record(10, 1, [0; 32]), &[&a]).to_json();
    let one = &line[line.find(r#"{"signer""#).unwrap()..line.len() - 2];
    let doubled = line.replace(one, &format!("{one},{one}"));
    assert_eq!(SignedRecord::from_json(&doubled), Err(Error::NotCanonical));
    // And a client cannot make one key count as two by listing it twice.
    let keys = [a.public_key(), a.public_key()];
    assert_eq!(
        verify(&three_epochs(&[&a]), &keys, 2),
        Err(Error::DuplicateSignerKey)
    );
}

#[test]
fn the_threshold_must_be_reachable_and_not_zero() {
    let a = key(1);
    let records = three_epochs(&[&a]);
    assert_eq!(
        verify(&records, &[a.public_key()], 0),
        Err(Error::InvalidThreshold)
    );
    assert_eq!(
        verify(&records, &[a.public_key()], 2),
        Err(Error::InvalidThreshold)
    );
    assert_eq!(verify(&records, &[], 0), Err(Error::InvalidThreshold));
}

/// Signers who contradict themselves: two records for one epoch, both
/// properly signed, with different sets.
#[test]
fn two_sets_for_one_epoch_are_refused() {
    let a = key(1);
    let records = chain(
        &[&a],
        &[
            &|prev| record(10, 1, prev),
            &|prev| record(11, 2, prev),
            &|prev| record(11, 3, prev),
        ],
    );
    assert_eq!(
        verify(&records, &[a.public_key()], 1),
        Err(Error::ConflictingSet {
            index: 2,
            epoch: 11
        })
    );
    // The same hash with a different size is also two different claims.
    let resized =
        |prev| Record::new("testnet", 9, 11, [2; 32], 401, vec![snapshot(1)], prev).unwrap();
    let records = chain(&[&a], &[&|prev| record(11, 2, prev), &resized]);
    assert_eq!(
        verify(&records, &[a.public_key()], 1),
        Err(Error::ConflictingSet {
            index: 1,
            epoch: 11
        })
    );
}

#[test]
fn an_epoch_that_goes_backward_is_refused() {
    let a = key(1);
    let records = chain(
        &[&a],
        &[
            &|prev| record(10, 1, prev),
            &|prev| record(12, 3, prev),
            &|prev| record(11, 2, prev),
        ],
    );
    assert_eq!(
        verify(&records, &[a.public_key()], 1),
        Err(Error::EpochWentBackward { index: 2 })
    );
    // Skipping an epoch is allowed: nobody may have been there to sign.
    assert!(verify(&records[..2], &[a.public_key()], 1).is_ok());
}

#[test]
fn a_change_of_cluster_is_refused() {
    let a = key(1);
    let other = |prev| Record::new("devnet", 9, 11, [2; 32], 400, vec![snapshot(1)], prev).unwrap();
    let records = chain(&[&a], &[&|prev| record(10, 1, prev), &other]);
    assert_eq!(
        verify(&records, &[a.public_key()], 1),
        Err(Error::ClusterChanged { index: 1 })
    );
}

/// A restart keeps the epoch and its validators and changes the shred
/// version. The log says so with one more record.
#[test]
fn a_restart_is_a_record_with_a_new_shred_version() {
    let a = key(1);
    let restarted = |epoch, set, prev| {
        Record::new(
            "testnet",
            10,
            epoch,
            [set; 32],
            400,
            vec![snapshot(3)],
            prev,
        )
        .unwrap()
    };
    let records = chain(
        &[&a],
        &[
            &|prev| record(10, 1, prev),
            &|prev| record(11, 2, prev),
            &|prev| restarted(11, 2, prev),
            &|prev| restarted(12, 3, prev),
        ],
    );
    let log = verify(&records, &[a.public_key()], 1).unwrap();
    assert_eq!(log.pin(10).unwrap().shred_version, 9);
    assert_eq!(log.pin(11).unwrap().shred_version, 10);
    assert_eq!(log.pin(11).unwrap().set_hash, [2; 32]);
    assert_eq!(log.pin(12).unwrap().shred_version, 10);
    assert_eq!(log.pins().len(), 3);
    assert_eq!(log.len(), 4);
}

/// The first records of a valid log are a valid log, so verifying cannot
/// show that a log is complete. The head a client kept can.
#[test]
fn a_shortened_or_rewritten_log_is_noticed_by_the_head_a_client_kept() {
    let a = key(1);
    let keys = [a.public_key()];
    let records = three_epochs(&[&a]);
    let seen = *verify(&records[..2], &keys, 1).unwrap().head();

    let extended = verify(&records, &keys, 1).unwrap();
    assert!(extended.contains(&seen));
    let shortened = verify(&records[..1], &keys, 1).unwrap();
    assert!(!shortened.contains(&seen));
    let rewritten = chain(
        &[&a],
        &[&|prev| record(10, 1, prev), &|prev| record(11, 8, prev)],
    );
    assert!(!verify(&rewritten, &keys, 1).unwrap().contains(&seen));
}

#[test]
fn links_can_be_checked_without_knowing_the_signers() {
    let records = three_epochs(&[&key(1)]);
    assert_eq!(check_links(&records), Ok(records[2].record().hash()));
    let unsigned = three_epochs(&[]);
    assert_eq!(check_links(&unsigned), Ok(records[2].record().hash()));
    assert_eq!(
        check_links(&[records[0].clone(), records[2].clone()]),
        Err(Error::BrokenLink { index: 1 })
    );
}

/// Every byte of a log file, changed several ways: none of the changed
/// files verifies.
#[test]
fn a_changed_byte_anywhere_in_a_log_is_refused() {
    let [a, b, c] = signers();
    let keys = public_keys(&[key(1), key(2), key(3)]);
    let text = to_text(&three_epochs(&[&a, &b, &c]));
    assert!(verify(&parse(&text).unwrap(), &keys, 2).is_ok());
    let mut refused = [0usize; 2];
    for at in 0..text.len() {
        for flip in [0x01, 0x04, 0x20] {
            let mut changed = text.clone().into_bytes();
            changed[at] ^= flip;
            let Ok(changed) = String::from_utf8(changed) else {
                continue;
            };
            match parse(&changed) {
                Err(_) => refused[0] += 1,
                Ok(records) => {
                    let result = verify(&records, &keys, 2);
                    assert!(result.is_err(), "byte {at} ^ {flip:#x} verified");
                    refused[1] += 1;
                }
            }
        }
    }
    // Both layers did some of the refusing.
    assert!(refused[0] > 0 && refused[1] > 0, "{refused:?}");
}

/// Removing one signature of three is not a changed byte, and leaves a log
/// that still has its two: the chain does not cover signatures, so that a
/// co-signer can add theirs later.
#[test]
fn a_dropped_signature_matters_only_below_the_threshold() {
    let [a, b, c] = signers();
    let keys = public_keys(&[key(1), key(2), key(3)]);
    let full = three_epochs(&[&a, &b, &c]);
    let mut fewer = full.clone();
    fewer[1] = signed(full[1].record().clone(), &[&a, &b]);
    assert_eq!(
        verify(&fewer, &keys, 2).unwrap().head(),
        verify(&full, &keys, 2).unwrap().head()
    );
    assert!(verify(&fewer, &keys, 3).is_err());
}
