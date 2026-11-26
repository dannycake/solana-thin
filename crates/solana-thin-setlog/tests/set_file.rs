//! Set files, and the agreement check over them.

mod common;

use common::*;
use solana_thin::testkit::TestValidators;
use solana_thin::{ClusterParams, Error as VerifierError, ThinClient, ValidatorSet};
use solana_thin_setlog::*;

fn validators(seed: u64) -> ValidatorSet {
    TestValidators::with_seed(seed, 5, |i| 1_000 + i as u64).set()
}

fn file(set: &ValidatorSet, sources: Vec<Source>) -> SetFile {
    SetFile::new("devnet", 7016, 1219, set.to_bytes(), sources).unwrap()
}

fn rank_map(host: &str, slot: u64) -> Source {
    Source::new(KIND_RANK_MAP, host, slot).unwrap()
}

#[test]
fn the_hash_is_the_verifiers_hash_of_the_set() {
    let set = validators(1);
    let file = file(&set, vec![snapshot(1)]);
    assert_eq!(file.set_hash(), set.hash());
    assert_eq!(file.validators(), 5);
    assert_eq!(file.set_bytes(), set.to_bytes());
    assert_eq!(
        (file.cluster(), file.shred_version(), file.epoch()),
        ("devnet", 7016, 1219)
    );
}

#[test]
fn a_set_file_round_trips() {
    let file = file(
        &validators(1),
        vec![snapshot(2), rank_map("rpc.example", 5)],
    );
    let text = file.to_json();
    assert!(text.starts_with(r#"{"format":"solana-thin/set/v1","cluster":"devnet","#));
    assert!(text.ends_with("\n"));
    assert_eq!(SetFile::from_json(&text), Ok(file.clone()));
    // Unlike a log line, a set file may be laid out for reading.
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let pretty = serde_json::to_string_pretty(&value).unwrap();
    assert_eq!(SetFile::from_json(&pretty), Ok(file));
}

#[test]
fn a_set_file_that_misstates_its_set_is_refused() {
    let text = file(&validators(1), vec![snapshot(1)]).to_json();
    let other_hash = hex::encode(validators(2).hash());
    let own_hash = hex::encode(validators(1).hash());
    let cases = [
        (
            text.replace(&own_hash, &other_hash),
            Error::InvalidField("set_hash"),
        ),
        (
            text.replace(r#""validators":5"#, r#""validators":6"#),
            Error::InvalidField("validators"),
        ),
        (
            text.replace("solana-thin/set/v1", "solana-thin/set/v2"),
            Error::InvalidField("format"),
        ),
        (
            text.replace(r#""cluster":"devnet""#, r#""cluster":"Devnet""#),
            Error::InvalidField("cluster"),
        ),
    ];
    for (changed, expected) in cases {
        assert_ne!(changed, text);
        assert_eq!(SetFile::from_json(&changed), Err(expected));
    }
    let extra = text.replace(r#""epoch":1219"#, r#""epoch":1219,"trusted":true"#);
    assert!(matches!(SetFile::from_json(&extra), Err(Error::Json(_))));
}

#[test]
fn bytes_that_are_not_the_shape_of_a_set_are_refused() {
    let good = validators(1).to_bytes();
    let new = |bytes: Vec<u8>| SetFile::new("devnet", 1, 1, bytes, vec![snapshot(1)]);
    assert!(new(good.clone()).is_ok());
    let mut miscounted = good.clone();
    miscounted[0] += 1;
    let empty_set = 0u32.to_le_bytes().to_vec();
    for bytes in [
        vec![],
        vec![1, 0],
        good[..good.len() - 1].to_vec(),
        miscounted,
        empty_set,
    ] {
        assert_eq!(new(bytes), Err(Error::InvalidField("set")));
    }
    assert_eq!(
        SetFile::new("devnet", 1, 1, good.clone(), vec![]),
        Err(Error::InvalidField("sources"))
    );
    assert_eq!(
        SetFile::new("dev net", 1, 1, good, vec![snapshot(1)]),
        Err(Error::InvalidField("cluster"))
    );
}

#[test]
fn a_set_file_makes_the_record_it_supports() {
    let file = file(&validators(1), vec![snapshot(2), snapshot(1)]);
    let record = file.candidate([4; 32]).unwrap();
    assert_eq!(record.cluster(), "devnet");
    assert_eq!(record.shred_version(), 7016);
    assert_eq!(record.epoch(), 1219);
    assert_eq!(record.set_hash(), &validators(1).hash());
    assert_eq!(record.validators(), 5);
    assert_eq!(record.sources(), file.sources());
    assert_eq!(record.prev(), &[4; 32]);
    assert!(file.supports(&record));

    let other_set = self::file(&validators(2), vec![snapshot(1)]);
    assert!(!other_set.supports(&record));
    let other_epoch = SetFile::new(
        "devnet",
        7016,
        1220,
        validators(1).to_bytes(),
        vec![snapshot(1)],
    )
    .unwrap();
    assert!(!other_epoch.supports(&record));
    let other_cluster = SetFile::new(
        "testnet",
        7016,
        1219,
        validators(1).to_bytes(),
        vec![snapshot(1)],
    )
    .unwrap();
    assert!(!other_cluster.supports(&record));
    let other_version = SetFile::new(
        "devnet",
        7017,
        1219,
        validators(1).to_bytes(),
        vec![snapshot(1)],
    )
    .unwrap();
    assert!(!other_version.supports(&record));
}

#[test]
fn sources_that_agree_are_merged() {
    let set = validators(1);
    let inputs = [
        file(&set, vec![snapshot(1)]),
        file(&set, vec![rank_map("rpc.example", 9)]),
        file(&set, vec![snapshot(2)]),
    ];
    let agreed = agree(&inputs, 3).unwrap();
    assert_eq!(agreed.set_hash(), set.hash());
    assert_eq!(
        agreed.sources(),
        [rank_map("rpc.example", 9), snapshot(1), snapshot(2)]
    );
    assert_eq!(agreed.epoch(), 1219);
    // A merged file can be an input in turn, with its sources counted.
    let later = [agreed, file(&set, vec![snapshot(3)])];
    assert_eq!(agree(&later, 4).unwrap().sources().len(), 4);
}

#[test]
fn too_few_sources_are_refused() {
    let set = validators(1);
    let inputs = [file(&set, vec![snapshot(1)]), file(&set, vec![snapshot(2)])];
    assert_eq!(
        agree(&inputs, 3),
        Err(Error::BelowQuorum { have: 2, need: 3 })
    );
    assert!(agree(&inputs, 2).is_ok());
    assert_eq!(agree(&[], 1), Err(Error::NoInputs));
    assert_eq!(agree(&inputs, 0), Err(Error::InvalidField("quorum")));
}

/// Asking one node three times is one source.
#[test]
fn one_place_read_twice_counts_once() {
    let set = validators(1);
    let at = |slot| {
        file(
            &set,
            vec![Source::new(KIND_SNAPSHOT, "node-a", slot).unwrap()],
        )
    };
    let inputs = [at(5), at(9), at(7)];
    assert_eq!(
        agree(&inputs, 2),
        Err(Error::BelowQuorum { have: 1, need: 2 })
    );
    let agreed = agree(&inputs, 1).unwrap();
    assert_eq!(agreed.sources().len(), 1);
    assert_eq!(agreed.sources()[0].slot(), 9);
    // The same label under another kind is another place.
    let both = [at(5), file(&set, vec![rank_map("node-a", 5)])];
    assert!(agree(&both, 2).is_ok());
}

/// The admission check is recorded beside the sources, and is not one: it
/// looked at who paid to be in the set, not at the set.
#[test]
fn an_admission_check_does_not_count_toward_the_quorum() {
    let set = validators(1);
    let checked = Source::new(KIND_ADMISSION, "vat-debits", 900).unwrap();
    let inputs = [
        file(&set, vec![snapshot(1), checked.clone()]),
        file(&set, vec![snapshot(2), checked.clone()]),
    ];
    assert_eq!(
        agree(&inputs, 3),
        Err(Error::BelowQuorum { have: 2, need: 3 })
    );
    let agreed = agree(&inputs, 2).unwrap();
    assert_eq!(
        agreed.sources(),
        [checked.clone(), snapshot(1), snapshot(2)]
    );
    assert_eq!(
        agree(&[file(&set, vec![checked])], 1),
        Err(Error::BelowQuorum { have: 0, need: 1 })
    );
}

/// Exact sources cannot differ, so one that does is not outvoted.
#[test]
fn one_source_that_differs_refuses_the_lot() {
    let (set, other) = (validators(1), validators(2));
    let inputs = [
        file(&set, vec![snapshot(1)]),
        file(&set, vec![snapshot(2)]),
        file(&set, vec![snapshot(3)]),
        file(&other, vec![snapshot(4)]),
    ];
    assert!(agree(&inputs[..3], 3).is_ok());
    assert_eq!(agree(&inputs, 3), Err(Error::SourcesDisagree));
    assert_eq!(agree(&inputs, 1), Err(Error::SourcesDisagree));

    let restarted = SetFile::new("devnet", 7017, 1219, set.to_bytes(), vec![snapshot(5)]).unwrap();
    assert_eq!(
        agree(&[inputs[0].clone(), restarted], 2),
        Err(Error::SourcesDisagree)
    );
}

#[test]
fn inputs_about_different_things_are_not_compared() {
    let set = validators(1);
    let base = file(&set, vec![snapshot(1)]);
    let next_epoch = SetFile::new("devnet", 7016, 1220, set.to_bytes(), vec![snapshot(2)]).unwrap();
    let elsewhere = SetFile::new("testnet", 7016, 1219, set.to_bytes(), vec![snapshot(2)]).unwrap();
    assert_eq!(
        agree(&[base.clone(), next_epoch], 2),
        Err(Error::MixedInputs("epoch"))
    );
    assert_eq!(
        agree(&[base, elsewhere], 2),
        Err(Error::MixedInputs("cluster"))
    );
}

/// The whole path a client takes, and the two ways it goes wrong: the set
/// offered is not the one the log names, or the log is not signed.
#[test]
fn a_client_pins_from_a_verified_log_and_nothing_else() {
    let (a, b) = (key(1), key(2));
    let keys = public_keys(&[key(1), key(2)]);
    let set = validators(1);
    let set_file = agree(
        &[
            SetFile::new("devnet", 7016, 3, set.to_bytes(), vec![snapshot(1)]).unwrap(),
            SetFile::new("devnet", 7016, 3, set.to_bytes(), vec![snapshot(2)]).unwrap(),
        ],
        2,
    )
    .unwrap();
    let record = signed(set_file.candidate([0; 32]).unwrap(), &[&a, &b]);
    let log_text = to_text(&[record]);

    let log = verify(&parse(&log_text).unwrap(), &keys, 2).unwrap();
    let pin = log.pin(3).unwrap();
    let params = ClusterParams::without_warmup(pin.shred_version, 432_000).unwrap();
    let mut client = ThinClient::new(params);
    let fetched = SetFile::from_json(&set_file.to_json()).unwrap();
    client
        .trust_validator_set_bytes(3, fetched.set_bytes(), &pin.set_hash)
        .unwrap();
    assert_eq!(client.validator_set(3).unwrap().hash(), set.hash());

    // A set file for the right epoch with other validators in it.
    let swapped = SetFile::new(
        "devnet",
        7016,
        3,
        validators(2).to_bytes(),
        vec![snapshot(1)],
    )
    .unwrap();
    let mut client = ThinClient::new(params);
    assert_eq!(
        client.trust_validator_set_bytes(3, swapped.set_bytes(), &pin.set_hash),
        Err(VerifierError::ValidatorSetHashMismatch)
    );
    assert!(!swapped.supports(parse(&log_text).unwrap()[0].record()));
}
