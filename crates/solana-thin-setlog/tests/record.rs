//! A record's bytes, its hash, its line of JSON, and its signatures.

mod common;

use common::*;
use sha2::{Digest, Sha256};
use solana_thin_setlog::*;

fn sample() -> Record {
    Record::new(
        "mainnet-beta",
        50093,
        1097,
        [0xab; 32],
        662,
        vec![
            Source::new(KIND_SNAPSHOT, "node-b", 474_000_002).unwrap(),
            Source::new(KIND_RANK_MAP, "rpc.example", 474_000_009).unwrap(),
            Source::new(KIND_SNAPSHOT, "node-a", 474_000_001).unwrap(),
        ],
        [0xcd; 32],
    )
    .unwrap()
}

/// The layout written out by hand, with sources in whatever order is given.
fn encode_by_hand(record: &Record, sources: &[&Source]) -> Vec<u8> {
    let text = |out: &mut Vec<u8>, s: &str| {
        out.push(s.len() as u8);
        out.extend_from_slice(s.as_bytes());
    };
    let mut out = b"solana-thin/set-record/v1".to_vec();
    text(&mut out, record.cluster());
    out.extend_from_slice(&record.shred_version().to_le_bytes());
    out.extend_from_slice(&record.epoch().to_le_bytes());
    out.extend_from_slice(record.set_hash());
    out.extend_from_slice(&record.validators().to_le_bytes());
    out.extend_from_slice(record.prev());
    out.push(sources.len() as u8);
    for source in sources {
        text(&mut out, source.kind());
        text(&mut out, source.label());
        out.extend_from_slice(&source.slot().to_le_bytes());
    }
    out
}

#[test]
fn the_bytes_are_the_documented_layout() {
    let record = sample();
    let sources: Vec<&Source> = record.sources().iter().collect();
    let bytes = record.to_bytes();
    assert_eq!(bytes, encode_by_hand(&record, &sources));
    assert!(bytes.starts_with(RECORD_DOMAIN));
    // domain, cluster, shred version, epoch, set hash, validators, prev, count
    let fixed = 25 + (1 + 12) + 2 + 8 + 32 + 4 + 32 + 1;
    let per_source = |kind: &str, label: &str| 1 + kind.len() + 1 + label.len() + 8;
    assert_eq!(
        bytes.len(),
        fixed
            + per_source("rank-map", "rpc.example")
            + per_source("snapshot", "node-a")
            + per_source("snapshot", "node-b")
    );
}

#[test]
fn sources_are_kept_in_order_of_kind_then_label() {
    let record = sample();
    let order: Vec<(&str, &str)> = record
        .sources()
        .iter()
        .map(|s| (s.kind(), s.label()))
        .collect();
    assert_eq!(
        order,
        [
            ("rank-map", "rpc.example"),
            ("snapshot", "node-a"),
            ("snapshot", "node-b")
        ]
    );
}

#[test]
fn bytes_round_trip() {
    let record = sample();
    assert_eq!(Record::from_bytes(&record.to_bytes()), Ok(record));
}

#[test]
fn the_hash_is_sha256_of_the_bytes() {
    let record = sample();
    let expected: Hash = Sha256::digest(record.to_bytes()).into();
    assert_eq!(record.hash(), expected);
}

#[test]
fn every_field_changes_the_hash() {
    let base = sample();
    let source = |slot| vec![Source::new(KIND_SNAPSHOT, "node-a", slot).unwrap()];
    let build = |cluster: &str, shred, epoch, set, validators, slot, prev| {
        Record::new(
            cluster,
            shred,
            epoch,
            [set; 32],
            validators,
            source(slot),
            [prev; 32],
        )
        .unwrap()
        .hash()
    };
    let hashes = [
        build("devnet", 1, 2, 3, 4, 5, 6),
        build("testnet", 1, 2, 3, 4, 5, 6),
        build("devnet", 9, 2, 3, 4, 5, 6),
        build("devnet", 1, 9, 3, 4, 5, 6),
        build("devnet", 1, 2, 9, 4, 5, 6),
        build("devnet", 1, 2, 3, 9, 5, 6),
        build("devnet", 1, 2, 3, 4, 9, 6),
        build("devnet", 1, 2, 3, 4, 5, 9),
        base.hash(),
    ];
    for (i, a) in hashes.iter().enumerate() {
        for b in &hashes[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn bytes_cut_short_or_run_long_are_refused() {
    let bytes = sample().to_bytes();
    for len in 0..bytes.len() {
        let cut = Record::from_bytes(&bytes[..len]);
        assert!(
            matches!(
                cut,
                Err(Error::Truncated | Error::WrongDomain | Error::InvalidField(_))
            ),
            "{len} bytes: {cut:?}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(Record::from_bytes(&long), Err(Error::TrailingBytes));
}

#[test]
fn bytes_under_another_domain_are_refused() {
    let mut bytes = sample().to_bytes();
    bytes[24] = b'2';
    assert_eq!(Record::from_bytes(&bytes), Err(Error::WrongDomain));
}

#[test]
fn sources_out_of_order_or_repeated_are_not_a_record() {
    let record = sample();
    let s = record.sources();
    let swapped = encode_by_hand(&record, &[&s[1], &s[0], &s[2]]);
    assert_eq!(
        Record::from_bytes(&swapped),
        Err(Error::InvalidField("sources"))
    );
    let repeated = encode_by_hand(&record, &[&s[0], &s[0]]);
    assert_eq!(
        Record::from_bytes(&repeated),
        Err(Error::InvalidField("sources"))
    );
    let none = encode_by_hand(&record, &[]);
    assert_eq!(
        Record::from_bytes(&none),
        Err(Error::InvalidField("sources"))
    );
}

#[test]
fn fields_outside_the_format_are_refused() {
    let source = || vec![snapshot(1)];
    let cluster = |name: &str| Record::new(name, 1, 1, [1; 32], 1, source(), [0; 32]);
    for name in ["", "Mainnet", "main net", "mainnet_beta", &"a".repeat(33)] {
        assert_eq!(
            cluster(name),
            Err(Error::InvalidField("cluster")),
            "{name:?}"
        );
    }
    assert!(cluster(&"a".repeat(32)).is_ok());

    assert_eq!(
        Record::new("devnet", 1, 1, [1; 32], 0, source(), [0; 32]),
        Err(Error::InvalidField("validators"))
    );

    let sources = |n: u64| (0..n).map(snapshot).collect();
    let with = |sources| Record::new("devnet", 1, 1, [1; 32], 1, sources, [0; 32]);
    assert_eq!(with(sources(0)), Err(Error::InvalidField("sources")));
    assert_eq!(with(sources(33)), Err(Error::InvalidField("sources")));
    assert!(with(sources(32)).is_ok());
    // One place at two slots is still one place.
    let twice = vec![
        Source::new(KIND_SNAPSHOT, "node-a", 1).unwrap(),
        Source::new(KIND_SNAPSHOT, "node-a", 2).unwrap(),
    ];
    assert_eq!(with(twice), Err(Error::InvalidField("sources")));

    for kind in ["", "Snapshot", "rank map", &"k".repeat(33)] {
        assert_eq!(
            Source::new(kind, "x", 1),
            Err(Error::InvalidField("source kind")),
            "{kind:?}"
        );
    }
    for label in ["", "two words", "tab\there", "caf\u{e9}", &"l".repeat(97)] {
        assert_eq!(
            Source::new(KIND_SNAPSHOT, label, 1),
            Err(Error::InvalidField("source label")),
            "{label:?}"
        );
    }
    assert!(Source::new(KIND_SNAPSHOT, &"l".repeat(96), 1).is_ok());
}

#[test]
fn a_line_round_trips() {
    let record = signed(sample(), &[&key(1), &key(2)]);
    let line = record.to_json();
    assert!(!line.contains('\n'));
    assert_eq!(SignedRecord::from_json(&line), Ok(record));
}

#[test]
fn a_line_is_spelled_one_way() {
    let unsigned = SignedRecord::unsigned(record(7, 0x1f, [0; 32]));
    assert_eq!(
        unsigned.to_json(),
        format!(
            concat!(
                r#"{{"cluster":"testnet","shred_version":9,"epoch":7,"set_hash":"{}","#,
                r#""validators":400,"sources":[{{"kind":"snapshot","label":"node-1","slot":1001}},"#,
                r#"{{"kind":"snapshot","label":"node-2","slot":1002}}],"prev":"{}","signatures":[{}]}}"#
            ),
            "1f".repeat(32),
            "00".repeat(32),
            ""
        )
    );

    let line = signed(record(7, 0x1f, [0; 32]), &[&key(1), &key(2)]).to_json();
    assert!(SignedRecord::from_json(&line).is_ok());
    let respelled = [
        line.replace("1f1f", "1F1f"),
        line.replace(r#""epoch":7"#, r#""epoch": 7"#),
        line.replace(r#""epoch":7"#, r#""epoch":07"#),
        line.replace(r#""epoch":7"#, r#""epoch":7.0"#),
        line.replace(r#""cluster":"testnet""#, r#""cluster":"\u0074estnet""#),
        line.replace(
            r#""cluster":"testnet","shred_version":9"#,
            r#""shred_version":9,"cluster":"testnet""#,
        ),
        line.replace(r#""epoch":7"#, r#""epoch":7,"note":"hello""#),
        line.replace(r#""epoch":7"#, r#""epoch":7,"epoch":7"#),
        line.replace("node-1", "node-3"),
        format!("{line}\n"),
        format!(" {line}"),
    ];
    for (i, other) in respelled.into_iter().enumerate() {
        assert_ne!(other, line, "respelling {i}");
        assert!(
            matches!(
                SignedRecord::from_json(&other),
                Err(Error::NotCanonical | Error::Json(_))
            ),
            "{other}"
        );
    }
}

#[test]
fn signatures_out_of_order_or_repeated_are_not_a_line() {
    let line = signed(sample(), &[&key(1), &key(2)]).to_json();
    let start = line.find(r#"[{"signer""#).unwrap() + 1;
    let (head, list) = line.split_at(start);
    let list = list.strip_suffix("]}").unwrap();
    let (first, second) = list.split_once("},{").unwrap();
    let (first, second) = (format!("{first}}}"), format!("{{{second}"));

    let swapped = format!("{head}{second},{first}]}}");
    assert_eq!(SignedRecord::from_json(&swapped), Err(Error::NotCanonical));
    let repeated = format!("{head}{first},{first}]}}");
    assert_eq!(SignedRecord::from_json(&repeated), Err(Error::NotCanonical));
    assert!(SignedRecord::from_json(&format!("{head}{first},{second}]}}")).is_ok());
}

#[test]
fn signing_is_per_key_and_repeatable() {
    let (a, b) = (key(1), key(2));
    let mut record = SignedRecord::unsigned(sample());
    assert!(record.signatures().is_empty());
    assert!(record.signatures_valid());
    record.sign(&b);
    record.sign(&a);
    record.sign(&b);
    assert_eq!(record.signatures().len(), 2);
    assert!(record.signatures_valid());
    let signers: Vec<SignerKey> = record.signatures().iter().map(|s| s.signer).collect();
    let mut sorted = vec![a.public_key(), b.public_key()];
    sorted.sort();
    assert_eq!(signers, sorted);
    // Adding a signature moves no link.
    assert_eq!(record.record().hash(), sample().hash());
}

#[test]
fn a_signature_is_for_one_record_only() {
    let signer = key(1);
    let original = signed(sample(), &[&signer]);
    let other = Record::new(
        "mainnet-beta",
        50093,
        1098,
        [0xab; 32],
        662,
        sample().sources().to_vec(),
        [0xcd; 32],
    )
    .unwrap();
    let moved = SignedRecord::from_json(&with_stale_signatures(&original, other)).unwrap();
    assert_eq!(moved.signatures(), original.signatures());
    assert!(!moved.signatures_valid());
}

/// The bytes are what is signed, so no byte of them may change and still
/// be covered by the signature.
#[test]
fn a_changed_byte_in_the_bytes_is_not_the_signed_record() {
    let original = signed(sample(), &[&key(1), &key(2)]);
    let bytes = original.record().to_bytes();
    for at in 0..bytes.len() {
        for flip in [0x01, 0x20, 0x80, 0xff] {
            let mut changed = bytes.clone();
            changed[at] ^= flip;
            let Ok(record) = Record::from_bytes(&changed) else {
                continue;
            };
            assert_ne!(&record, original.record(), "byte {at} ^ {flip:#x}");
            let line = with_stale_signatures(&original, record);
            let carried = SignedRecord::from_json(&line).unwrap();
            assert!(!carried.signatures_valid(), "byte {at} ^ {flip:#x}");
        }
    }
}

/// The same for the line a log stores: a changed byte anywhere, in the
/// record or in a signature, is refused on reading or fails the signatures.
#[test]
fn a_changed_byte_in_a_line_is_refused() {
    let line = signed(sample(), &[&key(1), &key(2)]).to_json();
    assert!(SignedRecord::from_json(&line).unwrap().signatures_valid());
    for at in 0..line.len() {
        for flip in [0x01, 0x02, 0x10, 0x20] {
            let mut changed = line.clone().into_bytes();
            changed[at] ^= flip;
            let Ok(changed) = String::from_utf8(changed) else {
                continue;
            };
            if let Ok(record) = SignedRecord::from_json(&changed) {
                assert!(
                    !record.signatures_valid(),
                    "byte {at} ^ {flip:#x}: {changed}"
                );
            }
        }
    }
}

#[test]
fn keys_come_from_seeds_and_refuse_the_empty_one() {
    assert_eq!(key(1).public_key(), key(1).public_key());
    assert_ne!(key(1).public_key(), key(2).public_key());
    assert_eq!(
        SigningKey::from_seed([0; 32]).err(),
        Some(Error::InvalidKey)
    );
    let from_hex = SigningKey::from_hex(&"07".repeat(32)).unwrap();
    assert_eq!(from_hex.public_key(), key(7).public_key());
    for bad in ["", "07", &"07".repeat(33), &"zz".repeat(32)] {
        assert_eq!(SigningKey::from_hex(bad).err(), Some(Error::InvalidKey));
    }
    // Printing a key shows the public half only.
    let shown = format!("{:?}", key(7));
    assert!(shown.contains(&hex::encode(key(7).public_key())));
    assert!(!shown.contains(&"07".repeat(32)));
    assert_eq!(
        signer_key_from_hex(&hex::encode(key(7).public_key())),
        Ok(key(7).public_key())
    );
    assert_eq!(signer_key_from_hex("abc"), Err(Error::InvalidKey));
}
