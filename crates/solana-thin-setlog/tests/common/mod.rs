//! Records, keys and logs that the tests share.
#![allow(dead_code)]

use solana_thin_setlog::*;

/// A signing key that exists only in the tests, from a seed of one repeated
/// byte.
pub fn key(n: u8) -> SigningKey {
    SigningKey::from_seed([n; 32]).unwrap()
}

pub fn public_keys(keys: &[SigningKey]) -> Vec<SignerKey> {
    keys.iter().map(SigningKey::public_key).collect()
}

pub fn snapshot(n: u64) -> Source {
    Source::new(KIND_SNAPSHOT, &format!("node-{n}"), 1_000 + n).unwrap()
}

/// A record for `epoch` whose set hash is `set` repeated, linking to `prev`.
pub fn record(epoch: u64, set: u8, prev: Hash) -> Record {
    Record::new(
        "testnet",
        9,
        epoch,
        [set; 32],
        400,
        vec![snapshot(1), snapshot(2)],
        prev,
    )
    .unwrap()
}

pub fn signed(record: Record, signers: &[&SigningKey]) -> SignedRecord {
    let mut signed = SignedRecord::unsigned(record);
    for signer in signers {
        signed.sign(signer);
    }
    signed
}

/// Links `records` into a chain, each signed by `signers`. `build` gets the
/// hash to link to.
pub fn chain(signers: &[&SigningKey], build: &[&dyn Fn(Hash) -> Record]) -> Vec<SignedRecord> {
    let mut prev = [0; 32];
    build
        .iter()
        .map(|build| {
            let record = build(prev);
            prev = record.hash();
            signed(record, signers)
        })
        .collect()
}

/// Three epochs, 10 to 12, with set hashes of 1, 2 and 3 repeated.
pub fn three_epochs(signers: &[&SigningKey]) -> Vec<SignedRecord> {
    chain(
        signers,
        &[
            &|prev| record(10, 1, prev),
            &|prev| record(11, 2, prev),
            &|prev| record(12, 3, prev),
        ],
    )
}

/// The record in `signed` replaced by `record`, keeping the signatures that
/// were made for the old one.
pub fn with_stale_signatures(signed: &SignedRecord, record: Record) -> String {
    with_signatures_of(&SignedRecord::unsigned(record), &[signed])
}

/// The line for `signed`'s record carrying the signatures found in `from`,
/// whatever record each was made for.
pub fn with_signatures_of(signed: &SignedRecord, from: &[&SignedRecord]) -> String {
    let line = SignedRecord::unsigned(signed.record().clone()).to_json();
    let mut signatures: Vec<String> = from
        .iter()
        .flat_map(|record| record.signatures())
        .map(|s| {
            format!(
                r#"{{"signer":"{}","signature":"{}"}}"#,
                hex::encode(s.signer),
                hex::encode(s.signature)
            )
        })
        .collect();
    // Hex of the key sorts as the key does.
    signatures.sort();
    line.replace(
        r#""signatures":[]"#,
        &format!(r#""signatures":[{}]"#, signatures.join(",")),
    )
}
