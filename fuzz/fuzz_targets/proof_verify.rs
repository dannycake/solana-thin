#![no_main]

//! A proof from anyone: whatever the bytes, decoding and verifying must return, never panic,
//! hang or allocate without bound. Checked against a client that trusts the testkit's demo
//! validators, so the valid proofs `seed_corpus` writes get all the way through.
//!
//! Two properties on top of "does not crash":
//! * a proof that decodes re-encodes to bytes that decode to the same proof;
//! * a proof that verifies still verifies after that round trip, to the same transaction in
//!   the same block, and `verify_transaction_bytes` agrees with `verify_transaction`.

use solana_thin::{Limits, TxProof};
use solana_thin_fuzz::client;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let client = client();
    let Ok(proof) = TxProof::from_bytes(data, &limits) else {
        assert!(client.verify_transaction_bytes(data).is_err());
        return;
    };
    let encoded = proof.to_bytes();
    let again = TxProof::from_bytes(&encoded, &limits)
        .expect("a decoded proof re-encodes to something that decodes");
    assert_eq!(again, proof, "decode, encode, decode changed the proof");

    let verified = client.verify_transaction(&proof);
    assert_eq!(client.verify_transaction_bytes(data), verified);
    let Ok(verified) = verified else { return };
    let reverified = client
        .verify_transaction(&again)
        .expect("a verified proof verifies after a round trip");
    assert_eq!(
        reverified.transaction.signature(),
        verified.transaction.signature()
    );
    assert_eq!(reverified, verified);
});
