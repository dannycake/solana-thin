//! A real mainnet block, the certificate that finalized it, and every
//! transaction in it.
//!
//! `tests/vectors/mainnet-block-473100911.json` holds:
//!
//! * the 512 data shreds of mainnet slot 473,100,911 (epoch 1095, November
//!   2026), fetched from 24 validators over the repair protocol by an
//!   unstaked client they had never seen;
//! * a proof for the block's first transaction, which carries the finality
//!   certificate the leader of slot 473,100,912 put in its footer;
//! * the ranked validator set of epoch 1095: 666 validators.
//!
//! The set's membership is the `VATDebit` rewards in the first block of epoch
//! 1094 (slot 472,608,000) and its keys are from the vote accounts. Its
//! stake values are from Trillium's per-epoch API (`api.trillium.so`,
//! CC BY 4.0, "Fueled By Trillium | Solana"), which rounds to 10^-5 SOL,
//! because public RPC no longer reports a past epoch's stake. So the ranking
//! is right, as the signature check below proves for every signer, but the
//! stake total is approximate and the set hash is not the one a client that
//! fetched in time would have pinned.

use serde_json::Value;
use solana_thin::prover::{self, BlockData};
use solana_thin::*;

struct Vector {
    shred_version: u16,
    epoch: u64,
    block_id: Hash,
    transactions: usize,
    set: ValidatorSet,
    first_signature: [u8; 64],
    proof: Vec<u8>,
    shreds: Vec<Vec<u8>>,
}

fn vector() -> Vector {
    let doc: Value =
        serde_json::from_str(include_str!("vectors/mainnet-block-473100911.json")).unwrap();
    let bytes = |name: &str| hex::decode(doc[name].as_str().unwrap()).unwrap();
    Vector {
        shred_version: doc["shred_version"].as_u64().unwrap() as u16,
        epoch: doc["epoch"].as_u64().unwrap(),
        block_id: bytes("block_id").try_into().unwrap(),
        transactions: doc["transactions"].as_u64().unwrap() as usize,
        set: ValidatorSet::from_bytes(&bytes("validator_set")).unwrap(),
        first_signature: bytes("first_signature").try_into().unwrap(),
        proof: bytes("proof_of_first_transaction"),
        shreds: doc["shreds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
            .collect(),
    }
}

fn client(v: &Vector, shred_version: u16, set: ValidatorSet) -> ThinClient {
    let mut client = ThinClient::new(ClusterParams::mainnet(shred_version));
    let hash = set.hash();
    client.trust_validator_set(v.epoch, set, &hash).unwrap();
    client
}

#[test]
fn a_mainnet_block_its_certificate_and_its_transactions_verify() {
    let v = vector();
    let client = client(&v, v.shred_version, v.set.clone());

    // The stored proof, as a client would receive it.
    let verified = client.verify_transaction_bytes(&v.proof).unwrap();
    assert_eq!(verified.transaction.signature(), &v.first_signature);
    assert_eq!(verified.block.slot, 473_100_911);
    assert_eq!(verified.block.id, v.block_id);
    assert_eq!(verified.finalized_by.finality, Finality::Fast);
    assert!(verified.block_time_nanos().is_some());

    // The block id, recomputed from shreds, is the one mainnet certified.
    let block = BlockData::from_shreds(&v.shreds).unwrap();
    assert_eq!(block.block().id, v.block_id);
    assert_eq!(block.shred_count(), 512);

    // Every transaction in the block proves and verifies.
    let cert = TxProof::from_bytes(&v.proof, &Limits::default())
        .unwrap()
        .finality;
    let signatures = block.signatures();
    assert_eq!(signatures.len(), v.transactions);
    let mut largest = 0;
    for signature in &signatures {
        let proof = prover::prove(cert.clone(), &[&block], signature, true).unwrap();
        let bytes = proof.to_bytes();
        largest = largest.max(bytes.len());
        let verified = client.verify_transaction_bytes(&bytes).unwrap();
        assert_eq!(verified.transaction.signature(), signature);
    }
    println!(
        "{} mainnet transactions proven and verified; largest proof {largest} bytes",
        signatures.len()
    );
}

#[test]
fn the_mainnet_certificate_is_bound_to_its_cluster_and_its_set() {
    let v = vector();
    let cert = TxProof::from_bytes(&v.proof, &Limits::default())
        .unwrap()
        .finality;
    assert!(client(&v, v.shred_version, v.set.clone())
        .verify_finality(&cert)
        .is_ok());

    // Another cluster's shred version: same keys, different signed bytes.
    assert_eq!(
        client(&v, v.shred_version + 1, v.set.clone()).verify_finality(&cert),
        Err(Error::SignatureMismatch)
    );

    // One validator missing from the set shifts every rank below it. This is
    // what a set built without the admission filter does.
    let mut validators = v.set.validators().to_vec();
    validators.remove(validators.len() / 2);
    let short = ValidatorSet::from_ranked(validators).unwrap();
    assert!(client(&v, v.shred_version, short)
        .verify_finality(&cert)
        .is_err());
}
