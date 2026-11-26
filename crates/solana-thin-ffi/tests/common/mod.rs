//! The mainnet block the verifier's own tests use, as a caller of the
//! binding would hold it: bytes and nothing else.
//!
//! The stored proof is for the block's first transaction. A second proof,
//! for the first transaction that carries a memo, is built here with the
//! prover, from the same shreds and the same certificate.

use serde_json::Value;
use solana_thin::prover::{self, BlockData};
use solana_thin::{ClusterParams, Limits, ThinClient, TxProof};

pub struct Vector {
    pub shred_version: u16,
    pub epoch: u64,
    pub slot: u64,
    pub block_id: Vec<u8>,
    pub set: Vec<u8>,
    pub set_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub proof: Vec<u8>,
    pub memo_signature: Vec<u8>,
    pub memo_proof: Vec<u8>,
    pub memos: Vec<Vec<u8>>,
}

pub fn vector() -> Vector {
    let doc: Value = serde_json::from_str(include_str!(
        "../../../solana-thin/tests/vectors/mainnet-block-473100911.json"
    ))
    .unwrap();
    let bytes = |name: &str| hex::decode(doc[name].as_str().unwrap()).unwrap();
    let number = |name: &str| doc[name].as_u64().unwrap();
    let shred_version = number("shred_version") as u16;
    let epoch = number("epoch");
    let set = bytes("validator_set");
    let set_hash = bytes("validator_set_hash");
    let proof = bytes("proof_of_first_transaction");

    let shreds: Vec<Vec<u8>> = doc["shreds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|shred| hex::decode(shred.as_str().unwrap()).unwrap())
        .collect();
    let block = BlockData::from_shreds(&shreds).unwrap();
    let certificate = TxProof::from_bytes(&proof, &Limits::default())
        .unwrap()
        .finality;
    let mut client = ThinClient::new(ClusterParams::mainnet(shred_version));
    client
        .trust_validator_set_bytes(epoch, &set, set_hash.as_slice().try_into().unwrap())
        .unwrap();
    let (memo_signature, memo_proof, memos) = block
        .signatures()
        .iter()
        .find_map(|signature| {
            let proof = prover::prove(certificate.clone(), &[&block], signature, true)
                .unwrap()
                .to_bytes()
                .unwrap();
            let verified = client.verify_transaction_bytes(&proof).unwrap();
            let memos: Vec<Vec<u8>> = verified.transaction.memos().map(<[u8]>::to_vec).collect();
            (!memos.is_empty()).then(|| (signature.to_vec(), proof, memos))
        })
        .expect("the block holds a transaction with a memo");

    Vector {
        shred_version,
        epoch,
        slot: number("slot"),
        block_id: bytes("block_id"),
        set,
        set_hash,
        signature: bytes("first_signature"),
        proof,
        memo_signature,
        memo_proof,
        memos,
    }
}
