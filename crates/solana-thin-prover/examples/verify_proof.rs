//! A client's side of the prover: check a proof with nothing but the
//! validator set and the shred version.
//!
//! ```text
//! curl -o tx.proof http://<prover>/proof/<signature>
//! cargo run -p solana-thin-prover --example verify_proof -- \
//!     <set file> <signature> tx.proof [<slots per epoch>]
//! ```
//!
//! The proof can come from anywhere. The set file cannot: its hash is what
//! the client trusts, and a real client takes that hash from a verified set
//! log (`docs/SETS.md`), not from the file as this example does. The shred
//! version is read from the same file. Give the epoch length for a cluster
//! that is not mainnet-beta, testnet or devnet.

use solana_thin::{ClusterParams, Finality, ThinClient, TxProof};
use solana_thin_setlog::SetFile;
use std::error::Error;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (set_path, signature, proof_path, slots_per_epoch) = match &args[..] {
        [set, signature, proof] => (set, signature, proof, None),
        [set, signature, proof, slots] => (set, signature, proof, Some(slots.parse::<u64>()?)),
        _ => {
            return Err(
                "usage: verify_proof <set file> <signature> <proof file> [<slots per epoch>]"
                    .into(),
            )
        }
    };
    let signature: [u8; 64] = bs58::decode(signature)
        .into_vec()?
        .try_into()
        .map_err(|_| "a signature is 64 bytes")?;

    // What is trusted: the set, under its hash, and the cluster's schedule
    // and shred version.
    let set = SetFile::from_json(&fs::read_to_string(set_path)?)?;
    let version = set.shred_version();
    let params = match (slots_per_epoch, set.cluster()) {
        (Some(slots), _) => ClusterParams::without_warmup(version, slots)?,
        (None, "mainnet-beta") => ClusterParams::mainnet(version),
        (None, "testnet" | "devnet") => ClusterParams::with_warmup(version, 432_000)?,
        (None, other) => return Err(format!("give the epoch length of {other}").into()),
    };
    let mut client = ThinClient::new(params);
    client.trust_validator_set_bytes(set.epoch(), set.set_bytes(), &set.set_hash())?;

    // What is not: the proof.
    let bytes = fs::read(proof_path)?;
    let proof = TxProof::from_bytes(&bytes, client.limits())?;
    let verified = client.verify_signature(&proof, &signature)?;
    let how = match verified.finalized_by.finality {
        Finality::Fast => "fast",
        Finality::Slow => "slow",
        _ => "unknown",
    };
    println!(
        "verified: in block {} of slot {}, final by a {how} certificate for slot {} ({} parent \
         links), {} bytes of proof",
        hex::encode(verified.block.id),
        verified.block.slot,
        verified.finalized_by.block.slot,
        proof.ancestry.len(),
        bytes.len()
    );
    Ok(())
}
