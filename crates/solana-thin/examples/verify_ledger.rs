//! Runs the whole pipeline against what a real validator wrote.
//!
//! Input is a dump of a ledger's data shreds (`tools/agave-fixtures`,
//! `ledger-dump`) and the cluster's vote accounts
//! (`tools/fetch_vote_accounts.py`). For every block in the dump this:
//!
//! 1. recomputes the block id from the shreds and compares it with the id the
//!    validator's blockstore recorded;
//! 2. verifies every finality certificate found in a block footer against the
//!    validator set built from the vote accounts;
//! 3. for each signature given, builds a proof, round-trips it through bytes
//!    and verifies it.
//!
//! ```text
//! cargo run --release --example verify_ledger -- \
//!     dump.jsonl vote-accounts.json <shred version> [signature ...]
//! ```
//!
//! Signatures are base58, as the `solana` CLI prints them. Set `HOPS=n` to
//! prove each transaction from a certificate `n` certified blocks later than
//! the nearest one, which exercises the ancestry chain. See
//! `docs/LOCAL-VALIDATOR.md` for the full procedure.

use serde_json::Value;
use solana_thin::prover::{self, BlockData};
use solana_thin::*;
use std::collections::BTreeMap;
use std::process::ExitCode;

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_signature(text: &str) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    for c in text.bytes() {
        let mut carry = ALPHABET.iter().position(|a| *a == c)? as u32;
        for byte in out.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return None;
        }
    }
    Some(out)
}

fn vote_accounts(path: &str) -> Vec<VoteAccount> {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("vote accounts"))
        .expect("vote accounts JSON");
    let hex32 = |v: &Value| -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    doc["accounts"]
        .as_array()
        .expect("accounts")
        .iter()
        .map(|a| VoteAccount {
            vote_pubkey: hex32(&a["vote_pubkey"]),
            node_pubkey: hex32(&a["node_pubkey"]),
            bls_pubkey: a["bls_pubkey"]
                .as_str()
                .map(|s| hex::decode(s).unwrap().try_into().unwrap()),
            stake: a["stake"].as_u64().unwrap(),
        })
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: verify_ledger <dump.jsonl> <vote-accounts.json> <shred version> [signature ...]"
        );
        return ExitCode::from(2);
    }
    let shred_version: u16 = args[3].parse().expect("shred version");
    let mut failed = false;

    // ---- 1. Blocks: index every slot and compare ids with the validator's.
    let dump = std::fs::read_to_string(&args[1]).expect("dump");
    let mut blocks: BTreeMap<u64, BlockData> = BTreeMap::new();
    let (mut ids_equal, mut ids_compared, mut refused) = (0, 0, 0);
    let (mut shreds_total, mut txs_total) = (0usize, 0usize);
    for line in dump.lines().filter(|l| !l.trim().is_empty()) {
        let doc: Value = serde_json::from_str(line).expect("dump line");
        let slot = doc["slot"].as_u64().unwrap();
        let shreds: Vec<Vec<u8>> = doc["shreds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
            .collect();
        let block = match BlockData::from_shreds(&shreds) {
            Ok(block) => block,
            Err(error) => {
                println!("slot {slot}: not indexed: {error}");
                refused += 1;
                continue;
            }
        };
        if block.block().slot != slot {
            println!("slot {slot}: shreds claim slot {}", block.block().slot);
            failed = true;
        }
        if let Some(id) = doc["block_id"].as_str() {
            ids_compared += 1;
            if hex::encode(block.block().id) == id {
                ids_equal += 1;
            } else {
                println!("slot {slot}: block id differs from the validator's");
                failed = true;
            }
        }
        shreds_total += shreds.len();
        txs_total += block.signatures().len();
        blocks.insert(slot, block);
    }
    println!(
        "blocks: {} indexed ({shreds_total} data shreds, {txs_total} transactions), {refused} refused",
        blocks.len()
    );
    println!("block ids: {ids_equal} of {ids_compared} equal to the validator's");

    // ---- 2. Certificates: every footer certificate against the vote accounts.
    let accounts = vote_accounts(&args[2]);
    let set = ValidatorSet::from_vote_accounts(&accounts).expect("validator set");
    println!(
        "validator set: {} ranked of {} vote accounts, hash {}",
        set.len(),
        accounts.len(),
        hex::encode(set.hash())
    );
    let params = ClusterParams::mainnet(shred_version);
    let mut client = ThinClient::new(params);
    let pinned = set.hash();
    let mut epochs: Vec<u64> = blocks
        .keys()
        .map(|slot| params.epoch_of(*slot).unwrap())
        .collect();
    epochs.dedup();
    for epoch in &epochs {
        client
            .trust_validator_set(*epoch, set.clone(), &pinned)
            .unwrap();
    }

    // Certified block -> certificate, as found in later blocks' footers.
    let mut certs: BTreeMap<u64, FinalityCert> = BTreeMap::new();
    let (mut fast, mut slow, mut without, mut bad) = (0, 0, 0, 0);
    for (slot, block) in &blocks {
        let Some((_, footer)) = block.footer() else {
            println!("slot {slot}: no footer");
            failed = true;
            continue;
        };
        let Some(cert) = footer.finality else {
            without += 1;
            continue;
        };
        match client.verify_finality(&cert) {
            Ok(finalized) => {
                match finalized.finality {
                    Finality::Fast => fast += 1,
                    Finality::Slow => slow += 1,
                }
                // The certified id must be the id we derive for that slot.
                if let Some(target) = blocks.get(&finalized.block.slot) {
                    if target.block() != finalized.block {
                        println!(
                            "slot {slot}: certificate names a different id for slot {}",
                            finalized.block.slot
                        );
                        failed = true;
                    }
                }
                certs.insert(finalized.block.slot, cert);
            }
            Err(error) => {
                println!(
                    "slot {slot}: certificate for slot {} rejected: {error}",
                    cert.block().slot
                );
                bad += 1;
                failed = true;
            }
        }
    }
    println!(
        "footer certificates: {fast} fast and {slow} slow verified, {bad} rejected, {without} footers without one"
    );

    // A certificate signed for another cluster must not verify here.
    if let Some(cert) = certs.values().next() {
        let other = ThinClient::new(ClusterParams::mainnet(shred_version.wrapping_add(1)));
        let mut other = other;
        for epoch in &epochs {
            other
                .trust_validator_set(*epoch, set.clone(), &pinned)
                .unwrap();
        }
        match other.verify_finality(cert) {
            Err(Error::SignatureMismatch) => {
                println!("wrong shred version: rejected, as it should be")
            }
            result => {
                println!("wrong shred version: expected a signature mismatch, got {result:?}");
                failed = true;
            }
        }
    }

    // ---- 3. Transactions: prove, encode, decode, verify.
    let hops: usize = std::env::var("HOPS")
        .ok()
        .and_then(|h| h.parse().ok())
        .unwrap_or(0);
    let (mut proven, mut smallest, mut largest) = (0usize, usize::MAX, 0usize);
    for text in &args[4..] {
        let Some(signature) = base58_signature(text) else {
            println!("{text}: not a base58 signature");
            failed = true;
            continue;
        };
        let short = &text[..text.len().min(12)];
        let Some((&slot, _)) = blocks
            .iter()
            .find(|(_, block)| block.signatures().contains(&signature))
        else {
            println!("{short}…: not in any dumped block");
            failed = true;
            continue;
        };
        // The nearest certified block at or after the transaction's, and the
        // chain of parents from it back down.
        let Some((&certified, cert)) = certs.range(slot..).nth(hops) else {
            println!("{short}…: slot {slot}, no certificate at or after it in the dump");
            failed = true;
            continue;
        };
        let mut chain = vec![&blocks[&certified]];
        while chain.last().unwrap().block().slot != slot {
            let parent = chain.last().unwrap().parent();
            match blocks.get(&parent.slot) {
                Some(block) if parent.slot >= slot => chain.push(block),
                _ => break,
            }
        }
        if chain.last().unwrap().block().slot != slot {
            println!("{short}…: slot {slot} is not an ancestor of certified slot {certified}");
            failed = true;
            continue;
        }
        let result = prover::prove(cert.clone(), &chain, &signature, true).and_then(|proof| {
            let bytes = proof.to_bytes();
            let decoded = TxProof::from_bytes(&bytes, &Limits::default())?;
            let verified = client.verify_signature(&decoded, &signature)?;
            Ok((bytes.len(), verified))
        });
        match result {
            Ok((size, verified)) => {
                proven += 1;
                smallest = smallest.min(size);
                largest = largest.max(size);
                if args.len() > 4 + 16 {
                    continue;
                }
                let memo = verified
                    .transaction
                    .memos()
                    .next()
                    .map(|m| String::from_utf8_lossy(m).into_owned())
                    .unwrap_or_default();
                println!(
                    "{short}…: verified in slot {} via a {:?} certificate on slot {} ({} hops), proof {size} bytes, time {:?}, memo {memo:?}",
                    verified.block.slot,
                    verified.finalized_by.finality,
                    verified.finalized_by.block.slot,
                    chain.len() - 1,
                    verified.block_time_nanos().map(|n| n / 1_000_000_000),
                );
            }
            Err(error) => {
                println!("{short}…: slot {slot}: {error}");
                failed = true;
            }
        }
    }

    if proven > 0 {
        println!(
            "transactions: {proven} of {} proven and verified, proofs {smallest} to {largest} bytes",
            args.len() - 4
        );
    }
    if failed {
        println!("FAILED");
        ExitCode::FAILURE
    } else {
        println!("ok");
        ExitCode::SUCCESS
    }
}
