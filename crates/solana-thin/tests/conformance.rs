//! Agreement with the validator.
//!
//! `tests/vectors/agave-v4.4.1.json` is written by `tools/agave-fixtures`,
//! which links Agave v4.4.1 (the release mainnet ran when Alpenglow went
//! live). Nothing in that file that this crate has an opinion about was
//! produced by this crate:
//!
//! * the blocks were serialized and shredded by Agave, real Reed-Solomon
//!   coding shreds included, and their ids read back from an Agave blockstore;
//! * vote payloads, signatures and bitmaps came from Agave's consensus crates;
//! * every certificate carries the verdict of Agave's own verifier;
//! * the validator ranking is Agave's.
//!
//! These tests check that this crate computes the same ids, parses the same
//! structure, and reaches the same verdicts.

use serde_json::Value;
use solana_thin::block::TxPosition;
use solana_thin::certificate::{finalize_payload, notarize_payload};
use solana_thin::prover::{self, BlockData};
use solana_thin::*;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/agave-v4.4.1.json")).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).unwrap()
}

fn array<const N: usize>(v: &Value) -> [u8; N] {
    bytes(v).try_into().expect("length")
}

fn aggregate(v: &Value) -> Aggregate {
    Aggregate {
        signature: array(&v["signature"]),
        bitmap: bytes(&v["bitmap"]),
    }
}

fn validator_set(v: &Value) -> ValidatorSet {
    let ranked = v["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| Validator {
            bls_pubkey: array(&entry["bls_pubkey"]),
            stake: entry["stake"].as_u64().unwrap(),
        })
        .collect();
    ValidatorSet::from_ranked(ranked).unwrap()
}

fn client(v: &Value) -> ThinClient {
    let version = v["shred_version"].as_u64().unwrap() as u16;
    let mut client = ThinClient::new(ClusterParams::mainnet(version));
    let set = validator_set(v);
    let hash = set.hash();
    let slot = v["blocks"][0]["slot"].as_u64().unwrap();
    let epoch = client.params().epoch_of(slot).unwrap();
    client.trust_validator_set(epoch, set, &hash).unwrap();
    client
}

fn blocks(v: &Value) -> Vec<BlockData> {
    v["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|block| {
            let shreds: Vec<Vec<u8>> = block["data_shreds"]
                .as_array()
                .unwrap()
                .iter()
                .map(bytes)
                .collect();
            BlockData::from_shreds(&shreds).unwrap()
        })
        .collect()
}

#[test]
fn block_ids_match_the_blockstore() {
    let v = vectors();
    for (json, block) in v["blocks"].as_array().unwrap().iter().zip(blocks(&v)) {
        assert_eq!(block.block().slot, json["slot"].as_u64().unwrap());
        assert_eq!(block.block().id, array::<32>(&json["block_id"]), "block id");
        assert_eq!(block.parent().slot, json["parent_slot"].as_u64().unwrap());
        assert_eq!(block.parent().id, array::<32>(&json["parent_id"]));
        // Every FEC set is 32 data shreds of 1,203 bytes.
        let shreds = json["data_shreds"].as_array().unwrap();
        assert_eq!(shreds.len() % 32, 0);
        assert!(shreds.iter().all(|s| bytes(s).len() == 1203));
    }
}

#[test]
fn vote_payloads_match() {
    let v = vectors();
    let p = &v["vote_payloads"];
    let block = BlockRef {
        slot: p["slot"].as_u64().unwrap(),
        id: array(&p["block_id"]),
    };
    let version = v["shred_version"].as_u64().unwrap() as u16;
    assert_eq!(
        notarize_payload(&block, version).to_vec(),
        bytes(&p["notarize"])
    );
    assert_eq!(
        finalize_payload(block.slot, version).to_vec(),
        bytes(&p["finalize"])
    );
}

#[test]
fn certificate_verdicts_match_agaves_verifier() {
    let v = vectors();
    let client = client(&v);
    let (mut accepted, mut rejected) = (0, 0);
    for case in v["certificates"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let block = BlockRef {
            slot: case["slot"].as_u64().unwrap(),
            id: array(&case["block_id"]),
        };
        let cert = match case["kind"].as_str().unwrap() {
            "fast" => FinalityCert::Fast {
                block,
                notar: aggregate(&case["notar"]),
            },
            "slow" => FinalityCert::Slow {
                block,
                finalize: aggregate(&case["finalize"]),
                notar: aggregate(&case["notar"]),
            },
            other => panic!("unknown kind {other}"),
        };
        let ours = client.verify_finality(&cert);
        let agave = case["agave_accepts"].as_bool().unwrap();
        assert_eq!(
            ours.is_ok(),
            agave,
            "{name}: we said {ours:?}, Agave said {agave}"
        );
        if agave {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    // The vectors exercise both outcomes.
    assert!(
        accepted >= 4 && rejected >= 8,
        "{accepted} accepted, {rejected} rejected"
    );
}

#[test]
fn validator_ranking_matches_bls_pubkey_to_rank_map() {
    let v = vectors();
    let ranking = &v["ranking"];
    let accounts: Vec<VoteAccount> = ranking["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| VoteAccount {
            vote_pubkey: array(&a["vote_pubkey"]),
            node_pubkey: array(&a["node_pubkey"]),
            bls_pubkey: (!a["bls_pubkey"].is_null()).then(|| array(&a["bls_pubkey"])),
            stake: a["stake"].as_u64().unwrap(),
        })
        .collect();
    let set = ValidatorSet::from_vote_accounts(&accounts).unwrap();
    let expected: Vec<Validator> = ranking["ranked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| Validator {
            bls_pubkey: array(&entry["bls_pubkey"]),
            stake: entry["stake"].as_u64().unwrap(),
        })
        .collect();
    assert_eq!(set.validators(), expected.as_slice());
    assert_eq!(set.total_stake(), ranking["total_stake"].as_u64().unwrap());
    // Zero-stake accounts and the pair sharing a key were dropped.
    assert!(set.len() < accounts.len());
}

#[test]
fn proofs_of_possession_verify_as_the_vote_program_would() {
    let v = vectors();
    let cases = v["proofs_of_possession"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let key: [u8; 48] = array(&case["bls_pubkey"]);
        let pop = ProofOfPossession {
            vote_pubkey: array(&case["vote_pubkey"]),
            signature: array(&case["proof_of_possession"]),
        };
        assert!(pop.verify(&key));
        let mut wrong_account = pop;
        wrong_account.vote_pubkey[0] ^= 1;
        assert!(!wrong_account.verify(&key));
    }
}

/// The certificate a leader embedded in block `i`'s footer.
fn footer_cert(block: &BlockData) -> FinalityCert {
    block
        .footer()
        .expect("block has a footer")
        .1
        .finality
        .expect("footer carries a certificate")
}

#[test]
fn every_agave_transaction_is_provable_and_parses_identically() {
    let v = vectors();
    let client = client(&v);
    let blocks = blocks(&v);
    let json_blocks = v["blocks"].as_array().unwrap();

    // Certificates as they occur on the ledger: block 2's footer finalizes
    // block 1 (fast), block 3's footer finalizes block 2 (slow). Block 3 gets
    // a certificate from the vector list.
    let cert_1 = footer_cert(&blocks[1]);
    let cert_2 = footer_cert(&blocks[2]);
    assert!(matches!(cert_1, FinalityCert::Fast { .. }));
    assert!(matches!(cert_2, FinalityCert::Slow { .. }));
    assert_eq!(cert_1.block(), blocks[0].block());
    assert_eq!(cert_2.block(), blocks[1].block());
    let first = &v["certificates"][0];
    let cert_3 = FinalityCert::Fast {
        block: blocks[2].block(),
        notar: aggregate(&first["notar"]),
    };
    assert_eq!(
        client.verify_finality(&cert_1).unwrap().finality,
        Finality::Fast
    );
    assert_eq!(
        client.verify_finality(&cert_2).unwrap().finality,
        Finality::Slow
    );
    let certs = [cert_1, cert_2, cert_3.clone()];

    let mut proven = 0;
    let mut versions = std::collections::BTreeMap::new();
    for (i, (json, block)) in json_blocks.iter().zip(&blocks).enumerate() {
        let footer = &json["footer"];
        for tx in json["transactions"].as_array().unwrap() {
            let signature: [u8; 64] = array(&tx["signature"]);

            // Certified directly...
            let direct = prover::prove(certs[i].clone(), &[block], &signature, true).unwrap();
            // ...and through a descendant's certificate.
            let chain: Vec<&BlockData> = blocks[i..].iter().rev().collect();
            let chained = prover::prove(cert_3.clone(), &chain, &signature, false).unwrap();
            assert_eq!(chained.ancestry.len(), 2 - i);

            for proof in [&direct, &chained] {
                let encoded = proof.to_bytes();
                let verified = client.verify_transaction_bytes(&encoded).unwrap();
                assert_eq!(verified.transaction.signature(), &signature);
                assert_eq!(verified.transaction.message, bytes(&tx["message"]));
                assert_eq!(verified.block, block.block());
                assert_eq!(
                    verified.component_start,
                    tx["component_start"].as_u64().unwrap() as u32
                );
                assert_eq!(
                    verified.position,
                    TxPosition {
                        entry: tx["entry"].as_u64().unwrap() as u32,
                        transaction: tx["transaction"].as_u64().unwrap() as u32,
                    }
                );
                // Our parse of the whole transaction equals a parse of the
                // bytes Agave serialized for it.
                assert_eq!(
                    verified.transaction,
                    Transaction::parse(&bytes(&tx["wire"])).unwrap()
                );
            }

            let verified = client.verify_transaction(&direct).unwrap();
            *versions
                .entry(format!("{:?}", verified.transaction.version))
                .or_insert(0) += 1;
            if verified.transaction.signatures.len() > 1 {
                *versions.entry("multi-signer".to_string()).or_insert(0) += 1;
            }
            let opened = verified.footer.expect("footer opened");
            assert_eq!(opened.bank_hash, array::<32>(&footer["bank_hash"]));
            assert_eq!(
                opened.producer_time_nanos,
                footer["producer_time_nanos"].as_u64().unwrap()
            );
            assert_eq!(opened.user_agent, bytes(&footer["user_agent"]));
            assert_eq!(
                direct.footer_start,
                Some(footer["start"].as_u64().unwrap() as u32)
            );
            proven += 1;
        }
    }
    assert!(proven >= 240, "only {proven} transactions in the vectors");
    // All three encodings, and transactions with more than one signature.
    println!("agave transactions proven: {proven} {versions:?}");
    for kind in ["Legacy", "V0", "V1", "multi-signer"] {
        assert!(
            versions.get(kind).copied().unwrap_or(0) >= 2,
            "too few {kind}"
        );
    }
}

#[test]
fn memos_written_by_agave_are_found() {
    let v = vectors();
    let client = client(&v);
    let blocks = blocks(&v);
    let cert = footer_cert(&blocks[2]);
    let mut anchors = 0;
    for signature in blocks[1].signatures() {
        let proof = prover::prove(cert.clone(), &[&blocks[1]], &signature, false).unwrap();
        let verified = client.verify_signature(&proof, &signature).unwrap();
        if verified.has_memo(b"anchor") {
            anchors += 1;
        }
    }
    assert_eq!(anchors, 1);
}

#[test]
fn agave_shreds_reject_tampering() {
    let v = vectors();
    let client = client(&v);
    let blocks = blocks(&v);
    let cert = footer_cert(&blocks[1]);
    let signature = blocks[0].signatures()[1];
    let good = prover::prove(cert, &[&blocks[0]], &signature, false).unwrap();
    assert!(client.verify_transaction(&good).is_ok());
    let mut bad = good.clone();
    let shred = bad
        .block
        .sets
        .last_mut()
        .unwrap()
        .shreds
        .last_mut()
        .unwrap();
    shred.body[20] ^= 0x80;
    assert_eq!(client.verify_transaction(&bad), Err(Error::BlockIdMismatch));
}
