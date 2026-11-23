//! Real mainnet data: the validators admitted for one epoch, with their keys.
//!
//! `tests/vectors/mainnet-vote-accounts.json` is the output of
//! `tools/fetch_vote_accounts.py` against api.mainnet-beta.solana.com during
//! epoch 1095 (November 2026, a month after Alpenglow went live): the 664
//! vote accounts that paid that epoch's admission ticket, which is the set
//! for epoch 1096. It checks the parts of this crate that touch live
//! validator data: key decoding, subgroup checks, ranking and the set
//! commitment.
//!
//! It does not check a live certificate. Public RPC does not serve them yet;
//! see the README.

use serde_json::Value;
use solana_thin::*;

fn accounts() -> (u64, Vec<VoteAccount>) {
    let doc: Value =
        serde_json::from_str(include_str!("vectors/mainnet-vote-accounts.json")).unwrap();
    let hex32 = |v: &Value| -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let accounts = doc["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| VoteAccount {
            vote_pubkey: hex32(&a["vote_pubkey"]),
            node_pubkey: hex32(&a["node_pubkey"]),
            bls_pubkey: a["bls_pubkey"]
                .as_str()
                .map(|s| hex::decode(s).unwrap().try_into().unwrap()),
            stake: a["stake"].as_u64().unwrap(),
        })
        .collect();
    (doc["fetched_in_epoch"].as_u64().unwrap(), accounts)
}

#[test]
fn the_live_validator_set_builds_and_commits() {
    let (epoch, accounts) = accounts();
    let with_key = accounts.iter().filter(|a| a.bls_pubkey.is_some()).count();
    let set = ValidatorSet::from_vote_accounts(&accounts).unwrap();

    // Every registered key on mainnet is a valid point in the right subgroup:
    // nothing was dropped beyond accounts with no key or no stake.
    let staked_with_key = accounts
        .iter()
        .filter(|a| a.bls_pubkey.is_some() && a.stake > 0)
        .count();
    assert_eq!(set.len(), staked_with_key);
    assert!(set.len() > 500, "only {} validators", set.len());

    // Rank order is what `from_ranked` demands, and the commitment is stable
    // across a round trip through bytes.
    let bytes = set.to_bytes();
    assert_eq!(bytes.len(), 4 + 56 * set.len());
    let again = ValidatorSet::from_bytes(&bytes).unwrap();
    assert_eq!(again.hash(), set.hash());

    // How concentrated is stake? This is what decides certificate sizes and
    // how few validators a fast certificate needs.
    let total = u128::from(set.total_stake());
    let reach = |bps: u128| {
        let mut sum = 0u128;
        set.validators()
            .iter()
            .position(|v| {
                sum += u128::from(v.stake);
                sum * 10_000 >= total * bps
            })
            .unwrap()
            + 1
    };
    println!(
        "fetched in epoch {epoch}: {} vote accounts, {with_key} with a BLS key, {} ranked",
        accounts.len(),
        set.len()
    );
    println!(
        "total stake {:.1}M SOL; top {} validators hold 60%, top {} hold 80%",
        set.total_stake() as f64 / 1e15,
        reach(6_000),
        reach(8_000)
    );
    println!(
        "validator set: {} bytes, bitmap {} bytes, set hash {}",
        bytes.len(),
        3 + set.len().div_ceil(8),
        hex::encode(set.hash())
    );
}

#[test]
fn live_keys_work_as_a_candidate_list() {
    let (_, accounts) = accounts();
    let set = ValidatorSet::from_vote_accounts(&accounts).unwrap();
    let candidates = set
        .validators()
        .iter()
        .map(|v| Candidate {
            bls_pubkey: v.bls_pubkey,
            proof_of_possession: None,
        })
        .collect();
    assert_eq!(CandidateSet::new(candidates).unwrap().len(), set.len());
}
