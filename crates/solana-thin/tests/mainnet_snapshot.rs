//! Real mainnet data: the validators admitted for one epoch, with their keys,
//! and four certificates the cluster made with that set.
//!
//! `tests/vectors/mainnet-vote-accounts.json` is the output of
//! `tools/fetch_vote_accounts.py` against api.mainnet-beta.solana.com during
//! epoch 1095 (November 2026, a month after Alpenglow went live): the 664
//! vote accounts that paid that epoch's admission ticket. Those are the
//! members of the set for epoch 1096, and their keys are right.
//!
//! Their stake is not quite what the cluster froze. The snapshot is taken at
//! the epoch's first block, before the staking rewards for the epoch that
//! just ended are paid out over the blocks that follow. `getVoteAccounts`
//! then reports stake with those rewards in it. On mainnet that put eight
//! small validators at the wrong rank, and one misplaced rank fails every
//! certificate. Two of them did most of the damage: their delegators had
//! left, and what RPC reported as 77 and 46 SOL of stake was 2 and 3 SOL
//! plus the last rewards on the stake that had gone.
//!
//! `tests/vectors/mainnet-certificates-1096.json` holds four finality
//! certificates from epoch 1096 (slots 473,475,739 to 473,475,742, read from
//! the footers of the blocks after them) and, for each validator, the stake
//! the cluster froze. That comes from the epoch-stakes map every bank
//! snapshot carries: three unrelated mainnet nodes served snapshots at three
//! different slots, and the maps in them were identical. The set built from
//! it ranks in the order of Agave's own rank map and has the hash pinned
//! below.

use serde_json::Value;
use solana_thin::*;

/// The hash of the set mainnet used in epoch 1096.
const EPOCH_1096_SET_HASH: &str =
    "87318834564a8a118f5377ac93a24955d914ddc4aa91665a4acbb49e49d93a68";

/// The hash of the set mainnet used in epoch 1097, fixed during epoch 1096.
const EPOCH_1097_SET_HASH: &str =
    "f546d44b5bca3e465839870dde98ca0bc1116ec4baba637f044c456dffd4c9b3";

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

fn certificates() -> (u16, u64, Vec<FinalityCert>, Value) {
    let doc: Value =
        serde_json::from_str(include_str!("vectors/mainnet-certificates-1096.json")).unwrap();
    let certs = fast_certificates(&doc);
    (
        doc["shred_version"].as_u64().unwrap() as u16,
        doc["epoch"].as_u64().unwrap(),
        certs,
        doc["stake_in_epoch_stakes"].clone(),
    )
}

fn fast_certificates(doc: &Value) -> Vec<FinalityCert> {
    let bytes = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    doc["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| FinalityCert::Fast {
            block: BlockRef {
                slot: c["slot"].as_u64().unwrap(),
                id: bytes(&c["block_id"]).try_into().unwrap(),
            },
            notar: Aggregate {
                signature: bytes(&c["signature"]).try_into().unwrap(),
                bitmap: bytes(&c["bitmap"]),
            },
        })
        .collect()
}

fn verdicts(
    shred_version: u16,
    epoch: u64,
    set: &ValidatorSet,
    certs: &[FinalityCert],
) -> Vec<Result<Finality>> {
    let mut client = ThinClient::new(ClusterParams::mainnet(shred_version));
    client
        .trust_validator_set(epoch, set.clone(), &set.hash())
        .unwrap();
    certs
        .iter()
        .map(|c| client.verify_finality(c).map(|f| f.finality))
        .collect()
}

/// The stake `getVoteAccounts` reports in the middle of an epoch is not the
/// stake the cluster ranks validators by. Real certificates say so.
#[test]
fn stake_fetched_after_rewards_are_paid_ranks_the_set_wrongly() {
    let (fetched_in, mut accounts) = accounts();
    let (shred_version, epoch, certs, frozen) = certificates();
    assert_eq!(epoch, fetched_in + 1);
    assert_eq!(certs.len(), 4);

    // As fetched: every certificate is refused, and on the signature, because
    // the signer bitmap names ranks and some ranks hold the wrong key.
    let as_fetched = ValidatorSet::from_vote_accounts(&accounts).unwrap();
    for verdict in verdicts(shred_version, epoch, &as_fetched, &certs) {
        assert_eq!(verdict, Err(Error::SignatureMismatch));
    }

    // With the stake the cluster froze, all four verify, and the set is the
    // one a client should have pinned for epoch 1096.
    let mut unpaid = 0;
    for account in &mut accounts {
        let stake = frozen[hex::encode(account.vote_pubkey)].as_u64().unwrap();
        // Rewards only ever add: RPC never reports less than was frozen, and
        // reports exactly it for a validator whose delegators earned nothing.
        assert!(account.stake >= stake);
        unpaid += usize::from(account.stake == stake);
        account.stake = stake;
    }
    assert_eq!(unpaid, 68);
    let at_first_block = ValidatorSet::from_vote_accounts(&accounts).unwrap();
    assert_eq!(hex::encode(at_first_block.hash()), EPOCH_1096_SET_HASH);
    for verdict in verdicts(shred_version, epoch, &at_first_block, &certs) {
        assert_eq!(verdict, Ok(Finality::Fast));
    }

    // Same members, and only a few small validators changed rank.
    assert_eq!(at_first_block.len(), as_fetched.len());
    let moved: Vec<usize> = (0..as_fetched.len())
        .filter(|&rank| {
            as_fetched.validators()[rank].bls_pubkey != at_first_block.validators()[rank].bls_pubkey
        })
        .collect();
    assert_eq!(moved, (649..=656).collect::<Vec<_>>());
    assert!(moved
        .iter()
        .all(|&rank| as_fetched.validators()[rank].stake < 100_000_000_000));
    println!(
        "{} of {} ranks differ; set hash as fetched {}, as frozen {}",
        moved.len(),
        as_fetched.len(),
        hex::encode(as_fetched.hash()),
        hex::encode(at_first_block.hash())
    );
}

/// A certificate proves the order of the set and nothing about its stake.
///
/// Stake that keeps every validator at its rank passes the signature check,
/// so "it verified a real certificate" cannot be what vouches for a set
/// hash. Here the top validator, 4% of the cluster, is given 200 times its
/// stake. The real certificates still verify, and under that set its
/// signature alone would be a fast certificate.
#[test]
fn a_certificate_does_not_vouch_for_the_stake_in_a_set() {
    let (_, mut accounts) = accounts();
    let (shred_version, epoch, certs, frozen) = certificates();
    for account in &mut accounts {
        account.stake = frozen[hex::encode(account.vote_pubkey)].as_u64().unwrap();
    }
    let honest = ValidatorSet::from_vote_accounts(&accounts).unwrap();

    // Keep the order and inflate the top validator: ranks, keys and
    // signatures are untouched, only the weights change.
    let mut validators = honest.validators().to_vec();
    validators[0].stake = validators[0].stake.checked_mul(200).unwrap();
    let inflated = ValidatorSet::from_ranked(validators).unwrap();
    assert_ne!(inflated.hash(), honest.hash());
    for verdict in verdicts(shred_version, epoch, &inflated, &certs) {
        assert_eq!(verdict, Ok(Finality::Fast));
    }
    // That validator now holds more than 80% by this set's count.
    let top = u128::from(inflated.validators()[0].stake);
    assert!(top * 5 > u128::from(inflated.total_stake()) * 4);
}

/// A set read before its epoch began is the set its epoch used.
///
/// The set for epoch 1097 was taken from the epoch-stakes map in a bank
/// snapshot of slot 473,835,192, in epoch 1096, about seven hours before
/// epoch 1097 started, and its hash was written down then. The four
/// certificates are from the first minutes of epoch 1097, read from the
/// footers of the blocks after them. Nothing about them was known when the
/// hash was fixed.
#[test]
fn a_set_fixed_a_day_ahead_verifies_its_epochs_certificates() {
    let doc: Value =
        serde_json::from_str(include_str!("vectors/mainnet-certificates-1097.json")).unwrap();
    let epoch = doc["epoch"].as_u64().unwrap();
    let shred_version = doc["shred_version"].as_u64().unwrap() as u16;
    let snapshot_slot = doc["snapshot_slot"].as_u64().unwrap();
    let params = ClusterParams::mainnet(shred_version);
    assert_eq!(params.epoch_of(snapshot_slot), Ok(epoch - 1));

    let set_bytes = hex::decode(doc["validator_set"].as_str().unwrap()).unwrap();
    let pinned: Hash = hex::decode(EPOCH_1097_SET_HASH)
        .unwrap()
        .try_into()
        .unwrap();
    let mut client = ThinClient::new(params);
    client
        .trust_validator_set_bytes(epoch, &set_bytes, &pinned)
        .unwrap();

    let certs = fast_certificates(&doc);
    assert_eq!(certs.len(), 4);
    for cert in &certs {
        let FinalityCert::Fast { block, .. } = cert else {
            unreachable!()
        };
        assert_eq!(params.epoch_of(block.slot), Ok(epoch));
        assert_eq!(
            client.verify_finality(cert).map(|f| f.finality),
            Ok(Finality::Fast)
        );
    }

    // The set of the epoch before, exact for its own epoch, is the wrong
    // one for these.
    let (_, mut accounts) = accounts();
    let (_, _, _, frozen) = certificates();
    for account in &mut accounts {
        account.stake = frozen[hex::encode(account.vote_pubkey)].as_u64().unwrap();
    }
    let set_1096 = ValidatorSet::from_vote_accounts(&accounts).unwrap();
    let mut stale = ThinClient::new(params);
    stale
        .trust_validator_set(epoch, set_1096.clone(), &set_1096.hash())
        .unwrap();
    for cert in &certs {
        assert!(stale.verify_finality(cert).is_err());
    }
}

#[cfg(feature = "unsound-stale-set")]
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
