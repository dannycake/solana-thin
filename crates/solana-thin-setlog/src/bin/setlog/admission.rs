//! The admission check: are the accounts a source says are members the ones
//! the cluster admitted?
//!
//! At the first block of epoch `E - 1` the cluster picks the vote accounts
//! that may enter the set for `E` (SIMD-0357: stake, a BLS key, the balance
//! for a ticket, the 2,000 with most stake), stores them as `E`'s
//! epoch-stakes map, and charges each of them the ticket. The charge is
//! listed in that block's rewards as a `VATDebit`. In Agave 4.4.1 the map is
//! filtered by `VoteAccounts::clone_and_filter_for_vat` and every account in
//! it is charged by `Bank::maybe_burn_vat_from_staked_accounts`.
//!
//! So the debited accounts are exactly the map a snapshot stores for `E`.
//! The rank map is built from that map afterwards and leaves out every
//! account that shares a BLS key or node identity with another
//! (`BLSPubkeyToRankMap::new`): it is the debited accounts less those.

use crate::sources::{epoch_schedule, read, unbase58, Pubkey, Ranked};
use serde::Deserialize;
use serde_json::json;
use solana_thin_setlog::rpc::Rpc;
use solana_thin_setlog::{Source, KIND_ADMISSION};
use std::collections::{BTreeMap, BTreeSet};

/// The label of the check in a record. Fixed, so that no part of a URL,
/// which can carry an API key, is written down; the slot says which block.
pub const LABEL: &str = "vat-debits";

/// The program that owns every vote account.
const VOTE_PROGRAM: &str = "Vote111111111111111111111111111111111111111";

/// Most accounts named in one refusal; the rest are counted.
const MAX_NAMED: usize = 20;

/// The accounts charged the admission ticket in one block.
pub struct Debits {
    /// The block: the first of the epoch before the set's.
    pub slot: u64,
    pub accounts: BTreeSet<Pubkey>,
}

impl Debits {
    /// The source that records the check in a set file and a record.
    pub fn source(&self) -> Source {
        Source::new(KIND_ADMISSION, LABEL, self.slot).expect("a valid kind and label")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Block {
    parent_slot: u64,
    rewards: Option<Vec<Reward>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reward {
    pubkey: String,
    reward_type: Option<String>,
}

/// Reads from the node at `url` the accounts debited in the block that
/// admitted the set for `set_epoch`.
///
/// No debits at all is a refusal, not a pass: it means admission was not
/// in force or the node keeps no rewards, and either way there is nothing
/// to check against.
pub fn fetch(rpc: &Rpc, url: &str, set_epoch: u64) -> Result<Debits, String> {
    let admitted_in = set_epoch
        .checked_sub(1)
        .ok_or("no block admits the set of epoch 0")?;
    let schedule = epoch_schedule(rpc, url)?;
    let (start, end) = (
        schedule.first_slot(admitted_in)?,
        schedule.first_slot(set_epoch)?,
    );
    // The first slots of an epoch may have been skipped.
    let method = "getBlocksWithLimit";
    let slots: Vec<u64> = read(
        method,
        rpc.call(url, method, json!([start, 1, {"commitment": "finalized"}]))?,
    )?;
    let Some(&slot) = slots.first() else {
        return Err(format!(
            "{method}: no finalized block from slot {start}, where epoch {admitted_in} begins"
        ));
    };
    if !(start..end).contains(&slot) {
        return Err(format!(
            "{method}: the first block from slot {start} is at {slot}, outside epoch {admitted_in}"
        ));
    }
    let method = "getBlock";
    let config = json!({"encoding": "json", "transactionDetails": "none", "rewards": true,
                        "commitment": "finalized", "maxSupportedTransactionVersion": 0});
    let block: Block = read(method, rpc.call(url, method, json!([slot, config]))?)?;
    // A node that no longer has the first block may offer a later one.
    if block.parent_slot >= start {
        return Err(format!(
            "the block at slot {slot} is not the first of epoch {admitted_in}: \
             its parent, {}, is in that epoch too",
            block.parent_slot
        ));
    }
    let mut accounts = BTreeSet::new();
    for reward in block.rewards.unwrap_or_default() {
        if reward.reward_type.as_deref() != Some("VATDebit") {
            continue;
        }
        let account = unbase58(&reward.pubkey).ok_or_else(|| {
            format!(
                "{method}: a VATDebit to {:?}, which is not an address",
                reward.pubkey
            )
        })?;
        if !accounts.insert(account) {
            return Err(format!("{method}: {} is debited twice", reward.pubkey));
        }
    }
    if accounts.is_empty() {
        return Err(format!(
            "the block at slot {slot}, the first of epoch {admitted_in}, lists no VATDebit \
             rewards: admission was not in force, or the node keeps no rewards, and there \
             is nothing to check the members against"
        ));
    }
    Ok(Debits { slot, accounts })
}

/// Base-58 addresses, at most [`MAX_NAMED`] of them.
fn names<'a>(accounts: impl ExactSizeIterator<Item = &'a Pubkey>) -> String {
    let count = accounts.len();
    let mut text: Vec<String> = accounts
        .take(MAX_NAMED)
        .map(|account| bs58::encode(account).into_string())
        .collect();
    if count > MAX_NAMED {
        text.push(format!("and {} more", count - MAX_NAMED));
    }
    text.join(", ")
}

/// Checks the members of an epoch-stakes map, as a snapshot stores it: the
/// map is the set of accounts admitted, so it must equal the debits.
pub fn check_map(debits: &Debits, members: &BTreeSet<Pubkey>) -> Result<(), String> {
    let not_debited: Vec<&Pubkey> = members.difference(&debits.accounts).collect();
    let not_listed: Vec<&Pubkey> = debits.accounts.difference(members).collect();
    let mut why = Vec::new();
    if !not_debited.is_empty() {
        why.push(format!(
            "{} in the map but not debited: {}",
            not_debited.len(),
            names(not_debited.into_iter())
        ));
    }
    if !not_listed.is_empty() {
        why.push(format!(
            "{} debited but not in the map: {}",
            not_listed.len(),
            names(not_listed.into_iter())
        ));
    }
    if why.is_empty() {
        return Ok(());
    }
    Err(format!(
        "its map is not the accounts admitted in the block at slot {}: {}",
        debits.slot,
        why.join("; ")
    ))
}

/// A vote account's node identity and BLS key, if it is a vote account
/// with a BLS key.
pub type Keys = Option<(Pubkey, [u8; 48])>;

/// Checks a rank map: it must be the debited accounts less every one that
/// shares a BLS key or node identity with another. Returns how many debited
/// accounts it leaves out for that.
///
/// The rank map gives the keys of the accounts it ranks, as the cluster
/// froze them. The keys of the accounts it leaves out come from `keys_now`,
/// which reads their vote accounts as they are now. A key changed since the
/// block can make this refuse a right rank map, or let pass one that leaves
/// out accounts which only came to share a key later.
pub fn check_rank_map(
    debits: &Debits,
    ranked: &[Ranked],
    keys_now: impl FnOnce(&[Pubkey]) -> Result<Vec<Keys>, String>,
) -> Result<usize, String> {
    let in_map: BTreeSet<Pubkey> = ranked.iter().map(|r| r.vote_pubkey).collect();
    if in_map.len() != ranked.len() {
        return Err("it ranks one vote account twice".into());
    }
    let not_debited: Vec<&Pubkey> = in_map.difference(&debits.accounts).collect();
    if !not_debited.is_empty() {
        return Err(format!(
            "{} ranked but not debited in the block at slot {}: {}",
            not_debited.len(),
            debits.slot,
            names(not_debited.into_iter())
        ));
    }
    let left_out: Vec<Pubkey> = debits.accounts.difference(&in_map).copied().collect();
    if left_out.is_empty() {
        return Ok(0);
    }
    let keys = keys_now(&left_out)?;
    if keys.len() != left_out.len() {
        return Err("the keys read do not match the accounts asked for".into());
    }

    // The cluster counted keys over every debited account.
    let mut by_node: BTreeMap<Pubkey, usize> = BTreeMap::new();
    let mut by_key: BTreeMap<[u8; 48], usize> = BTreeMap::new();
    let ranked_keys = ranked.iter().map(|r| (r.node_pubkey, r.bls_pubkey));
    for (node, key) in ranked_keys.chain(keys.iter().flatten().copied()) {
        *by_node.entry(node).or_default() += 1;
        *by_key.entry(key).or_default() += 1;
    }
    let shares = |node: &Pubkey, key: &[u8; 48]| by_node[node] > 1 || by_key[key] > 1;

    let unknown: Vec<&Pubkey> = left_out
        .iter()
        .zip(&keys)
        .filter_map(|(account, keys)| keys.is_none().then_some(account))
        .collect();
    let alone: Vec<&Pubkey> = left_out
        .iter()
        .zip(&keys)
        .filter_map(|(account, keys)| {
            let (node, key) = keys.as_ref()?;
            (!shares(node, key)).then_some(account)
        })
        .collect();
    let sharing: Vec<&Pubkey> = ranked
        .iter()
        .filter(|r| shares(&r.node_pubkey, &r.bls_pubkey))
        .map(|r| &r.vote_pubkey)
        .collect();
    let mut why = Vec::new();
    if !unknown.is_empty() {
        why.push(format!(
            "{} debited but not ranked, with no vote account with a BLS key now: {}",
            unknown.len(),
            names(unknown.into_iter())
        ));
    }
    if !alone.is_empty() {
        why.push(format!(
            "{} debited but not ranked, and sharing no BLS key or node identity with another: {}",
            alone.len(),
            names(alone.into_iter())
        ));
    }
    if !sharing.is_empty() {
        why.push(format!(
            "{} ranked, though sharing a BLS key or node identity with an account left out: {}",
            sharing.len(),
            names(sharing.into_iter())
        ));
    }
    if why.is_empty() {
        return Ok(left_out.len());
    }
    Err(format!(
        "it is not the accounts admitted in the block at slot {} less those that share \
         a key: {}",
        debits.slot,
        why.join("; ")
    ))
}

#[derive(Deserialize)]
struct Accounts {
    value: Vec<Option<Account>>,
}

#[derive(Deserialize)]
struct Account {
    /// The bytes asked for and their encoding.
    data: (String, String),
    owner: String,
}

/// Reads the node identity and BLS key of each of `accounts` from the vote
/// account as it is now.
pub fn keys_now(rpc: &Rpc, url: &str, accounts: &[Pubkey]) -> Result<Vec<Keys>, String> {
    let method = "getMultipleAccounts";
    let mut out = Vec::with_capacity(accounts.len());
    // The method takes at most 100 addresses.
    for chunk in accounts.chunks(100) {
        let addresses: Vec<String> = chunk
            .iter()
            .map(|account| bs58::encode(account).into_string())
            .collect();
        let config = json!({"encoding": "base64", "commitment": "finalized",
                            "dataSlice": {"offset": 0, "length": VOTE_STATE_PREFIX}});
        let answer: Accounts = read(method, rpc.call(url, method, json!([addresses, config]))?)?;
        if answer.value.len() != chunk.len() {
            return Err(format!(
                "{method}: asked for {} accounts, told of {}",
                chunk.len(),
                answer.value.len()
            ));
        }
        out.extend(
            answer
                .value
                .iter()
                .map(|account| vote_keys(account.as_ref()?)),
        );
    }
    Ok(out)
}

/// Bytes of a vote account up to the end of its BLS key.
const VOTE_STATE_PREFIX: usize = 193;

fn vote_keys(account: &Account) -> Keys {
    if account.owner != VOTE_PROGRAM || account.data.1 != "base64" {
        return None;
    }
    let data = unbase64(&account.data.0)?;
    // VoteStateV4, version tag 3: the node identity at 4, three more keys,
    // two u16 and a u64, then an optional 48-byte BLS key at 144.
    if data.len() < VOTE_STATE_PREFIX || data[..4] != 3u32.to_le_bytes() || data[144] != 1 {
        return None;
    }
    Some((
        data[4..36].try_into().ok()?,
        data[145..193].try_into().ok()?,
    ))
}

/// Standard base64 with padding: what RPC sends account data in.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    let digits = text
        .strip_suffix("==")
        .or(text.strip_suffix('='))
        .unwrap_or(text);
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    let (mut bits, mut held) = (0u32, 0u32);
    for c in digits.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = bits << 6 | u32::from(value);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use solana_thin_setlog::rpc::testing::Scripted;

    fn b58(key: &[u8]) -> String {
        bs58::encode(key).into_string()
    }

    /// Answers for a node whose epochs are 100 slots from slot 1,000 on
    /// (epoch 10), and whose first block of epoch 19 is at slot 1,902.
    fn answers(debited: &[Pubkey], parent: u64) -> Vec<Value> {
        let mut rewards: Vec<Value> = debited
            .iter()
            .map(|a| {
                json!({"pubkey": b58(a), "lamports": -5, "postBalance": 1,
                            "rewardType": "VATDebit", "commission": null})
            })
            .collect();
        rewards.push(
            json!({"pubkey": b58(&[9; 32]), "lamports": 5, "postBalance": 1,
                            "rewardType": "Fee", "commission": null}),
        );
        vec![
            json!({"firstNormalEpoch": 10, "firstNormalSlot": 1_000, "slotsPerEpoch": 100}),
            json!([1_902]),
            json!({"parentSlot": parent, "rewards": rewards}),
        ]
    }

    fn fetch_from(answers: &[Value]) -> (Result<Debits, String>, Vec<Value>) {
        let bodies: Vec<String> = answers
            .iter()
            .map(|result| json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string())
            .collect();
        let script: Vec<(u16, &str)> = bodies.iter().map(|b| (200, b.as_str())).collect();
        let transport = Scripted::new(&script);
        let result = fetch(&transport.rpc(), "http://node", 20);
        let asked = transport
            .asked
            .borrow()
            .iter()
            .map(|(_, b)| b.clone())
            .collect();
        (result, asked)
    }

    fn refusal(answers: &[Value]) -> String {
        match fetch_from(answers).0 {
            Ok(_) => panic!("not refused"),
            Err(why) => why,
        }
    }

    #[test]
    fn the_debits_of_the_first_block_of_the_epoch_before_are_read() {
        let (debits, asked) = fetch_from(&answers(&[[1; 32], [2; 32]], 1_897));
        let debits = debits.unwrap();
        assert_eq!(debits.slot, 1_902);
        assert_eq!(debits.accounts, [[1; 32], [2; 32]].into());
        assert_eq!(
            debits.source(),
            Source::new(KIND_ADMISSION, "vat-debits", 1_902).unwrap()
        );
        // The set of epoch 20 was admitted at the start of epoch 19.
        assert_eq!(asked[1]["method"], "getBlocksWithLimit");
        assert_eq!(asked[1]["params"][0], 1_900);
        assert_eq!(asked[2]["params"][0], 1_902);
        assert_eq!(asked[2]["params"][1]["rewards"], true);
    }

    #[test]
    fn a_block_that_cannot_be_the_admitting_one_is_refused() {
        let good = answers(&[[1; 32]], 1_897);
        let with = |change: &dyn Fn(&mut Vec<Value>)| {
            let mut answers = good.clone();
            change(&mut answers);
            refusal(&answers)
        };
        assert!(with(&|a| a[2]["parentSlot"] = json!(1_901)).contains("is not the first"));
        assert!(with(&|a| a[1] = json!([2_000])).contains("outside epoch 19"));
        assert!(with(&|a| a[1] = json!([])).contains("no finalized block from slot 1900"));
        let empty = with(&|a| a[2]["rewards"] = json!([]));
        assert!(empty.contains("lists no VATDebit rewards"), "{empty}");
        assert!(with(&|a| a[2]["rewards"] = Value::Null).contains("no VATDebit"));
        let twice = answers(&[[1; 32], [1; 32]], 1_897);
        assert!(refusal(&twice).contains("debited twice"));
        let bad = with(&|a| a[2]["rewards"][0]["pubkey"] = json!("0OIl"));
        assert!(bad.contains("not an address"), "{bad}");

        let transport = Scripted::new(&[]);
        let zero = fetch(&transport.rpc(), "http://node", 0);
        assert!(zero.is_err_and(|why| why.contains("epoch 0")));
    }

    fn debits(accounts: &[u8]) -> Debits {
        Debits {
            slot: 77,
            accounts: accounts.iter().map(|a| [*a; 32]).collect(),
        }
    }

    #[test]
    fn a_map_must_be_the_debits_exactly() {
        let members = |a: &[u8]| a.iter().map(|a| [*a; 32]).collect::<BTreeSet<_>>();
        assert_eq!(check_map(&debits(&[1, 2, 3]), &members(&[3, 2, 1])), Ok(()));
        let why = check_map(&debits(&[1, 2, 3]), &members(&[1, 2, 4])).unwrap_err();
        assert!(
            why.contains(&format!("1 in the map but not debited: {}", b58(&[4; 32])))
                && why.contains(&format!("1 debited but not in the map: {}", b58(&[3; 32])))
                && why.contains("slot 77"),
            "{why}"
        );
        // A long list is cut short.
        let many: Vec<u8> = (10..40).collect();
        let why = check_map(&debits(&many), &members(&[])).unwrap_err();
        assert!(
            why.contains("30 debited") && why.contains("and 10 more"),
            "{why}"
        );
    }

    fn ranked(accounts: &[(u8, u8, u8)]) -> Vec<Ranked> {
        accounts
            .iter()
            .map(|(vote, node, key)| Ranked {
                vote_pubkey: [*vote; 32],
                node_pubkey: [*node; 32],
                bls_pubkey: [*key; 48],
            })
            .collect()
    }

    fn keys(accounts: &[Option<(u8, u8)>]) -> Vec<Keys> {
        accounts
            .iter()
            .map(|k| k.map(|(node, key)| ([node; 32], [key; 48])))
            .collect()
    }

    #[test]
    fn a_rank_map_lacks_exactly_the_accounts_that_share_a_key() {
        let map = ranked(&[(1, 101, 201), (2, 102, 202)]);
        // Nothing left out: the lookup is not made.
        let none = |_: &[Pubkey]| -> Result<Vec<Keys>, String> { panic!("not needed") };
        assert_eq!(check_rank_map(&debits(&[1, 2]), &map, none), Ok(0));

        // Accounts 3 and 4 share a key, 5 and 6 a node identity.
        let looked_up = keys(&[
            Some((103, 9)),
            Some((104, 9)),
            Some((8, 205)),
            Some((8, 206)),
        ]);
        let asked = std::cell::RefCell::new(Vec::new());
        let lookup = |accounts: &[Pubkey]| {
            asked.borrow_mut().extend_from_slice(accounts);
            Ok(looked_up.clone())
        };
        assert_eq!(
            check_rank_map(&debits(&[1, 2, 3, 4, 5, 6]), &map, lookup),
            Ok(4)
        );
        assert_eq!(*asked.borrow(), [[3; 32], [4; 32], [5; 32], [6; 32]]);

        let refused = |looked_up: Vec<Keys>, why: &str| {
            let error =
                check_rank_map(&debits(&[1, 2, 3, 4]), &map, |_| Ok(looked_up)).unwrap_err();
            assert!(error.contains(why), "{why}: {error}");
        };
        refused(
            keys(&[Some((103, 9)), Some((104, 10))]),
            "2 debited but not ranked, and sharing no BLS key or node identity",
        );
        refused(
            keys(&[Some((103, 9)), None]),
            &format!("with no vote account with a BLS key now: {}", b58(&[4; 32])),
        );
        // Account 3 runs on ranked account 1's node, so both would be out.
        refused(
            keys(&[Some((101, 9)), Some((104, 9))]),
            &format!(
                "1 ranked, though sharing a BLS key or node identity with an account left out: {}",
                b58(&[1; 32])
            ),
        );
        refused(
            keys(&[Some((103, 9))]),
            "do not match the accounts asked for",
        );

        let error = check_rank_map(&debits(&[1]), &map, none).unwrap_err();
        assert!(
            error.contains(&format!(
                "1 ranked but not debited in the block at slot 77: {}",
                b58(&[2; 32])
            )),
            "{error}"
        );
        let twice = ranked(&[(1, 101, 201), (1, 102, 202)]);
        assert!(check_rank_map(&debits(&[1]), &twice, none)
            .unwrap_err()
            .contains("twice"));
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn base64_is_decoded() {
        for len in 0..10 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 200) as u8).collect();
            assert_eq!(unbase64(&base64(&bytes)), Some(bytes));
        }
        assert_eq!(unbase64("TWFu"), Some(b"Man".to_vec()));
        assert_eq!(unbase64("TWE="), Some(b"Ma".to_vec()));
        assert_eq!(unbase64("TQ=="), Some(b"M".to_vec()));
        assert_eq!(unbase64("T!=="), None);
    }

    fn vote_account(version: u32, owner: &str, key: Option<[u8; 48]>) -> Account {
        let mut data = vec![0u8; VOTE_STATE_PREFIX];
        data[..4].copy_from_slice(&version.to_le_bytes());
        data[4..36].copy_from_slice(&[7; 32]);
        if let Some(key) = key {
            data[144] = 1;
            data[145..].copy_from_slice(&key);
        }
        Account {
            data: (base64(&data), "base64".into()),
            owner: owner.into(),
        }
    }

    #[test]
    fn the_keys_are_read_from_a_vote_account_of_the_current_version() {
        let key = Some([5; 48]);
        assert_eq!(
            vote_keys(&vote_account(3, VOTE_PROGRAM, key)),
            Some(([7; 32], [5; 48]))
        );
        assert_eq!(vote_keys(&vote_account(3, VOTE_PROGRAM, None)), None);
        assert_eq!(vote_keys(&vote_account(2, VOTE_PROGRAM, key)), None);
        assert_eq!(
            vote_keys(&vote_account(3, "11111111111111111111111111111111", key)),
            None
        );
        let mut short = vote_account(3, VOTE_PROGRAM, key);
        short.data.0 = base64(&[3, 0, 0, 0]);
        assert_eq!(vote_keys(&short), None);
    }

    #[test]
    fn keys_are_asked_for_in_hundreds() {
        let accounts: Vec<Pubkey> = (0..150).map(|i| [i as u8; 32]).collect();
        let entry = |i: usize| {
            let account = vote_account(3, VOTE_PROGRAM, Some([i as u8; 48]));
            json!({"data": [account.data.0, "base64"], "owner": VOTE_PROGRAM,
                   "lamports": 1, "executable": false, "rentEpoch": 0})
        };
        let first: Vec<Value> = (0..100).map(entry).collect();
        let mut second: Vec<Value> = (100..150).map(entry).collect();
        second[0] = Value::Null;
        let bodies: Vec<String> = [first, second]
            .iter()
            .map(|value| {
                json!({"jsonrpc": "2.0", "id": 1,
                       "result": {"context": {"slot": 1}, "value": value}})
                .to_string()
            })
            .collect();
        let script: Vec<(u16, &str)> = bodies.iter().map(|b| (200, b.as_str())).collect();
        let transport = Scripted::new(&script);
        let keys = keys_now(&transport.rpc(), "http://node", &accounts).unwrap();
        assert_eq!(keys.len(), 150);
        assert_eq!(keys[99], Some(([7; 32], [99; 48])));
        assert_eq!(keys[100], None);
        let asked = transport.asked.borrow();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1].1["params"][0].as_array().unwrap().len(), 50);
        assert_eq!(asked[0].1["params"][1]["dataSlice"]["length"], 193);
    }
}
