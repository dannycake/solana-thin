//! Turning what a source said into a set file: a snapshot extract read
//! from disk, or a rank map asked of an RPC node.
//!
//! Either way the set is built by the verifier's own code, so a set file
//! made here holds bytes the verifier accepts.

use serde::Deserialize;
use serde_json::{json, Value};
use solana_thin::{Validator, ValidatorSet, VoteAccount};
use solana_thin_setlog::rpc::{host_label, Rpc};
use solana_thin_setlog::{SetFile, Source, KIND_RANK_MAP, KIND_SNAPSHOT, SET_FILE_FORMAT};
use std::collections::BTreeSet;

/// The `format` field of a snapshot extract: the epoch-stakes maps of one
/// bank snapshot, as `snapshot-stakes` in `tools/agave-fixtures` writes them.
pub const EXTRACT_FORMAT: &str = "solana-thin/snapshot-extract/v1";

/// A vote account's address.
pub type Pubkey = [u8; 32];

/// One input of `setlog agree`, and the vote accounts it says are members.
pub struct Input {
    pub file: SetFile,
    /// Every vote account in an extract's epoch-stakes map. `None` for a set
    /// file, which holds keys and stakes and names no account.
    pub members: Option<BTreeSet<Pubkey>>,
}

/// One rank in a rank map, with the accounts the node says it stands for.
pub struct Ranked {
    pub vote_pubkey: Pubkey,
    pub node_pubkey: Pubkey,
    pub bls_pubkey: [u8; 48],
}

/// A node's rank map as a set file, and the ranks it gave.
pub struct RankMapReading {
    pub file: SetFile,
    pub ranked: Vec<Ranked>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extract {
    format: String,
    cluster: String,
    shred_version: u16,
    /// What names the node the snapshot came from; the source's label.
    node: String,
    /// The slot of the snapshot.
    slot: u64,
    epochs: Vec<ExtractEpoch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractEpoch {
    epoch: u64,
    /// Every vote account in the bank's stakes map for the epoch.
    accounts: Vec<ExtractAccount>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractAccount {
    vote_pubkey: String,
    node_pubkey: String,
    bls_pubkey: Option<String>,
    stake: u64,
}

fn unhex<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).map_err(|_| format!("{what} is not {N} bytes of hex"))?;
    Ok(out)
}

/// Reads one input of `setlog agree`: a set file, or a snapshot extract
/// from which the set for `epoch` is built.
pub fn set_file_from_input(text: &str, epoch: u64) -> Result<Input, String> {
    let format = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|value| Some(value.get("format")?.as_str()?.to_string()))
        .ok_or("not a set file or a snapshot extract")?;
    match format.as_str() {
        SET_FILE_FORMAT => {
            let file = SetFile::from_json(text).map_err(|e| e.to_string())?;
            if file.epoch() != epoch {
                return Err(format!("is the set for epoch {}", file.epoch()));
            }
            Ok(Input {
                file,
                members: None,
            })
        }
        EXTRACT_FORMAT => set_file_from_extract(text, epoch),
        other => Err(format!("unknown format {other:?}")),
    }
}

fn set_file_from_extract(text: &str, epoch: u64) -> Result<Input, String> {
    let extract: Extract = serde_json::from_str(text).map_err(|e| e.to_string())?;
    if extract.format != EXTRACT_FORMAT {
        return Err(format!("unknown format {:?}", extract.format));
    }
    let mut matching = extract.epochs.iter().filter(|e| e.epoch == epoch);
    let (Some(stakes), None) = (matching.next(), matching.next()) else {
        let held: Vec<String> = extract.epochs.iter().map(|e| e.epoch.to_string()).collect();
        return Err(format!(
            "does not hold epoch {epoch} once (it holds {})",
            held.join(", ")
        ));
    };
    let accounts = stakes
        .accounts
        .iter()
        .map(|account| {
            Ok(VoteAccount {
                vote_pubkey: unhex(&account.vote_pubkey, "vote_pubkey")?,
                node_pubkey: unhex(&account.node_pubkey, "node_pubkey")?,
                bls_pubkey: account
                    .bls_pubkey
                    .as_deref()
                    .map(|key| unhex(key, "bls_pubkey"))
                    .transpose()?,
                stake: account.stake,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    // The cluster's own filter and ranking, as the verifier implements them.
    let set = ValidatorSet::from_vote_accounts(&accounts)
        .map_err(|e| format!("epoch {epoch} does not rank into a set: {e}"))?;
    let source =
        Source::new(KIND_SNAPSHOT, &extract.node, extract.slot).map_err(|e| e.to_string())?;
    let file = SetFile::new(
        &extract.cluster,
        extract.shred_version,
        epoch,
        set.to_bytes(),
        vec![source],
    )
    .map_err(|e| e.to_string())?;
    let members: BTreeSet<Pubkey> = accounts.iter().map(|a| a.vote_pubkey).collect();
    if members.len() != accounts.len() {
        return Err(format!("epoch {epoch} lists a vote account twice"));
    }
    Ok(Input {
        file,
        members: Some(members),
    })
}

/// How a cluster's slots fall into epochs.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochSchedule {
    slots_per_epoch: u64,
    first_normal_epoch: u64,
    first_normal_slot: u64,
}

impl EpochSchedule {
    /// The first slot of `epoch`. Only epochs after warm-up, where every
    /// epoch has the same length, are supported.
    pub fn first_slot(&self, epoch: u64) -> Result<u64, String> {
        epoch
            .checked_sub(self.first_normal_epoch)
            .and_then(|epochs| epochs.checked_mul(self.slots_per_epoch))
            .and_then(|slots| slots.checked_add(self.first_normal_slot))
            .ok_or_else(|| format!("epoch {epoch} is outside the cluster's epoch schedule"))
    }
}

/// Asks the node at `url` for the cluster's epoch schedule.
pub fn epoch_schedule(rpc: &Rpc, url: &str) -> Result<EpochSchedule, String> {
    read(
        "getEpochSchedule",
        rpc.call(url, "getEpochSchedule", json!([]))?,
    )
}

#[derive(Deserialize)]
struct RankMapAnswer {
    context: Context,
    value: Option<RankMap>,
}

#[derive(Deserialize)]
struct Context {
    slot: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RankMap {
    epoch: u64,
    total_stake: u64,
    validators: Vec<RankEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RankEntry {
    rank: u64,
    vote_pubkey: String,
    node_pubkey: String,
    bls_pubkey_compressed: String,
    stake: u64,
}

/// Decodes a base-58 string of exactly `N` bytes.
pub fn unbase58<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    (bs58::decode(text).onto(&mut out) == Ok(N)).then_some(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterNode {
    shred_version: Option<u16>,
}

/// Reads the `result` of a call to `method` as a `T`.
pub fn read<T: serde::de::DeserializeOwned>(method: &str, value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|e| format!("{method}: unexpected answer: {e}"))
}

/// Asks the node at `url` for the validator set of `epoch` and for the
/// cluster's shred version.
///
/// `getVatActiveSetRankMap` (Agave 4.5) takes a slot and returns the ranked
/// set of that slot's epoch. The answer is checked against the verifier's
/// rules for a ranked set, and its stated total against the sum.
pub fn set_file_from_rank_map(
    rpc: &Rpc,
    url: &str,
    cluster: &str,
    epoch: u64,
) -> Result<RankMapReading, String> {
    let label = host_label(url)?;
    let first_slot = epoch_schedule(rpc, url)?.first_slot(epoch)?;

    let method = "getVatActiveSetRankMap";
    let answer: RankMapAnswer = read(method, rpc.call(url, method, json!([first_slot]))?)?;
    let map = answer
        .value
        .ok_or_else(|| format!("{method}: the node has no rank map for epoch {epoch}"))?;
    if map.epoch != epoch {
        return Err(format!(
            "{method}: asked for epoch {epoch}, got epoch {}",
            map.epoch
        ));
    }
    let mut validators = Vec::with_capacity(map.validators.len());
    let mut ranked = Vec::with_capacity(map.validators.len());
    for (rank, entry) in map.validators.iter().enumerate() {
        if entry.rank != rank as u64 {
            return Err(format!("{method}: ranks are not 0, 1, 2, ... in order"));
        }
        let Some(bls_pubkey) = unbase58(&entry.bls_pubkey_compressed) else {
            return Err(format!(
                "{method}: rank {rank} has a key that is not 48 bytes"
            ));
        };
        let (Some(vote_pubkey), Some(node_pubkey)) =
            (unbase58(&entry.vote_pubkey), unbase58(&entry.node_pubkey))
        else {
            return Err(format!(
                "{method}: rank {rank} has an account address that is not 32 bytes"
            ));
        };
        validators.push(Validator {
            bls_pubkey,
            stake: entry.stake,
        });
        ranked.push(Ranked {
            vote_pubkey,
            node_pubkey,
            bls_pubkey,
        });
    }
    // Refuses a list that is not in the cluster's order, so a node cannot
    // hand over a set the verifier would rank differently.
    let set = ValidatorSet::from_ranked(validators).map_err(|e| format!("{method}: {e}"))?;
    if set.total_stake() != map.total_stake {
        return Err(format!("{method}: totalStake is not the sum of the stakes"));
    }

    let method = "getClusterNodes";
    let nodes: Vec<ClusterNode> = read(method, rpc.call(url, method, json!([]))?)?;
    let mut versions: Vec<u16> = nodes.iter().filter_map(|node| node.shred_version).collect();
    versions.sort_unstable();
    versions.dedup();
    let [shred_version] = versions[..] else {
        return Err(format!(
            "{method}: the nodes listed do not share one shred version"
        ));
    };

    let source =
        Source::new(KIND_RANK_MAP, &label, answer.context.slot).map_err(|e| e.to_string())?;
    let file = SetFile::new(cluster, shred_version, epoch, set.to_bytes(), vec![source])
        .map_err(|e| e.to_string())?;
    Ok(RankMapReading { file, ranked })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use solana_thin::testkit::TestValidators;
    use solana_thin_setlog::rpc::testing::Scripted;

    fn validators() -> ValidatorSet {
        TestValidators::new(4, |i| 500 + 10 * i as u64).set()
    }

    /// The answers a 4.5 node gives for `set`, in the order they are asked.
    pub fn answers(set: &ValidatorSet, epoch: u64, shred_version: u16) -> Vec<Value> {
        let ranked: Vec<Value> = set
            .validators()
            .iter()
            .enumerate()
            .map(|(rank, v)| {
                json!({
                    "rank": rank,
                    "votePubkey": bs58::encode([rank as u8; 32]).into_string(),
                    "nodePubkey": bs58::encode([rank as u8 + 100; 32]).into_string(),
                    "blsPubkeyCompressed": bs58::encode(v.bls_pubkey).into_string(),
                    "stake": v.stake,
                })
            })
            .collect();
        vec![
            json!({"firstNormalEpoch": 14, "firstNormalSlot": 524_256, "slotsPerEpoch": 432_000,
                   "leaderScheduleSlotOffset": 432_000, "warmup": true}),
            json!({"context": {"apiVersion": "4.5.0", "slot": 987_654},
                   "value": {"epoch": epoch, "totalStake": set.total_stake(), "validators": ranked}}),
            json!([{"pubkey": "a", "shredVersion": shred_version, "rpc": null},
                   {"pubkey": "b", "shredVersion": shred_version}]),
        ]
    }

    fn fetch(answers: &[Value]) -> (Result<RankMapReading, String>, Vec<(String, Value)>) {
        let bodies: Vec<String> = answers
            .iter()
            .map(|result| json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string())
            .collect();
        let script: Vec<(u16, &str)> = bodies.iter().map(|b| (200, b.as_str())).collect();
        let transport = Scripted::new(&script);
        let result = set_file_from_rank_map(
            &transport.rpc(),
            "https://rpc.example/key/SECRET",
            "testnet",
            20,
        );
        let asked = transport.asked.borrow().clone();
        (result, asked)
    }

    #[test]
    fn a_rank_map_becomes_the_set_the_verifier_builds() {
        let set = validators();
        let (reading, asked) = fetch(&answers(&set, 20, 9));
        let RankMapReading { file, ranked } = reading.unwrap();
        // The accounts behind each rank, kept for the admission check.
        for (rank, entry) in ranked.iter().enumerate() {
            assert_eq!(entry.vote_pubkey, [rank as u8; 32]);
            assert_eq!(entry.node_pubkey, [rank as u8 + 100; 32]);
            assert_eq!(entry.bls_pubkey, set.validators()[rank].bls_pubkey);
        }
        assert_eq!(ranked.len(), 4);
        assert_eq!(file.set_hash(), set.hash());
        assert_eq!(file.set_bytes(), set.to_bytes());
        assert_eq!(
            (file.cluster(), file.epoch(), file.shred_version()),
            ("testnet", 20, 9)
        );
        assert_eq!(
            file.sources(),
            [Source::new(KIND_RANK_MAP, "rpc.example", 987_654).unwrap()]
        );
        // The slot asked about is the first of the epoch, after warm-up.
        let methods: Vec<&str> = asked
            .iter()
            .map(|(_, b)| b["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            [
                "getEpochSchedule",
                "getVatActiveSetRankMap",
                "getClusterNodes"
            ]
        );
        assert_eq!(asked[1].1["params"], json!([524_256 + 6 * 432_000]));
    }

    #[test]
    fn an_answer_that_is_not_the_epochs_ranked_set_is_refused() {
        let set = validators();
        let good = answers(&set, 20, 9);
        let refused = |change: &dyn Fn(&mut Vec<Value>), why: &str| {
            let mut answers = good.clone();
            change(&mut answers);
            let Err(error) = fetch(&answers).0 else {
                panic!("not refused: {why}");
            };
            assert!(error.contains(why), "{error}");
        };
        refused(&|a| a[1]["value"] = Value::Null, "no rank map for epoch 20");
        refused(&|a| a[1]["value"]["epoch"] = json!(21), "got epoch 21");
        refused(
            &|a| a[1]["value"]["totalStake"] = json!(1),
            "totalStake is not the sum",
        );
        refused(
            &|a| a[1]["value"]["validators"][2]["rank"] = json!(3),
            "ranks are not",
        );
        refused(
            &|a| a[1]["value"]["validators"][0]["blsPubkeyCompressed"] = json!("abc"),
            "not 48 bytes",
        );
        refused(
            &|a| a[1]["value"]["validators"][1]["votePubkey"] = json!("abc"),
            "rank 1 has an account address that is not 32 bytes",
        );
        // Stake raised out of order: the verifier's own check of rank order.
        refused(
            &|a| {
                let stake = a[1]["value"]["validators"][0]["stake"].as_u64().unwrap();
                a[1]["value"]["validators"][3]["stake"] = json!(stake + 1);
                let total = a[1]["value"]["totalStake"].as_u64().unwrap();
                a[1]["value"]["totalStake"] = json!(total + 1);
            },
            "rank order",
        );
        refused(
            &|a| a[2][1]["shredVersion"] = json!(10),
            "do not share one shred version",
        );
        refused(&|a| a[2] = json!([]), "do not share one shred version");
        refused(
            &|a| a[0]["firstNormalEpoch"] = json!(21),
            "outside the cluster's epoch schedule",
        );
    }

    fn extract(set_accounts: Value) -> String {
        json!({
            "format": EXTRACT_FORMAT,
            "cluster": "mainnet-beta",
            "shred_version": 50093,
            "node": "node-a",
            "slot": 4242,
            "epochs": [{"epoch": 7, "accounts": []}, {"epoch": 8, "accounts": set_accounts}],
        })
        .to_string()
    }

    fn accounts(set: &ValidatorSet) -> Vec<Value> {
        set.validators()
            .iter()
            .enumerate()
            .map(|(i, v)| {
                json!({
                    "vote_pubkey": hex::encode([i as u8; 32]),
                    "node_pubkey": hex::encode([i as u8 + 100; 32]),
                    "bls_pubkey": hex::encode(v.bls_pubkey),
                    "stake": v.stake,
                })
            })
            .collect()
    }

    #[test]
    fn an_extract_is_ranked_by_the_verifier() {
        let set = validators();
        let mut listed = accounts(&set);
        // Out of rank order, with an account that has no key and one with
        // no stake: the map holds every vote account, the set does not.
        listed.reverse();
        listed.push(
            json!({"vote_pubkey": hex::encode([50; 32]), "node_pubkey": hex::encode([51; 32]),
                           "bls_pubkey": null, "stake": 900}),
        );
        listed.push(
            json!({"vote_pubkey": hex::encode([60; 32]), "node_pubkey": hex::encode([61; 32]),
                           "bls_pubkey": listed[0]["bls_pubkey"], "stake": 0}),
        );
        let Input { file, members } = set_file_from_input(&extract(json!(listed)), 8).unwrap();
        // The members are every account in the map, ranked or not: the
        // map is what the cluster admitted, and ranking comes after.
        let mut listed_members: Vec<Pubkey> = (0..4).map(|i| [i; 32]).collect();
        listed_members.extend([[50; 32], [60; 32]]);
        assert_eq!(members, Some(listed_members.into_iter().collect()));
        assert_eq!(file.set_hash(), set.hash());
        assert_eq!(
            (file.cluster(), file.epoch(), file.shred_version()),
            ("mainnet-beta", 8, 50093)
        );
        assert_eq!(
            file.sources(),
            [Source::new(KIND_SNAPSHOT, "node-a", 4242).unwrap()]
        );
    }

    #[test]
    fn an_input_without_the_epoch_is_refused() {
        let text = extract(json!(accounts(&validators())));
        let refusal = |text: &str, epoch| match set_file_from_input(text, epoch) {
            Ok(_) => panic!("not refused"),
            Err(why) => why,
        };
        let missing = refusal(&text, 9);
        assert!(
            missing.contains("does not hold epoch 9 once (it holds 7, 8)"),
            "{missing}"
        );
        let empty = refusal(&text, 7);
        assert!(empty.contains("does not rank into a set"), "{empty}");

        let set_file = set_file_from_input(&text, 8).unwrap().file.to_json();
        // A set file lists keys, not vote accounts.
        assert!(set_file_from_input(&set_file, 8).unwrap().members.is_none());
        assert_eq!(refusal(&set_file, 9), "is the set for epoch 8");

        let mut twice = accounts(&validators());
        twice.push(twice[0].clone());
        assert!(refusal(&extract(json!(twice)), 8).contains("lists a vote account twice"));
    }

    #[test]
    fn a_file_of_another_kind_is_refused() {
        let refusal = |text: &str| match set_file_from_input(text, 8) {
            Ok(_) => panic!("not refused"),
            Err(why) => why,
        };
        for text in ["", "[]", "{}", r#"{"format":7}"#] {
            assert_eq!(refusal(text), "not a set file or a snapshot extract");
        }
        assert_eq!(
            refusal(r#"{"format":"solana-thin/set/v9"}"#),
            r#"unknown format "solana-thin/set/v9""#
        );
        let unknown_field = extract(json!([])).replace(r#""slot":4242"#, r#""slot":4242,"x":1"#);
        assert!(refusal(&unknown_field).contains("unknown field"));
        let bad_key = extract(
            json!([{"vote_pubkey": "zz", "node_pubkey": "", "bls_pubkey": null, "stake": 1}]),
        );
        assert!(refusal(&bad_key).contains("vote_pubkey is not 32 bytes of hex"));
    }
}
