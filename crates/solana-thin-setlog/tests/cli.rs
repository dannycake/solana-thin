//! The `setlog` binary, run as an operator and a client would run it.

use serde_json::{json, Value};
use solana_thin::testkit::TestValidators;
use solana_thin::ValidatorSet;
use solana_thin_setlog::{parse, SetFile, SigningKey, Source, KIND_ADMISSION};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

/// A directory of its own for one test, empty at the start.
struct Dir(PathBuf);

impl Dir {
    fn new(test: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("setlog-cli")
            .join(test);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_string()
    }

    fn write(&self, name: &str, text: &str) -> String {
        let path = self.path(name);
        fs::write(&path, text).unwrap();
        path
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.path(name)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.0.join(name).exists()
    }
}

struct Ran {
    ok: bool,
    code: Option<i32>,
    out: String,
    err: String,
}

/// Runs `setlog`, with `key` as the signing key in its environment if given.
fn setlog(key: Option<&str>, args: &[&str]) -> Ran {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setlog"));
    command.args(args).env_remove("SETLOG_SIGNING_KEY");
    if let Some(key) = key {
        command.env("SETLOG_SIGNING_KEY", key);
    }
    let output = command.output().unwrap();
    Ran {
        ok: output.status.success(),
        code: output.status.code(),
        out: String::from_utf8(output.stdout).unwrap(),
        err: String::from_utf8(output.stderr).unwrap(),
    }
}

fn run(args: &[&str]) -> Ran {
    setlog(None, args)
}

/// The secret of a signer that exists only here: one byte, repeated.
fn secret(n: u8) -> String {
    hex::encode([n; 32])
}

fn public(n: u8) -> String {
    hex::encode(SigningKey::from_seed([n; 32]).unwrap().public_key())
}

fn validators(seed: u64) -> ValidatorSet {
    TestValidators::with_seed(seed, 6, |i| 1_000_000 + 37 * i as u64).set()
}

/// A snapshot extract from `node` holding `sets` by epoch.
fn extract(node: &str, slot: u64, sets: &[(u64, &ValidatorSet)]) -> String {
    let epochs: Vec<Value> = sets
        .iter()
        .map(|(epoch, set)| {
            let accounts: Vec<Value> = set
                .validators()
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
                .collect();
            json!({"epoch": epoch, "accounts": accounts})
        })
        .collect();
    json!({
        "format": "solana-thin/snapshot-extract/v1",
        "cluster": "testnet",
        "shred_version": 9,
        "node": node,
        "slot": slot,
        "epochs": epochs,
    })
    .to_string()
}

/// Three extracts that agree on the sets of epochs 20 and 21.
fn three_extracts(dir: &Dir) -> [String; 3] {
    let (a, b) = (validators(1), validators(2));
    [("node-a", 501), ("node-b", 502), ("node-c", 503)].map(|(node, slot)| {
        dir.write(
            &format!("{node}.json"),
            &extract(node, slot, &[(20, &a), (21, &b)]),
        )
    })
}

/// The flags that check membership against the debits a node serves, or
/// skip the check when there is no node.
fn admission_flags(node: Option<&str>) -> Vec<&str> {
    match node {
        Some(url) => vec!["--admission-url", url],
        None => vec!["--no-admission-check"],
    }
}

fn agree(
    dir: &Dir,
    epoch: &str,
    quorum: &str,
    inputs: &[String],
    log: Option<&str>,
    admission: Option<&str>,
) -> Ran {
    let (set, record) = (
        dir.path(&format!("set-{epoch}.json")),
        dir.path(&format!("record-{epoch}.json")),
    );
    let mut args = vec![
        "agree", "--epoch", epoch, "--quorum", quorum, "--set", &set, "--record", &record,
    ];
    if let Some(log) = log {
        args.extend(["--log", log]);
    }
    args.extend(admission_flags(admission));
    args.extend(inputs.iter().map(String::as_str));
    run(&args)
}

/// Epochs 20 and 21 agreed, signed by signers 1 and 2, and appended.
fn published_log(dir: &Dir) -> String {
    let inputs = three_extracts(dir);
    let log = dir.path("log.jsonl");
    for epoch in ["20", "21"] {
        let ran = agree(dir, epoch, "3", &inputs, Some(&log), None);
        assert!(ran.ok, "{}", ran.err);
        let (set, record) = (
            dir.path(&format!("set-{epoch}.json")),
            dir.path(&format!("record-{epoch}.json")),
        );
        for signer in [1, 2] {
            let ran = setlog(
                Some(&secret(signer)),
                &["sign", "--record", &record, "--set", &set],
            );
            assert!(ran.ok, "{}", ran.err);
        }
        let ran = run(&["append", "--log", &log, "--record", &record]);
        assert!(ran.ok, "{}", ran.err);
    }
    log
}

fn verify(log: &str, signers: &[u8], threshold: &str) -> Ran {
    let keys: Vec<String> = signers.iter().map(|n| public(*n)).collect();
    let mut args = vec!["verify", "--log", log, "--threshold", threshold];
    for key in &keys {
        args.extend(["--signer", key]);
    }
    run(&args)
}

#[test]
fn from_sources_to_a_log_a_client_verifies() {
    let dir = Dir::new("procedure");
    let inputs = three_extracts(&dir);
    let log = dir.path("log.jsonl");
    // The first blocks of epochs 19 and 20 admitted the extracts' accounts.
    let node = serve(Node::debiting(&[(19, accounts(6)), (20, accounts(6))]));

    let ran = agree(&dir, "20", "3", &inputs, Some(&log), Some(&node));
    assert!(ran.ok, "{}", ran.err);
    let hash = hex::encode(validators(1).hash());
    for node in ["node-a", "node-b", "node-c"] {
        assert!(
            ran.out.contains(&format!("snapshot {node} at slot 50")) && ran.out.contains(&hash),
            "{}",
            ran.out
        );
    }
    assert!(ran
        .out
        .contains("agreed: 3 sources give epoch 20 of testnet (shred version 9)"));

    // The set file is the verifier's bytes; the candidate is unsigned and
    // starts the log.
    let set = SetFile::from_json(&dir.read("set-20.json")).unwrap();
    assert_eq!(set.set_bytes(), validators(1).to_bytes());
    // Three readings, and the check, which names the block and not the node.
    let checked = Source::new(KIND_ADMISSION, "vat-debits", first_block(19)).unwrap();
    assert_eq!(set.sources().len(), 4);
    assert_eq!(set.sources()[0], checked);
    let candidate = parse(&dir.read("record-20.json")).unwrap().pop().unwrap();
    assert!(candidate.signatures().is_empty());
    assert_eq!(candidate.record().prev(), &[0; 32]);
    assert!(set.supports(candidate.record()));
    assert_eq!(candidate.record().sources(), set.sources());
    assert!(ran.out.contains(&format!(
        "admission: the block at slot {} debited 6 vote accounts",
        first_block(19)
    )));
    assert!(!ran.out.contains("SECRET-KEY") && !dir.read("set-20.json").contains("127.0.0.1"));

    let (set_path, record_path) = (dir.path("set-20.json"), dir.path("record-20.json"));
    let ran = setlog(
        Some(&secret(1)),
        &["sign", "--record", &record_path, "--set", &set_path],
    );
    assert!(ran.ok, "{}", ran.err);
    assert!(ran.out.contains(&public(1)) && ran.out.contains("1 signature(s)"));
    assert!(!ran.out.contains(&secret(1)) && !ran.err.contains(&secret(1)));
    let ran = setlog(
        Some(&secret(2)),
        &["sign", "--record", &record_path, "--set", &set_path],
    );
    assert!(ran.out.contains("2 signature(s)"), "{}", ran.err);

    let ran = run(&["append", "--log", &log, "--record", &record_path]);
    assert!(ran.ok, "{}", ran.err);
    assert!(ran.out.contains("1 record(s)"));

    // The next epoch links to the first record.
    let ran = agree(&dir, "21", "3", &inputs, Some(&log), Some(&node));
    assert!(ran.ok, "{}", ran.err);
    let first = parse(&dir.read("log.jsonl")).unwrap()[0].record().hash();
    let second = parse(&dir.read("record-21.json")).unwrap().pop().unwrap();
    assert_eq!(second.record().prev(), &first);
    let (set_path, record_path) = (dir.path("set-21.json"), dir.path("record-21.json"));
    for signer in [2, 3] {
        let ran = setlog(
            Some(&secret(signer)),
            &["sign", "--record", &record_path, "--set", &set_path],
        );
        assert!(ran.ok, "{}", ran.err);
    }
    assert!(run(&["append", "--log", &log, "--record", &record_path]).ok);

    let ran = verify(&log, &[1, 2, 3], "2");
    assert!(ran.ok, "{}", ran.err);
    assert!(ran.out.contains("verified: 2 record(s) for testnet"));
    assert!(ran.out.contains(&format!(
        "epoch 20: pin {hash} (6 validators, shred version 9)"
    )));
    assert!(ran.out.contains(&format!(
        "epoch 21: pin {}",
        hex::encode(validators(2).hash())
    )));
    assert!(
        ran.out.contains(&format!(
            "members checked against the admission debits in the block at slot {}",
            first_block(20)
        )),
        "{}",
        ran.out
    );

    // Signer 1 did not sign epoch 21, so a client that wants signers 1 and
    // 3 both is not served by this log.
    let ran = verify(&log, &[1, 3], "2");
    assert!(!ran.ok);
    assert!(
        ran.err.contains("line 1") && ran.err.contains("1 valid signatures"),
        "{}",
        ran.err
    );

    let ran = run(&["show", &log]);
    assert!(ran.ok, "{}", ran.err);
    assert!(ran.out.contains("record 2: epoch 21 of testnet"));
    assert!(ran.out.contains("(starts a log)") && ran.out.contains("(links to the record before)"));
    let ran = run(&["show", &record_path]);
    assert!(ran.out.contains("record 1: epoch 21") && ran.out.contains("(continues a log)"));
    assert!(ran
        .out
        .contains(&format!("signed by {} (valid)", public(3))));
    let ran = run(&["show", &dir.path("set-20.json")]);
    assert!(
        ran.out.contains("a valid ranked set, total stake 6000555"),
        "{}",
        ran.out
    );
    assert!(ran.out.contains(&format!(
        "members checked against the admission debits in the block at slot {}",
        first_block(19)
    )));
}

#[test]
fn a_set_file_and_extracts_count_together() {
    let dir = Dir::new("mixed");
    let inputs = three_extracts(&dir);
    let node = serve(Node::debiting(&[(19, accounts(6))]));
    assert!(agree(&dir, "20", "2", &inputs[..2], None, Some(&node)).ok);
    // The merged set file stands for the two sources that made it, and
    // carries the check they passed.
    let merged = [dir.path("set-20.json"), inputs[2].clone()];
    let (set, record) = (dir.path("all.json"), dir.path("all-record.json"));
    let ran = run(&[
        "agree",
        "--epoch",
        "20",
        "--quorum",
        "3",
        "--set",
        &set,
        "--record",
        &record,
        "--admission-url",
        &node,
        &merged[0],
        &merged[1],
    ]);
    assert!(ran.ok, "{}", ran.err);
    let all = SetFile::from_json(&dir.read("all.json")).unwrap();
    assert_eq!(all.sources().len(), 4);
    assert_eq!(
        all.sources()
            .iter()
            .filter(|s| s.kind() == KIND_ADMISSION)
            .count(),
        1
    );
    // Listing one node's extract twice does not make it two sources.
    let twice = [inputs[0].clone(), inputs[0].clone()];
    let ran = agree(&dir, "21", "2", &twice, None, None);
    assert!(!ran.ok);
    assert!(
        ran.err.contains("1 distinct sources agree, 2 needed"),
        "{}",
        ran.err
    );
}

#[test]
fn sources_that_disagree_write_nothing() {
    let dir = Dir::new("disagree");
    let mut inputs = three_extracts(&dir).to_vec();
    // A fourth node reports one validator a lamport richer.
    let mut other = validators(1).validators().to_vec();
    other[3].stake += 1;
    let other = ValidatorSet::from_unordered(other).unwrap();
    inputs.push(dir.write("node-d.json", &extract("node-d", 504, &[(20, &other)])));

    let ran = agree(&dir, "20", "3", &inputs, None, None);
    assert!(!ran.ok);
    assert_eq!(ran.code, Some(1));
    assert!(
        ran.err
            .contains("nothing written: the sources do not agree"),
        "{}",
        ran.err
    );
    // Every source's hash was printed, so the odd one can be seen.
    assert!(ran.out.contains(&format!(
        "snapshot node-d at slot 504: {}",
        hex::encode(other.hash())
    )));
    assert!(ran.out.contains(&hex::encode(validators(1).hash())));
    assert!(!dir.exists("set-20.json") && !dir.exists("record-20.json"));
}

#[test]
fn too_few_sources_write_nothing() {
    let dir = Dir::new("quorum");
    let inputs = three_extracts(&dir);
    let ran = agree(&dir, "20", "4", &inputs, None, None);
    assert!(!ran.ok);
    assert!(
        ran.err.contains("3 distinct sources agree, 4 needed"),
        "{}",
        ran.err
    );
    assert!(!dir.exists("set-20.json") && !dir.exists("record-20.json"));

    let ran = agree(&dir, "22", "3", &inputs, None, None);
    assert!(
        ran.err
            .contains("does not hold epoch 22 once (it holds 20, 21)"),
        "{}",
        ran.err
    );
    let ran = agree(&dir, "20", "3", &[], None, None);
    assert!(ran.err.contains("nothing to compare"), "{}", ran.err);
}

#[test]
fn a_candidate_is_never_written_over_a_file() {
    let dir = Dir::new("overwrite");
    let inputs = three_extracts(&dir);
    dir.write("record-20.json", "a record someone signed\n");
    let ran = agree(&dir, "20", "3", &inputs, None, None);
    assert!(!ran.ok);
    assert!(
        ran.err.contains("record-20.json already exists"),
        "{}",
        ran.err
    );
    assert_eq!(dir.read("record-20.json"), "a record someone signed\n");
    // Neither file, not one of the two.
    assert!(!dir.exists("set-20.json"));
}

#[test]
fn a_candidate_that_the_log_cannot_take_is_not_written() {
    let dir = Dir::new("stale");
    let log = published_log(&dir);
    let inputs = three_extracts(&dir);
    fs::remove_file(dir.path("set-20.json")).unwrap();
    fs::remove_file(dir.path("record-20.json")).unwrap();
    // The log is at epoch 21.
    let ran = agree(&dir, "20", "3", &inputs, Some(&log), None);
    assert!(!ran.ok);
    assert!(
        ran.err
            .contains("its epoch is before the previous record's"),
        "{}",
        ran.err
    );
    assert!(!dir.exists("record-20.json"));
}

#[test]
fn signing_takes_the_key_from_the_environment_and_the_signers_own_set() {
    let dir = Dir::new("sign");
    let inputs = three_extracts(&dir);
    assert!(agree(&dir, "20", "3", &inputs, None, None).ok);
    assert!(agree(&dir, "21", "3", &inputs, None, None).ok);
    let (set, record) = (dir.path("set-20.json"), dir.path("record-20.json"));
    let unsigned = dir.read("record-20.json");

    let ran = run(&["sign", "--record", &record, "--set", &set]);
    assert!(!ran.ok);
    assert!(
        ran.err.contains("SETLOG_SIGNING_KEY is not set"),
        "{}",
        ran.err
    );
    for bad in ["", "abc", &"00".repeat(32), &"zz".repeat(32)] {
        let ran = setlog(Some(bad), &["sign", "--record", &record, "--set", &set]);
        assert!(!ran.ok);
        assert!(ran.err.contains("is not a signing key"), "{}", ran.err);
        assert!(bad.len() < 8 || !ran.err.contains(bad));
    }
    // A signer whose own reading gave another set does not sign.
    let ran = setlog(
        Some(&secret(1)),
        &[
            "sign",
            "--record",
            &record,
            "--set",
            &dir.path("set-21.json"),
        ],
    );
    assert!(!ran.ok);
    assert!(
        ran.err.contains("not signed: the set file is for epoch 21"),
        "{}",
        ran.err
    );
    assert_eq!(dir.read("record-20.json"), unsigned);

    // Signing twice with one key is one signature.
    for _ in 0..2 {
        let ran = setlog(
            Some(&secret(1)),
            &["sign", "--record", &record, "--set", &set],
        );
        assert!(ran.ok && ran.out.contains("1 signature(s)"), "{}", ran.err);
    }
    let ran = setlog(Some(&secret(1)), &["pubkey"]);
    assert_eq!(ran.out.trim(), public(1));
}

#[test]
fn append_refuses_what_does_not_extend_the_log() {
    let dir = Dir::new("append");
    let log = published_log(&dir);
    let before = dir.read("log.jsonl");
    let refused = |record: &str, why: &str| {
        let ran = run(&["append", "--log", &log, "--record", record]);
        assert!(!ran.ok);
        assert!(ran.err.contains(why), "{}", ran.err);
        assert_eq!(dir.read("log.jsonl"), before);
    };
    // Already in the log: it links to the first record, not the last.
    refused(
        &dir.path("record-21.json"),
        "does not link to the end of the log",
    );
    refused(
        &dir.path("record-20.json"),
        "does not link to the end of the log",
    );

    // Linked, but not signed.
    let inputs = [dir.write(
        "later.json",
        &extract("node-a", 600, &[(22, &validators(3))]),
    )];
    assert!(agree(&dir, "22", "1", &inputs, Some(&log), None).ok);
    refused(&dir.path("record-22.json"), "the record is not signed");

    // Two records in one file are not a record.
    let both = dir.write("both.jsonl", &before);
    refused(&both, "expected one record");
}

/// What a client is protected from: a hash swapped in a published log, a
/// record taken out of it, and a record its signers did not all sign.
#[test]
fn verify_refuses_a_forged_hash_a_broken_link_and_a_missing_signature() {
    let dir = Dir::new("verify");
    let log = published_log(&dir);
    let text = dir.read("log.jsonl");
    assert!(verify(&log, &[1, 2], "2").ok);
    let lines: Vec<&str> = text.lines().collect();

    let honest = hex::encode(validators(2).hash());
    let forged = dir.write(
        "forged.jsonl",
        &text.replace(&honest, &hex::encode(validators(9).hash())),
    );
    let ran = verify(&forged, &[1, 2], "2");
    assert_eq!(ran.code, Some(1));
    assert!(
        ran.err
            .contains("forged.jsonl, line 2: a signature does not verify"),
        "{}",
        ran.err
    );
    assert!(!ran.out.contains("pin"));

    let broken = dir.write("broken.jsonl", &format!("{}\n", lines[1]));
    let ran = verify(&broken, &[1, 2], "2");
    assert!(!ran.ok);
    assert!(
        ran.err
            .contains("broken.jsonl, line 1: does not link to the record before it"),
        "{}",
        ran.err
    );

    // The second signature of the second record, cut out cleanly.
    let cut = lines[1].rfind(r#",{"signer""#).unwrap();
    let fewer = format!("{}\n{}]}}\n", lines[0], &lines[1][..cut]);
    let missing = dir.write("missing.jsonl", &fewer);
    let ran = verify(&missing, &[1, 2], "2");
    assert!(!ran.ok);
    assert!(
        ran.err
            .contains("missing.jsonl, line 2: 1 valid signatures from the listed keys, 2 needed"),
        "{}",
        ran.err
    );
    // The same file is still good for a client that asks for one signer.
    assert!(verify(&missing, &[1, 2], "1").ok);

    // And the plain mistakes.
    assert!(verify(&log, &[1, 2], "3").err.contains("threshold must be"));
    assert!(verify(&log, &[], "1").err.contains("--signer is required"));
    assert!(verify(&log, &[7, 8], "1")
        .err
        .contains("0 valid signatures"));
    let ran = run(&[
        "verify",
        "--log",
        &log,
        "--threshold",
        "1",
        "--signer",
        "not-a-key",
    ]);
    assert!(ran.err.contains("not 64 hex digits"), "{}", ran.err);
}

#[test]
fn keygen_gives_a_key_that_signs() {
    let ran = run(&["keygen"]);
    assert!(ran.ok, "{}", ran.err);
    let secret = ran.out.trim();
    assert_eq!(secret.len(), 64);
    let key = SigningKey::from_hex(secret).unwrap();
    assert!(ran
        .err
        .contains(&format!("public key: {}", hex::encode(key.public_key()))));
    assert!(!ran.err.contains(secret));
    assert_ne!(run(&["keygen"]).out, ran.out);
    assert_eq!(
        setlog(Some(secret), &["pubkey"]).out.trim(),
        hex::encode(key.public_key())
    );
}

#[test]
fn mistakes_on_the_command_line_are_reported() {
    let ran = run(&["frobnicate"]);
    assert_eq!(ran.code, Some(2));
    assert!(ran.err.contains("setlog from-rank-map"));
    assert!(run(&["help"]).out.contains("setlog verify"));
    let ran = run(&[
        "agree", "--quorum", "2", "--epoch", "x", "--set", "a", "--record", "b",
    ]);
    assert!(ran.err.contains("--epoch x: not a number"), "{}", ran.err);
    let ran = run(&["agree", "--epoch", "1", "--quorm", "2"]);
    assert!(ran.err.contains("unknown option --quorm"), "{}", ran.err);
    let ran = run(&["show", "/nonexistent/file"]);
    assert_eq!(ran.code, Some(1));
}

const SLOTS_PER_EPOCH: u64 = 432_000;

/// The vote accounts the extracts and rank maps here list: `[i; 32]` at
/// rank `i`, run by node `[i + 100; 32]`.
fn accounts(count: u8) -> Vec<[u8; 32]> {
    (0..count).map(|i| [i; 32]).collect()
}

fn b58(key: &[u8]) -> String {
    bs58::encode(key).into_string()
}

/// The slot of the first block of `epoch` on a stand-in node: two slots
/// into it, the first two having been skipped.
fn first_block(epoch: u64) -> u64 {
    epoch * SLOTS_PER_EPOCH + 2
}

/// What a stand-in RPC node knows. Its epochs are 432,000 slots from slot
/// zero.
#[derive(Clone, Default)]
struct Node {
    /// The epoch and set `getVatActiveSetRankMap` answers with, if the node
    /// has the method.
    rank_map: Option<(u64, ValidatorSet)>,
    /// By epoch, the accounts debited in its first block. An epoch not
    /// listed is one whose block the node does not have.
    debits: BTreeMap<u64, Vec<[u8; 32]>>,
    /// Vote accounts as they are now: address, node identity, BLS key.
    vote_accounts: Vec<([u8; 32], [u8; 32], [u8; 48])>,
}

impl Node {
    fn ranking(epoch: u64, set: &ValidatorSet) -> Self {
        Self {
            rank_map: Some((epoch, set.clone())),
            ..Self::default()
        }
    }

    fn debiting(epochs: &[(u64, Vec<[u8; 32]>)]) -> Self {
        Self::default().and_debiting(epochs)
    }

    fn and_debiting(mut self, epochs: &[(u64, Vec<[u8; 32]>)]) -> Self {
        self.debits.extend(epochs.iter().cloned());
        self
    }

    fn answer(&self, request: &Value) -> Value {
        let params = &request["params"];
        match request["method"].as_str().unwrap() {
            "getEpochSchedule" => json!({"result": {"firstNormalEpoch": 0, "firstNormalSlot": 0,
                                                    "slotsPerEpoch": SLOTS_PER_EPOCH}}),
            "getVatActiveSetRankMap" if self.rank_map.is_some() => {
                let (epoch, set) = self.rank_map.as_ref().unwrap();
                assert_eq!(params, &json!([epoch * SLOTS_PER_EPOCH]));
                let ranked: Vec<Value> = set
                    .validators()
                    .iter()
                    .enumerate()
                    .map(|(rank, v)| {
                        json!({"rank": rank, "votePubkey": b58(&[rank as u8; 32]),
                               "nodePubkey": b58(&[rank as u8 + 100; 32]),
                               "blsPubkeyCompressed": b58(&v.bls_pubkey), "stake": v.stake})
                    })
                    .collect();
                json!({"result": {"context": {"slot": epoch * SLOTS_PER_EPOCH + 77},
                                  "value": {"epoch": epoch, "totalStake": set.total_stake(),
                                            "validators": ranked}}})
            }
            "getClusterNodes" => json!({"result": [{"shredVersion": 9}, {"shredVersion": 9}]}),
            "getBlocksWithLimit" => {
                let start = params[0].as_u64().unwrap();
                assert_eq!(start % SLOTS_PER_EPOCH, 0, "{params}");
                assert_eq!(params[1], json!(1));
                json!({"result": [start + 2]})
            }
            "getBlock" => {
                let slot = params[0].as_u64().unwrap();
                assert_eq!(params[1]["rewards"], json!(true));
                assert_eq!(params[1]["transactionDetails"], json!("none"));
                let debited = (slot == first_block(slot / SLOTS_PER_EPOCH))
                    .then(|| self.debits.get(&(slot / SLOTS_PER_EPOCH)))
                    .flatten();
                let Some(debited) = debited else {
                    return json!({"error": {"code": -32009, "message":
                        format!("Slot {slot} was skipped, or missing in long-term storage")}});
                };
                let mut rewards: Vec<Value> = debited
                    .iter()
                    .map(|vote| {
                        json!({"pubkey": b58(vote), "lamports": -800_000_000i64,
                               "postBalance": 1_000_000_000u64, "rewardType": "VATDebit",
                               "commission": null})
                    })
                    .collect();
                // The leader's fee, which is no debit.
                rewards.push(json!({"pubkey": b58(&[200; 32]), "lamports": 5000,
                                    "postBalance": 9, "rewardType": "Fee", "commission": null}));
                json!({"result": {"blockHeight": slot - 9, "blockTime": null,
                                  "blockhash": b58(&[1; 32]), "previousBlockhash": b58(&[2; 32]),
                                  "parentSlot": slot - 3, "rewards": rewards}})
            }
            "getMultipleAccounts" => {
                let value: Vec<Value> = params[0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|address| {
                        let found = self
                            .vote_accounts
                            .iter()
                            .find(|(vote, _, _)| &b58(vote) == address);
                        let Some((_, node, bls)) = found else {
                            return Value::Null;
                        };
                        // A VoteStateV4 up to its BLS key, as `dataSlice` asks.
                        let mut data = vec![0u8; 193];
                        data[..4].copy_from_slice(&3u32.to_le_bytes());
                        data[4..36].copy_from_slice(node);
                        data[144] = 1;
                        data[145..].copy_from_slice(bls);
                        json!({"data": [base64(&data), "base64"], "executable": false,
                               "lamports": 1_000_000_000u64,
                               "owner": "Vote111111111111111111111111111111111111111",
                               "rentEpoch": 0, "space": 3762})
                    })
                    .collect();
                json!({"result": {"context": {"slot": 1}, "value": value}})
            }
            _ => json!({"error": {"code": -32601, "message": "Method not found"}}),
        }
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
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

/// An RPC node, as far as `setlog` can tell: it answers what `node` knows
/// and refuses anything else.
fn serve(node: Node) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim().to_ascii_lowercase();
                if let Some(value) = line.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                if line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let answer = node.answer(&request).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            )
            .unwrap();
        }
    });
    // A path that looks like a key, to see that it is never printed.
    format!("http://{address}/v1/SECRET-KEY")
}

/// A URL nothing answers at.
fn nobody() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}/")
}

/// `from-rank-map` for epoch 30. `admission` is passed as given, so that
/// leaving it empty takes the debits from the first `--url`.
fn from_rank_map(dir: &Dir, quorum: &str, urls: &[&str], admission: &[&str]) -> Ran {
    let (set, record) = (dir.path("set.json"), dir.path("record.json"));
    let mut args = vec![
        "from-rank-map",
        "--cluster",
        "testnet",
        "--epoch",
        "30",
        "--quorum",
        quorum,
        "--set",
        &set,
        "--record",
        &record,
    ];
    for url in urls {
        args.extend(["--url", url]);
    }
    args.extend(admission);
    run(&args)
}

#[test]
fn rank_maps_from_two_nodes_that_agree_make_a_candidate() {
    let dir = Dir::new("rank-map");
    let set = validators(1);
    let a = serve(Node::ranking(30, &set).and_debiting(&[(29, accounts(6))]));
    let b = serve(Node::ranking(30, &set));
    let ran = from_rank_map(&dir, "2", &[&a, &b], &[]);
    assert!(ran.ok, "{}", ran.err);
    assert!(!ran.out.contains("SECRET-KEY") && !ran.err.contains("SECRET-KEY"));
    assert_eq!(
        ran.out.matches(&hex::encode(set.hash())).count(),
        3,
        "{}",
        ran.out
    );
    // The debits came from the first node.
    let host = a.trim_start_matches("http://").split('/').next().unwrap();
    assert!(
        ran.out.contains(&format!(
            "admission: the block at slot {} debited 6 vote accounts, from {host}",
            first_block(29)
        )),
        "{}",
        ran.out
    );

    let file = SetFile::from_json(&dir.read("set.json")).unwrap();
    assert_eq!(file.set_bytes(), set.to_bytes());
    assert_eq!(
        (file.cluster(), file.epoch(), file.shred_version()),
        ("testnet", 30, 9)
    );
    let (checked, read) = file.sources().split_first().unwrap();
    assert_eq!(
        checked,
        &Source::new(KIND_ADMISSION, "vat-debits", first_block(29)).unwrap()
    );
    let labels: Vec<&str> = read.iter().map(|s| s.label()).collect();
    assert!(
        labels.len() == 2 && labels.iter().all(|label| label.starts_with("127.0.0.1:")),
        "{labels:?}"
    );
    assert_eq!(read[0].slot(), 30 * SLOTS_PER_EPOCH + 77);
    assert!(!dir.read("set.json").contains("SECRET-KEY"));
    assert!(file.supports(parse(&dir.read("record.json")).unwrap()[0].record()));
}

#[test]
fn a_node_that_differs_or_does_not_answer_stops_a_candidate() {
    let dir = Dir::new("rank-map-refused");
    let set = validators(1);
    let good = serve(Node::ranking(30, &set).and_debiting(&[(29, accounts(6))]));

    let differs = serve(Node::ranking(30, &validators(2)));
    let ran = from_rank_map(&dir, "2", &[&good, &differs], &[]);
    assert!(!ran.ok);
    assert!(ran.err.contains("the sources do not agree"), "{}", ran.err);
    assert!(ran.out.contains(&hex::encode(set.hash())));
    assert!(ran.out.contains(&hex::encode(validators(2).hash())));

    // A node on a release without the method is no source at all.
    let silent = serve(Node::debiting(&[(29, accounts(6))]));
    let ran = from_rank_map(&dir, "2", &[&good, &silent], &[]);
    assert!(!ran.ok);
    assert!(
        ran.out.contains("no answer: getVatActiveSetRankMap"),
        "{}",
        ran.out
    );
    assert!(
        ran.err.contains("1 distinct sources agree, 2 needed"),
        "{}",
        ran.err
    );
    assert!(from_rank_map(&dir, "1", &[], &[])
        .err
        .contains("--url is required"));
    assert!(!dir.exists("set.json") && !dir.exists("record.json"));
}

/// Agave drops every account that shares a BLS key or a node identity with
/// another after it has debited them all, so a rank map lacks exactly those.
#[test]
fn a_rank_map_lacks_the_debited_accounts_that_share_a_key() {
    let dir = Dir::new("rank-map-duplicates");
    let set = validators(1);
    let shared = validators(7).validators()[0].bls_pubkey;
    let other = validators(7).validators()[1].bls_pubkey;
    let mut debited = accounts(6);
    debited.extend([[7; 32], [8; 32]]);
    let node = |vote_accounts: Vec<([u8; 32], [u8; 32], [u8; 48])>| {
        serve(Node {
            vote_accounts,
            ..Node::ranking(30, &set).and_debiting(&[(29, debited.clone())])
        })
    };

    // Accounts 7 and 8 share a key: both were debited, neither is ranked.
    let url = node(vec![
        ([7; 32], [107; 32], shared),
        ([8; 32], [108; 32], shared),
    ]);
    let ran = from_rank_map(&dir, "1", &[&url], &[]);
    assert!(ran.ok, "{}", ran.err);
    assert!(
        ran.out
            .contains("the 2 debited accounts it does not rank share a BLS key or node identity"),
        "{}",
        ran.out
    );
    assert!(SetFile::from_json(&dir.read("set.json"))
        .unwrap()
        .sources()
        .iter()
        .any(|s| s.kind() == KIND_ADMISSION));
    fs::remove_file(dir.path("set.json")).unwrap();
    fs::remove_file(dir.path("record.json")).unwrap();

    // Sharing a node identity is the same.
    let url = node(vec![
        ([7; 32], [107; 32], shared),
        ([8; 32], [107; 32], other),
    ]);
    assert!(from_rank_map(&dir, "1", &[&url], &[]).ok);
    fs::remove_file(dir.path("set.json")).unwrap();
    fs::remove_file(dir.path("record.json")).unwrap();

    let refused = |vote_accounts, why: &[String]| {
        let ran = from_rank_map(&dir, "1", &[&node(vote_accounts)], &[]);
        assert!(!ran.ok);
        for why in why {
            assert!(ran.err.contains(why.as_str()), "{why}: {}", ran.err);
        }
        assert!(!dir.exists("set.json") && !dir.exists("record.json"));
    };
    // Account 7's key is its own: nothing explains its absence.
    refused(
        vec![([7; 32], [107; 32], other), ([8; 32], [108; 32], shared)],
        &[
            "debited but not ranked, and sharing no BLS key or node identity".into(),
            b58(&[7; 32]),
            b58(&[8; 32]),
        ],
    );
    // Account 7 shares ranked account 0's node identity, so the cluster
    // would have dropped account 0 as well.
    refused(
        vec![([7; 32], [100; 32], shared), ([8; 32], [108; 32], shared)],
        &[
            "ranked, though sharing a BLS key or node identity".into(),
            b58(&[0; 32]),
        ],
    );
    // Account 8 is not a vote account the node knows.
    refused(
        vec![([7; 32], [107; 32], shared)],
        &["no vote account with a BLS key now".into(), b58(&[8; 32])],
    );

    // A ranked account that paid nothing.
    let url = serve(Node::ranking(30, &set).and_debiting(&[(29, accounts(5))]));
    let ran = from_rank_map(&dir, "1", &[&url], &[]);
    assert!(!ran.ok);
    assert!(
        ran.err.contains("ranked but not debited") && ran.err.contains(&b58(&[5; 32])),
        "{}",
        ran.err
    );
}

#[test]
fn the_debits_can_come_from_another_node_or_not_be_asked_for() {
    let dir = Dir::new("rank-map-admission-url");
    let set = validators(1);
    let ranks = serve(Node::ranking(30, &set));
    let debits = serve(Node::debiting(&[(29, accounts(6))]));
    // The node that ranks has no block: asked by default, it cannot answer.
    let ran = from_rank_map(&dir, "1", &[&ranks], &[]);
    assert!(!ran.ok);
    assert!(ran.err.contains("getBlock"), "{}", ran.err);
    let ran = from_rank_map(&dir, "1", &[&ranks], &["--admission-url", &debits]);
    assert!(ran.ok, "{}", ran.err);
    fs::remove_file(dir.path("set.json")).unwrap();
    fs::remove_file(dir.path("record.json")).unwrap();

    let ran = from_rank_map(&dir, "1", &[&ranks], &["--no-admission-check"]);
    assert!(ran.ok, "{}", ran.err);
    assert!(ran.out.contains("admission: not checked"), "{}", ran.out);
    let file = SetFile::from_json(&dir.read("set.json")).unwrap();
    assert!(file.sources().iter().all(|s| s.kind() != KIND_ADMISSION));
}

#[test]
fn an_extract_must_list_exactly_the_accounts_debited() {
    let dir = Dir::new("admission-extract");
    let inputs = three_extracts(&dir);
    let refused = |debited: Vec<[u8; 32]>, why: &[String]| {
        let node = serve(Node::debiting(&[(19, debited)]));
        let ran = agree(&dir, "20", "3", &inputs, None, Some(&node));
        assert!(!ran.ok);
        assert_eq!(ran.code, Some(1));
        assert!(ran.err.contains("nothing written"), "{}", ran.err);
        for why in why {
            assert!(ran.err.contains(why.as_str()), "{why}: {}", ran.err);
        }
        assert!(!dir.exists("set-20.json") && !dir.exists("record-20.json"));
    };
    // A member that paid nothing.
    refused(
        accounts(5),
        &["1 in the map but not debited".into(), b58(&[5; 32])],
    );
    // A debited account the map leaves out.
    let mut more = accounts(6);
    more.push([6; 32]);
    refused(
        more,
        &["1 debited but not in the map".into(), b58(&[6; 32])],
    );
    // Equal, and it passes.
    let node = serve(Node::debiting(&[(19, accounts(6))]));
    assert!(agree(&dir, "20", "3", &inputs, None, Some(&node)).ok);
}

/// A snapshot holds the maps of several epochs. The debits tell them apart.
#[test]
fn the_map_of_another_epoch_is_refused() {
    let dir = Dir::new("admission-epoch");
    let inputs = three_extracts(&dir);
    // Epoch 20's first block admitted a different six from epoch 19's.
    let mut later = accounts(5);
    later.push([9; 32]);
    let node = serve(Node::debiting(&[(19, accounts(6)), (20, later)]));
    // The extracts' map for 21 lists epoch 19's six: it is not 21's.
    let ran = agree(&dir, "21", "3", &inputs, None, Some(&node));
    assert!(!ran.ok);
    assert!(
        ran.err.contains(&b58(&[5; 32])) && ran.err.contains(&b58(&[9; 32])),
        "{}",
        ran.err
    );
    assert!(ran.err.contains(&format!("slot {}", first_block(20))));
    assert!(agree(&dir, "20", "3", &inputs, None, Some(&node)).ok);
}

#[test]
fn no_debits_to_compare_with_is_a_refusal() {
    let dir = Dir::new("admission-none");
    let inputs = three_extracts(&dir);
    let refused = |admission: &[&str], why: &str| {
        let (set, record) = (dir.path("set-20.json"), dir.path("record-20.json"));
        let mut args = vec![
            "agree", "--epoch", "20", "--quorum", "3", "--set", &set, "--record", &record,
        ];
        args.extend(admission);
        args.extend(inputs.iter().map(String::as_str));
        let ran = run(&args);
        assert!(!ran.ok);
        assert!(ran.err.contains(why), "{why}: {}", ran.err);
        assert!(!ran.err.contains("SECRET-KEY") && !ran.out.contains("SECRET-KEY"));
        assert!(!dir.exists("set-20.json") && !dir.exists("record-20.json"));
    };
    // A block with no debits: admission was not in force, or the node keeps
    // no rewards. Either way there is nothing to compare with.
    let empty = serve(Node::debiting(&[(19, vec![])]));
    refused(&["--admission-url", &empty], "no VATDebit rewards");
    // A node without the block.
    let pruned = serve(Node::debiting(&[(18, accounts(6))]));
    refused(
        &["--admission-url", &pruned],
        "missing in long-term storage",
    );
    // Nothing there at all.
    refused(&["--admission-url", &nobody()], "nothing written");
    // The check is not skipped by leaving it out.
    refused(&[], "--admission-url is required, or --no-admission-check");
    refused(
        &["--admission-url", &empty, "--no-admission-check"],
        "not both",
    );
}

#[test]
fn skipping_the_check_leaves_it_out_of_the_record() {
    let dir = Dir::new("admission-skipped");
    let inputs = three_extracts(&dir);
    let node = serve(Node::debiting(&[(19, accounts(6))]));
    assert!(agree(&dir, "20", "2", &inputs[..2], None, Some(&node)).ok);
    let checked = dir.path("set-20.json");
    fs::rename(&checked, dir.path("checked.json")).unwrap();
    fs::remove_file(dir.path("record-20.json")).unwrap();

    // Not checked now, so the record does not say it was, even for an
    // input that carries a check.
    let with_checked = [dir.path("checked.json"), inputs[2].clone()];
    let ran = agree(&dir, "20", "3", &with_checked, None, None);
    assert!(ran.ok, "{}", ran.err);
    assert!(
        ran.out
            .contains("admission: not checked (--no-admission-check)"),
        "{}",
        ran.out
    );
    let file = SetFile::from_json(&dir.read("set-20.json")).unwrap();
    assert_eq!(file.sources().len(), 3);
    assert!(file.sources().iter().all(|s| s.kind() != KIND_ADMISSION));
    let record = parse(&dir.read("record-20.json")).unwrap().pop().unwrap();
    assert_eq!(record.record().sources(), file.sources());
    let ran = run(&["show", &dir.path("record-20.json")]);
    assert!(
        ran.out
            .contains("members not checked against the admission debits"),
        "{}",
        ran.out
    );
}

#[test]
fn the_check_is_not_a_source_for_the_quorum() {
    let dir = Dir::new("admission-quorum");
    let inputs = three_extracts(&dir);
    let node = serve(Node::debiting(&[(19, accounts(6))]));
    // One reading and a check, carried in a set file.
    assert!(agree(&dir, "20", "1", &inputs[..1], None, Some(&node)).ok);
    fs::rename(dir.path("set-20.json"), dir.path("one.json")).unwrap();
    fs::remove_file(dir.path("record-20.json")).unwrap();
    let ran = agree(&dir, "20", "2", &[dir.path("one.json")], None, Some(&node));
    assert!(!ran.ok);
    assert!(
        ran.err.contains("1 distinct sources agree, 2 needed"),
        "{}",
        ran.err
    );
    let ran = agree(&dir, "20", "2", &inputs[..2], None, Some(&node));
    assert!(ran.ok, "{}", ran.err);
    assert!(
        ran.out.contains("agreed: 2 sources give epoch 20"),
        "{}",
        ran.out
    );
}

/// A set file lists keys, not vote accounts. It counts as checked if it
/// carries a check against the same block, or by being the same set as an
/// input that lists accounts.
#[test]
fn a_set_file_is_checked_by_what_it_carries_or_by_an_extract() {
    let dir = Dir::new("admission-set-file");
    let inputs = three_extracts(&dir);
    let node = serve(Node::debiting(&[(19, accounts(6))]));
    let elsewhere = serve(Node {
        debits: [(19, accounts(6))].into(),
        ..Node::default()
    });
    let made = |name: &str, admission: Option<&str>| {
        assert!(agree(&dir, "20", "1", &inputs[..1], None, admission).ok);
        fs::rename(dir.path("set-20.json"), dir.path(name)).unwrap();
        fs::remove_file(dir.path("record-20.json")).unwrap();
        dir.path(name)
    };
    let checked = made("checked.json", Some(&node));
    let unchecked = made("unchecked.json", None);

    let ran = agree(
        &dir,
        "20",
        "1",
        std::slice::from_ref(&checked),
        None,
        Some(&elsewhere),
    );
    assert!(ran.ok, "{}", ran.err);
    fs::remove_file(dir.path("set-20.json")).unwrap();
    fs::remove_file(dir.path("record-20.json")).unwrap();

    let ran = agree(
        &dir,
        "20",
        "1",
        std::slice::from_ref(&unchecked),
        None,
        Some(&node),
    );
    assert!(!ran.ok);
    assert!(
        ran.err.contains("no input lists the vote accounts"),
        "{}",
        ran.err
    );
    let ran = agree(
        &dir,
        "20",
        "2",
        &[unchecked, inputs[1].clone()],
        None,
        Some(&node),
    );
    assert!(ran.ok, "{}", ran.err);
    fs::remove_file(dir.path("set-20.json")).unwrap();
    fs::remove_file(dir.path("record-20.json")).unwrap();

    // Checked against some other block than the one read now.
    let mut text = fs::read_to_string(&checked).unwrap();
    text = text.replace(
        &format!(r#""slot":{}"#, first_block(19)),
        &format!(r#""slot":{}"#, first_block(19) + 1),
    );
    let moved = dir.write("moved.json", &text);
    let ran = agree(&dir, "20", "1", &[moved], None, Some(&node));
    assert!(!ran.ok);
    assert!(
        ran.err.contains(&format!(
            "checked against the block at slot {}, not {}",
            first_block(19) + 1,
            first_block(19)
        )),
        "{}",
        ran.err
    );
}
