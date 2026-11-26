//! The `prover` binary, run as an operator would run it: against validators
//! on loopback and a local stand-in for an RPC node, reached with `curl`.

mod common;

use common::*;
use serde_json::{json, Value};
use solana_thin::TxProof;
use solana_thin_setlog::{to_text, SignedRecord, SigningKey};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// An RPC node, as far as the prover can tell: it lists `peers` as the
/// cluster's nodes, reports epochs of `slots_per_epoch` slots, and knows
/// which slot each of the chain's transactions landed in.
fn rpc_node(chain: &Chain, peers: &[&FakePeer], shred_version: u16) -> String {
    let mut listed = nodes(peers);
    for node in listed.as_array_mut().unwrap() {
        node["shredVersion"] = json!(shred_version);
    }
    let slots_per_epoch = chain.slots_per_epoch;
    let landed: HashMap<String, u64> = chain
        .blocks
        .iter()
        .flat_map(|(slot, built)| {
            built
                .signatures
                .iter()
                .map(|s| (bs58::encode(s).into_string(), *slot))
        })
        .collect();
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
            let result = match request["method"].as_str().unwrap() {
                "getClusterNodes" => listed.clone(),
                "getEpochSchedule" => json!({"slotsPerEpoch": slots_per_epoch, "warmup": false,
                    "firstNormalEpoch": 0, "firstNormalSlot": 0,
                    "leaderScheduleSlotOffset": slots_per_epoch}),
                "getSignatureStatuses" => {
                    let signature = request["params"][0][0].as_str().unwrap();
                    let status = landed.get(signature).map(|slot| {
                        json!({"slot": slot, "confirmations": null, "err": null,
                               "confirmationStatus": "finalized"})
                    });
                    json!({"context": {"slot": 1}, "value": [status]})
                }
                other => panic!("the prover has no business calling {other}"),
            };
            let answer = json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{answer}",
                answer.len()
            );
        }
    });
    format!("http://{address}")
}

struct Ran {
    ok: bool,
    out: String,
    err: String,
}

fn prover_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_prover"));
    command.args(args).args(["--bind", "127.0.0.1:0"]);
    command
}

fn run(args: &[&str]) -> Ran {
    let output = prover_command(args).output().unwrap();
    Ran {
        ok: output.status.success(),
        out: String::from_utf8(output.stdout).unwrap(),
        err: String::from_utf8(output.stderr).unwrap(),
    }
}

fn write_set(dir: &Path, chain: &Chain, epoch: u64) -> String {
    let path = dir.join(format!("set-{epoch}.json"));
    std::fs::write(&path, chain.set_file(epoch).to_json()).unwrap();
    path.to_str().unwrap().to_string()
}

fn text(signature: &[u8; 64]) -> String {
    bs58::encode(signature).into_string()
}

/// Kills the server when the test ends, however it ends.
struct Serving(Child);

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http_get(address: &str, target: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).unwrap();
    write!(stream, "GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    (
        head.split(' ').nth(1).unwrap().parse().unwrap(),
        raw[split + 4..].to_vec(),
    )
}

#[test]
fn blocks_are_fetched_and_transactions_proven_and_served() {
    let chain = Chain::linear(100..106);
    let peers = [
        FakePeer::start(1, &chain, Behavior::Honest),
        FakePeer::start(2, &chain, Behavior::Duplicates),
    ];
    let url = rpc_node(&chain, &[&peers[0], &peers[1]], VERSION);
    let dir = directory("cli-run");
    let set = write_set(&dir, &chain, 0);
    let store = dir.join("store");
    let common = [
        "--rpc",
        &url,
        "--set",
        &set,
        "--slots-per-epoch",
        "432000",
        "--store",
        store.to_str().unwrap(),
        "--rate",
        "1000",
    ];
    let client = chain.client(&[0]);

    // fetch: two slots, every transaction proven.
    let ran = run(&[&["fetch", "--prove-all", "101", "102"], &common[..]].concat());
    assert!(ran.ok, "{}{}", ran.out, ran.err);
    assert!(ran.err.contains("2 of 2 nodes can be asked"), "{}", ran.err);
    assert!(ran.err.contains("pinned from the set file itself"));
    for slot in [101u64, 102] {
        let line = ran
            .out
            .lines()
            .find(|line| line.starts_with(&format!("slot {slot}: ")))
            .unwrap();
        assert!(line.contains(&format!("block {}", hex::encode(chain.block(slot).id))));
        assert!(line.contains(&format!(
            "fast certificate for slot {slot} from the footer of slot {}",
            slot + 1
        )));
        assert!(line.contains("128 shreds from 2 holders"), "{line}");
        assert!(
            line.contains("3 transactions, 3 proven and verified"),
            "{line}"
        );
    }
    assert!(ran
        .out
        .contains("2 blocks fetched by certified id, 0 slots refused"));
    assert!(ran.out.contains("6 of 6 transactions proven and verified"));

    // prove: the slot comes from the RPC node, the proof goes to a file.
    let signature = chain.signature(103, 1);
    let out = dir.join("tx.proof");
    let ran = run(&[
        &["prove", &text(&signature), "--out", out.to_str().unwrap()],
        &common[..],
    ]
    .concat());
    assert!(ran.ok, "{}{}", ran.out, ran.err);
    assert!(ran.err.contains("says slot 103"), "{}", ran.err);
    assert!(ran
        .out
        .contains("of slot 103, final by a fast certificate for slot 103"));
    let proof = TxProof::from_bytes(&std::fs::read(&out).unwrap(), client.limits()).unwrap();
    assert_eq!(
        client.verify_signature(&proof, &signature).unwrap().block,
        chain.block(103)
    );

    // A wrong hint, and a slot that was fetched before: no proof, and why.
    let elsewhere = text(&chain.signature(104, 0));
    let ran = run(&[&["prove", &elsewhere, "--slot", "101"], &common[..]].concat());
    assert!(!ran.ok);
    assert!(
        ran.err.contains("not in the block of slot 101"),
        "{}",
        ran.err
    );
    let ran = run(&[&["fetch", "101", "900"], &common[..]].concat());
    assert!(!ran.ok);
    assert!(ran.out.contains("slot 101: ") && ran.out.contains("128 shreds already held"));
    assert!(
        ran.out
            .contains("slot 900: refused: no finality certificate"),
        "{}",
        ran.out
    );

    // serve: the same proof over HTTP, and one that has to be fetched first.
    let mut child = prover_command(&[&["serve", "--listen", "127.0.0.1:0"], &common[..]].concat())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = BufReader::new(child.stderr.take().unwrap());
    let _serving = Serving(child);
    let address = stderr
        .lines()
        .map(|line| line.unwrap())
        .find_map(|line| {
            line.strip_prefix("prover: listening on http://")
                .map(str::to_string)
        })
        .expect("the server says where it listens");
    for signature in [signature, chain.signature(104, 0)] {
        let (status, body) = http_get(&address, &format!("/proof/{}", text(&signature)));
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let proof = TxProof::from_bytes(&body, client.limits()).unwrap();
        client.verify_signature(&proof, &signature).unwrap();
    }
    let (status, body) = http_get(&address, &format!("/proof/{}", text(&[9; 64])));
    assert_eq!(status, 404);
    assert!(String::from_utf8_lossy(&body).contains("does not know this transaction"));
    let (status, body) = http_get(&address, "/health");
    assert_eq!(status, 200);
    let health: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["store"]["blocks"], 4);
}

#[test]
fn a_set_log_decides_the_hash_when_one_is_given() {
    let chain = Chain::linear(100..103);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let url = rpc_node(&chain, &[&peer], VERSION);
    let dir = directory("cli-log");
    let set = write_set(&dir, &chain, 0);
    let signer = SigningKey::from_seed([3; 32]).unwrap();
    let mut record = SignedRecord::unsigned(chain.set_file(0).candidate([0; 32]).unwrap());
    record.sign(&signer);
    let log = dir.join("log.jsonl");
    std::fs::write(&log, to_text(&[record])).unwrap();
    let store = dir.join("store");
    let base = [
        "fetch",
        "101",
        "--rpc",
        &url,
        "--set",
        &set,
        "--slots-per-epoch",
        "432000",
        "--store",
        store.to_str().unwrap(),
        "--log",
        log.to_str().unwrap(),
    ];
    let key = hex::encode(signer.public_key());
    let ran = run(&[&base[..], &["--signer", &key, "--threshold", "1"]].concat());
    assert!(ran.ok, "{}{}", ran.out, ran.err);
    assert!(ran.err.contains("pinned from the log"));

    // A log signed by somebody else pins nothing.
    let other = hex::encode(SigningKey::from_seed([4; 32]).unwrap().public_key());
    let ran = run(&[&base[..], &["--signer", &other, "--threshold", "1"]].concat());
    assert!(!ran.ok);
    assert!(ran.err.contains("log.jsonl"), "{}", ran.err);
    let ran = run(&base);
    assert!(!ran.ok);
    assert!(ran
        .err
        .contains("--log needs --signer keys and a --threshold"));

    // A log that has no record for the epoch of a set file.
    let later = dir.join("set-later.json");
    let mut wrong_epoch = Chain::new(432_000, 99);
    wrong_epoch.push(432_100, None);
    std::fs::write(&later, wrong_epoch.set_file(1).to_json()).unwrap();
    let ran = run(&[
        &base[..],
        &[
            "--signer",
            &key,
            "--threshold",
            "1",
            "--set",
            later.to_str().unwrap(),
        ],
    ]
    .concat());
    assert!(!ran.ok);
    assert!(
        ran.err.contains("the log has no record for epoch 1"),
        "{}",
        ran.err
    );
}

#[test]
fn a_wrong_setup_is_refused_before_anything_is_asked_of_a_validator() {
    let chain = Chain::linear(100..103);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let url = rpc_node(&chain, &[&peer], VERSION);
    let restarted = rpc_node(&chain, &[&peer], VERSION + 1);
    let dir = directory("cli-setup");
    let set = write_set(&dir, &chain, 0);
    let store = dir.join("store");
    let store = store.to_str().unwrap();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["--rpc", &url], "--set is required"),
        (
            vec!["--set", &set, "--slots-per-epoch", "432000"],
            "--rpc is required",
        ),
        (
            vec!["--rpc", &url, "--set", &set],
            "the epoch schedule of cluster \"localnet\" is not known",
        ),
        (
            vec!["--rpc", &url, "--set", &set, "--slots-per-epoch", "64"],
            "reports epochs of 432000 slots",
        ),
        (
            vec!["--rpc", &url, "--set", &set, "--warmup"],
            "--warmup needs --slots-per-epoch",
        ),
        (
            vec![
                "--rpc",
                &url,
                "--set",
                &set,
                "--slots-per-epoch",
                "432000",
                "--shred-version",
                "7",
            ],
            "the set files are for shred version 4242, not 7",
        ),
        (
            vec![
                "--rpc",
                &restarted,
                "--set",
                &set,
                "--slots-per-epoch",
                "432000",
            ],
            "the cluster's nodes are on shred version 4243 and the pinned sets are for 4242",
        ),
        (
            vec![
                "--rpc",
                &url,
                "--set",
                &set,
                "--slots-per-epoch",
                "432000",
                "--rate",
                "0",
            ],
            "--rate is between 1 and 1000",
        ),
        (
            vec![
                "--rpc",
                "ftp://node",
                "--set",
                &set,
                "--slots-per-epoch",
                "432000",
            ],
            "a URL must start with https:// or http://",
        ),
        (
            vec![
                "--rpc",
                &url,
                "--set",
                "nowhere.json",
                "--slots-per-epoch",
                "432000",
            ],
            "nowhere.json",
        ),
        (
            vec![
                "--rpc",
                &url,
                "--set",
                &set,
                "--slots-per-epoch",
                "432000",
                "--fast",
            ],
            "unknown option --fast",
        ),
    ];
    for (args, complaint) in cases {
        let ran = run(&[&["fetch", "101", "--store", store], &args[..]].concat());
        assert!(!ran.ok, "{args:?}");
        assert!(ran.err.contains(complaint), "{args:?}: {}", ran.err);
    }
    // Nothing above got as far as a validator.
    assert_eq!(peer.seen().len(), 0);

    let ran = run(&[
        "fetch",
        "--rpc",
        &url,
        "--set",
        &set,
        "--slots-per-epoch",
        "432000",
    ]);
    assert!(ran.err.contains("give at least one slot"));
    let ran = run(&["prove", "abc", "--rpc", &url, "--set", &set]);
    assert!(ran.err.contains("not a transaction signature"));
    let ran = run(&["serve", "--rpc", &url, "--set", &set]);
    assert!(ran.err.contains("--listen is required"));
    let ran = run(&["mine"]);
    assert!(!ran.ok && ran.err.contains("prover fetch <options>"));
    let ran = run(&["help"]);
    assert!(ran.ok && ran.out.contains("prover serve <options>"));
}

#[test]
fn around_an_epoch_boundary_the_missing_set_is_named() {
    // Epochs of 32 slots. The tip is the first block of epoch 2; its footer
    // certifies the last block of epoch 1.
    let mut chain = Chain::new(32, 59);
    for slot in 60..=64 {
        chain.push(slot, Some(slot - 1));
    }
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let url = rpc_node(&chain, &[&peer], VERSION);
    let dir = directory("cli-boundary");
    let (old, new) = (write_set(&dir, &chain, 1), write_set(&dir, &chain, 2));
    let store = dir.join("store");
    let signature = text(&chain.signature(63, 0));
    let base = [
        "prove",
        &signature,
        "--rpc",
        &url,
        "--slots-per-epoch",
        "32",
        "--store",
        store.to_str().unwrap(),
        "--out",
        dir.join("tx.proof").to_str().unwrap(),
    ]
    .map(str::to_string);
    let with = |sets: &[&str]| {
        let mut args: Vec<&str> = base.iter().map(String::as_str).collect();
        for set in sets {
            args.extend(["--set", set]);
        }
        run(&args)
    };
    let ran = with(&[&new]);
    assert!(!ran.ok);
    assert!(
        ran.err.contains(
            "no validator set is pinned for epoch 1, which the certificate for slot 63 needs \
             (pinned: 2); pass that epoch's set file"
        ),
        "{}",
        ran.err
    );
    let ran = with(&[&new, &old]);
    assert!(ran.ok, "{}{}", ran.out, ran.err);
    assert!(ran
        .out
        .contains("of slot 63, final by a fast certificate for slot 63"));
}
