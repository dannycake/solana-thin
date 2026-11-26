//! The HTTP side: proofs, certificates and sets served to a client that
//! trusts none of it, the reason given with every refusal, and the bounds
//! that keep one client from holding up another or the fetching.

mod common;

use common::*;
use serde_json::Value;
use solana_thin::TxProof;
use solana_thin_prover::anchor::decode_certificate;
use solana_thin_prover::prove::{Prover, ProverConfig};
use solana_thin_prover::serve::{serve, ServeConfig, Server, SlotHints};
use solana_thin_prover::{PeerBook, Store};
use solana_thin_setlog::SetFile;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Slot hints from a table, as an RPC node would give them.
#[derive(Default)]
struct Hints {
    slots: HashMap<[u8; 64], u64>,
    down: bool,
    asked: AtomicUsize,
}

impl SlotHints for Hints {
    fn slot_of(&self, signature: &[u8; 64]) -> Result<Option<u64>, String> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.down {
            return Err("connection refused".into());
        }
        Ok(self.slots.get(signature).copied())
    }
}

fn hints_for(chain: &Chain) -> Hints {
    let slots = chain
        .blocks
        .iter()
        .flat_map(|(slot, built)| built.signatures.iter().map(|s| (*s, *slot)))
        .collect();
    Hints {
        slots,
        ..Hints::default()
    }
}

fn start(prover: Prover, hints: Hints, config: ServeConfig) -> (Server, Arc<Hints>) {
    let hints = Arc::new(hints);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = serve(listener, prover, hints.clone(), None, config).unwrap();
    (server, hints)
}

struct Answer {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }
}

/// Sends `request` as it is and reads the answer to its end.
fn exchange(addr: SocketAddr, request: &[u8]) -> Answer {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(request).unwrap();
    read_answer(&mut stream)
}

fn read_answer(stream: &mut TcpStream) -> Answer {
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("an HTTP answer");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let body = raw[split + 4..].to_vec();
    assert!(head.contains(&format!("Content-Length: {}", body.len())));
    assert!(head.contains("Connection: close"));
    Answer { status, head, body }
}

fn get(addr: SocketAddr, target: &str) -> Answer {
    exchange(
        addr,
        format!("GET {target} HTTP/1.1\r\nHost: prover\r\n\r\n").as_bytes(),
    )
}

fn base58(signature: &[u8; 64]) -> String {
    bs58::encode(signature).into_string()
}

#[test]
fn a_proof_is_served_and_verifies_with_only_the_set_and_the_shred_version() {
    let chain = Chain::linear(100..105);
    let peers = [
        FakePeer::start(1, &chain, Behavior::Honest),
        FakePeer::start(2, &chain, Behavior::Duplicates),
    ];
    let prover = prover("serve-proof", &chain, &[0], &[&peers[0], &peers[1]]);
    let (server, hints) = start(prover, hints_for(&chain), ServeConfig::default());
    let addr = server.addr();

    // The client's side: the set comes from anywhere, here from the prover
    // itself, and is held to a hash the client already has.
    let set = get(addr, "/set/0");
    assert_eq!(set.status, 200);
    assert!(set.head.contains("Content-Type: application/json"));
    let set = SetFile::from_json(&set.text()).unwrap();
    assert_eq!(set.set_hash(), chain.validators(0).set().hash());
    let client = chain.client(&[0]);

    for slot in [101, 103] {
        for n in 0..3 {
            let signature = chain.signature(slot, n);
            let answer = get(addr, &format!("/proof/{}", base58(&signature)));
            assert_eq!(answer.status, 200, "{}", answer.text());
            assert!(answer.head.contains("application/octet-stream"));
            let proof = TxProof::from_bytes(&answer.body, client.limits()).unwrap();
            let verified = client.verify_signature(&proof, &signature).unwrap();
            assert_eq!(verified.block, chain.block(slot));
        }
    }
    // A proof already built is served without asking for a hint again.
    let asked = hints.asked.load(Ordering::SeqCst);
    let again = get(
        addr,
        &format!("/proof/{}", base58(&chain.signature(101, 0))),
    );
    assert_eq!(again.status, 200);
    assert_eq!(hints.asked.load(Ordering::SeqCst), asked);

    // The certificate the proofs rest on.
    let finality = get(addr, "/finality/101");
    assert_eq!(finality.status, 200);
    let certificate = decode_certificate(&finality.body).unwrap();
    assert_eq!(certificate, chain.certificate(101));
    assert_eq!(
        client.verify_finality(&certificate).unwrap().block,
        chain.block(101)
    );

    let health: Value = serde_json::from_slice(&get(addr, "/health").body).unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["cluster"], CLUSTER);
    assert_eq!(health["shred_version"], VERSION);
    assert_eq!(health["epochs"], serde_json::json!([0]));
    assert_eq!(health["peers"], 2);
    assert_eq!(health["peers_answering"], 2);
    assert_eq!(health["proofs_built"], 6);
    assert_eq!(health["store"]["blocks"], 2);
    assert!(health["requests_sent"].as_u64().unwrap() > 256);
    server.stop();
}

#[test]
fn a_refusal_comes_with_its_reason() {
    let chain = Chain::linear([100, 101, 103, 104]);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let prover = prover("serve-refusals", &chain, &[0], &[&peer]);
    let (server, _) = start(prover, hints_for(&chain), ServeConfig::default());
    let addr = server.addr();
    let known = base58(&chain.signature(101, 0));
    let unknown = base58(&[7; 64]);

    let cases = [
        // The RPC node has never seen it, and no slot was given.
        (
            format!("/proof/{unknown}"),
            404,
            "does not know this transaction",
        ),
        // A hint that names a block it is not in.
        (
            format!("/proof/{known}?slot=103"),
            404,
            "not in the block of slot 103",
        ),
        // A hint that names a slot the cluster skipped.
        (
            format!("/proof/{known}?slot=102"),
            404,
            "slot 102 is not in the finalized chain",
        ),
        // A hint that names a slot far past the tip.
        (
            format!("/proof/{known}?slot=900"),
            404,
            "no finality certificate for slot 900",
        ),
        (
            format!("/proof/{known}?slot=soon"),
            400,
            "a slot is a number",
        ),
        (
            "/proof/not-a-signature".to_string(),
            400,
            "not a transaction signature",
        ),
        (
            format!("/proof/{}", &known[..40]),
            400,
            "not a transaction signature",
        ),
        (
            "/finality/100".to_string(),
            404,
            "no certificate is held for slot 100",
        ),
        ("/finality/x".to_string(), 400, "a slot is a number"),
        (
            "/set/9".to_string(),
            404,
            "no set is pinned for epoch 9 (pinned: [0])",
        ),
        ("/set/x".to_string(), 400, "an epoch is a number"),
        ("/".to_string(), 404, "nothing here"),
        ("/proof".to_string(), 404, "nothing here"),
        (format!("/proof/{known}/extra"), 404, "nothing here"),
    ];
    for (target, status, reason) in cases {
        let answer = get(addr, &target);
        assert_eq!(answer.status, status, "{target}: {}", answer.text());
        assert!(
            answer.text().contains(reason),
            "{target}: {}",
            answer.text()
        );
        assert!(answer.head.contains("text/plain"));
    }
    // None of that stops the right question from being answered.
    assert_eq!(get(addr, &format!("/proof/{known}")).status, 200);
    assert_eq!(get(addr, &format!("/proof/{known}?slot=101")).status, 200);
    server.stop();
}

#[test]
fn only_a_get_request_of_a_sane_size_is_answered() {
    let chain = Chain::linear(100..102);
    let prover = prover("serve-requests", &chain, &[0], &[]);
    let config = ServeConfig {
        read_timeout: Duration::from_millis(300),
        ..ServeConfig::default()
    };
    let (server, _) = start(prover, Hints::default(), config);
    let addr = server.addr();

    let post = exchange(addr, b"POST /proof/x HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(post.status, 405);
    let garbage = exchange(addr, b"\x16\x03\x01 not http at all\r\n\r\n");
    assert_eq!(garbage.status, 400);
    let old = exchange(addr, b"GET /health\r\n\r\n");
    assert_eq!(old.status, 400);
    let long = format!("GET /proof/{} HTTP/1.1\r\n\r\n", "1".repeat(4_000));
    assert_eq!(exchange(addr, long.as_bytes()).status, 431);
    // Half a request, then nothing.
    let started = Instant::now();
    let stalled = exchange(addr, b"GET /health HTTP/1.1\r\nHost:");
    assert_eq!(stalled.status, 408);
    assert!(started.elapsed() < Duration::from_secs(2));
    // With no peers a proof cannot be built, and the answer says so.
    let nobody = get(addr, &format!("/proof/{}?slot=101", base58(&[7; 64])));
    assert_eq!(nobody.status, 404);
    assert!(nobody.text().contains("no validator"));
    server.stop();
}

#[test]
fn a_node_that_gives_no_hint_is_a_temporary_failure() {
    let chain = Chain::linear(100..104);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let prover = prover("serve-no-rpc", &chain, &[0], &[&peer]);
    let hints = Hints {
        down: true,
        ..Hints::default()
    };
    let (server, _) = start(prover, hints, ServeConfig::default());
    let signature = base58(&chain.signature(101, 0));
    let answer = get(server.addr(), &format!("/proof/{signature}"));
    assert_eq!(answer.status, 503);
    assert!(answer.text().contains("no slot hint from the RPC node"));
    // The caller's own hint needs no node.
    let answer = get(server.addr(), &format!("/proof/{signature}?slot=101"));
    assert_eq!(answer.status, 200);
    server.stop();
}

#[test]
fn a_stalled_client_holds_up_neither_other_clients_nor_the_fetching() {
    let chain = Chain::linear(100..104);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    let prover = prover("serve-stalled", &chain, &[0], &[&peer]);
    let config = ServeConfig {
        workers: 2,
        read_timeout: Duration::from_secs(6),
        ..ServeConfig::default()
    };
    let (server, _) = start(prover, hints_for(&chain), config);
    let addr = server.addr();

    // A client that connects and says half of what it came to say.
    let mut stalled = TcpStream::connect(addr).unwrap();
    stalled.write_all(b"GET /proof/").unwrap();
    std::thread::sleep(Duration::from_millis(100));

    let started = Instant::now();
    let signature = chain.signature(102, 0);
    let answer = get(addr, &format!("/proof/{}", base58(&signature)));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(get(addr, "/health").status, 200);
    // Fetched, proven and served well inside the stalled client's time.
    assert!(started.elapsed() < Duration::from_secs(5));

    // The stalled one is told so and closed, not kept.
    let answer = read_answer(&mut stalled);
    assert_eq!(answer.status, 408);
    assert!(started.elapsed() >= Duration::from_secs(5));
    server.stop();
}

#[test]
fn proofs_that_cannot_be_built_in_time_are_told_to_ask_again() {
    let chain = Chain::linear(100..104);
    // Peers that never answer: every proof takes as long as giving up does.
    let peers: Vec<FakePeer> = (1..=3)
        .map(|n| FakePeer::start(n, &chain, Behavior::Silent))
        .collect();
    let store = Arc::new(Store::open(&directory("serve-busy"), 64 << 20).unwrap());
    let searching = ProverConfig {
        certificate_window: 2,
        certificate_passes: 1,
        ..ProverConfig::default()
    };
    let fetcher = fetcher(&peers.iter().collect::<Vec<_>>(), quick());
    let prover = Prover::new(chain.trust(&[0]), store, fetcher, searching);
    let config = ServeConfig {
        queue: 1,
        proof_wait: Duration::from_millis(250),
        ..ServeConfig::default()
    };
    let (server, _) = start(prover, Hints::default(), config);
    let addr = server.addr();

    let askers: Vec<_> = (0..5u8)
        .map(|n| {
            std::thread::spawn(move || {
                let target = format!("/proof/{}?slot=101", base58(&[n + 1; 64]));
                let answer = get(addr, &target);
                (answer.status, answer.text())
            })
        })
        .collect();
    let answers: Vec<(u16, String)> = askers.into_iter().map(|a| a.join().unwrap()).collect();
    // One is being built and one waits its turn; the rest find the queue
    // full. Nobody is left hanging and nobody gets a proof.
    assert!(
        answers.iter().all(|(status, _)| *status == 503),
        "{answers:?}"
    );
    let full = answers
        .iter()
        .filter(|(_, why)| why.contains("too many proofs"))
        .count();
    let late = answers
        .iter()
        .filter(|(_, why)| why.contains("still being built"))
        .count();
    assert!(full >= 3 && late >= 1 && full + late == 5, "{answers:?}");
    // Health is answered throughout: it never waits on the fetching.
    assert_eq!(get(addr, "/health").status, 200);
    server.stop();
}

#[test]
fn the_list_of_peers_is_fetched_again() {
    let chain = Chain::linear(100..104);
    let peer = FakePeer::start(1, &chain, Behavior::Honest);
    // It starts with nobody to ask, and learns of a validator later.
    let prover = prover("serve-refresh", &chain, &[0], &[]);
    let listed = nodes(&[&peer]);
    let mut calls = 0;
    let refresh = Box::new(move || {
        calls += 1;
        if calls == 1 {
            return Err("the node is restarting".to_string());
        }
        Ok(PeerBook::from_cluster_nodes(&listed, VERSION, 3).0)
    });
    let config = ServeConfig {
        peer_refresh: Duration::from_millis(150),
        ..ServeConfig::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let hints = Arc::new(hints_for(&chain));
    let server = serve(listener, prover, hints, Some(refresh), config).unwrap();
    let target = format!("/proof/{}", base58(&chain.signature(101, 0)));
    let first = get(server.addr(), &target);
    assert_eq!(first.status, 404);
    assert!(first.text().contains("no validator"));
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(get(server.addr(), &target).status, 200);
    server.stop();
}
