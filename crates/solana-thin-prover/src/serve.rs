//! Proofs over HTTP.
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /proof/<signature>` | 200 and the proof's bytes; 404 and the reason when it cannot be built; 503 when it could not be built just now |
//! | `GET /proof/<signature>?slot=N` | the same, with the caller's slot hint in place of the RPC node's |
//! | `GET /finality/<slot>` | 200 and the certificate for that slot's block, if one is held; 404 otherwise |
//! | `GET /set/<epoch>` | 200 and the set file the prover verifies that epoch with; 404 otherwise |
//! | `GET /health` | 200 and a JSON object of counters |
//!
//! Everything here is small and bounded. One thread accepts, a fixed number
//! answer, and one owns the socket to the validators. A connection gets a
//! few seconds to send its request line and is closed after one answer. A
//! client that stalls holds one of the answering threads until its
//! timeout; the fetching thread never touches a client's socket, so it is
//! never held at all.

use crate::anchor::encode_certificate;
use crate::peers::PeerBook;
use crate::prove::{held_certificate, held_proof, Prover};
use crate::refusal::Refusal;
use crate::store::Store;
use crate::trust::Trust;
use serde_json::json;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Longest request head read. A signature is 88 characters.
const MAX_REQUEST: usize = 2048;

/// Where a slot hint for a signature comes from.
pub trait SlotHints: Send + Sync {
    /// The slot `signature` is said to have landed in, `None` if the source
    /// does not know it, or why the source could not be asked.
    fn slot_of(&self, signature: &[u8; 64]) -> Result<Option<u64>, String>;
}

/// Gets a fresh list of peers, or says why it could not.
pub type Refresh = Box<dyn FnMut() -> Result<PeerBook, String> + Send>;

/// The server's bounds.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Threads answering requests.
    pub workers: usize,
    /// Accepted connections that may wait for one of them.
    pub backlog: usize,
    /// Proofs that may wait to be built.
    pub queue: usize,
    /// How long a client has to send its request.
    pub read_timeout: Duration,
    /// How long a client has to take each piece of the answer.
    pub write_timeout: Duration,
    /// How long a request waits for its proof to be built before it is
    /// told to ask again. The proof is built and kept regardless.
    pub proof_wait: Duration,
    /// How often the list of peers is fetched again.
    pub peer_refresh: Duration,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            workers: 8,
            backlog: 64,
            queue: 32,
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(10),
            proof_wait: Duration::from_secs(45),
            peer_refresh: Duration::from_secs(600),
        }
    }
}

struct Job {
    signature: [u8; 64],
    slot: u64,
    reply: mpsc::Sender<Result<Vec<u8>, Refusal>>,
}

#[derive(Default)]
struct Status {
    peers: usize,
    answering: usize,
    paused: bool,
    requests: u64,
    built: u64,
    refused: u64,
}

struct Shared {
    trust: Arc<Trust>,
    store: Arc<Store>,
    hints: Arc<dyn SlotHints>,
    jobs: SyncSender<Job>,
    status: Mutex<Status>,
    config: ServeConfig,
    stop: AtomicBool,
}

/// A running server.
pub struct Server {
    addr: SocketAddr,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Server {
    /// The address it listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Runs until the process ends.
    pub fn wait(self) {
        for thread in self.threads {
            let _ = thread.join();
        }
    }

    /// Stops accepting, lets requests in hand finish, and returns.
    pub fn stop(self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // The accepting thread is waiting for a connection: give it one.
        let _ = TcpStream::connect(self.addr);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Starts serving `prover`'s proofs on `listener`.
///
/// `hints` supplies the slot for a signature that comes without one, and
/// `refresh`, if given, a new list of peers every so often.
pub fn serve(
    listener: TcpListener,
    prover: Prover,
    hints: Arc<dyn SlotHints>,
    refresh: Option<Refresh>,
    config: ServeConfig,
) -> io::Result<Server> {
    let addr = listener.local_addr()?;
    let (jobs, job_queue) = mpsc::sync_channel(config.queue.max(1));
    let (connections, accepted) = mpsc::sync_channel::<TcpStream>(config.backlog.max(1));
    let shared = Arc::new(Shared {
        trust: prover.trust(),
        store: prover.store(),
        hints,
        jobs,
        status: Mutex::new(Status::default()),
        config,
        stop: AtomicBool::new(false),
    });
    let mut threads = Vec::new();

    let for_engine = Arc::clone(&shared);
    threads.push(std::thread::spawn(move || {
        engine(prover, job_queue, for_engine, refresh)
    }));

    let accepted = Arc::new(Mutex::new(accepted));
    for _ in 0..shared.config.workers.max(1) {
        let (shared, accepted) = (Arc::clone(&shared), Arc::clone(&accepted));
        threads.push(std::thread::spawn(move || loop {
            // Held only while waiting: the answer is written without it.
            let next = accepted.lock().unwrap().recv();
            match next {
                Ok(stream) => answer(&shared, stream),
                Err(_) => return,
            }
        }));
    }

    let for_accept = Arc::clone(&shared);
    threads.push(std::thread::spawn(move || {
        for stream in listener.incoming() {
            if for_accept.stop.load(Ordering::SeqCst) {
                return;
            }
            // With every thread busy and the backlog full, a new connection
            // is closed unanswered instead of piling up.
            if let Ok(stream) = stream {
                let _ = connections.try_send(stream);
            }
        }
    }));
    Ok(Server {
        addr,
        shared,
        threads,
    })
}

/// The one thread that talks to validators: builds the proofs asked for,
/// one at a time, and keeps the list of peers fresh.
fn engine(
    mut prover: Prover,
    jobs: Receiver<Job>,
    shared: Arc<Shared>,
    mut refresh: Option<Refresh>,
) {
    let mut refreshed = Instant::now();
    let note = |prover: &Prover, outcome: Option<bool>| {
        let mut status = shared.status.lock().unwrap();
        status.peers = prover.fetcher().peers().len();
        status.answering = prover.fetcher().peers().answering();
        status.paused = prover.fetcher().is_paused();
        status.requests = prover.fetcher().net_stats().requests;
        match outcome {
            Some(true) => status.built += 1,
            Some(false) => status.refused += 1,
            None => {}
        }
    };
    note(&prover, None);
    while !shared.stop.load(Ordering::SeqCst) {
        if let Some(refresh) = refresh.as_mut() {
            if refreshed.elapsed() >= shared.config.peer_refresh {
                refreshed = Instant::now();
                // A node that cannot answer leaves the old list in place.
                if let Ok(peers) = refresh() {
                    if !peers.is_empty() {
                        prover.set_peers(peers);
                    }
                }
            }
        }
        match jobs.recv_timeout(Duration::from_millis(200)) {
            Ok(job) => {
                let result = prover.prove(&job.signature, job.slot);
                note(&prover, Some(result.is_ok()));
                // The asker may have given up waiting; the proof is kept.
                let _ = job.reply.send(result);
            }
            Err(RecvTimeoutError::Timeout) => note(&prover, None),
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

fn text(status: u16, message: impl Into<String>) -> Response {
    let mut body = message.into().into_bytes();
    body.push(b'\n');
    Response {
        status,
        content_type: "text/plain; charset=utf-8",
        body,
    }
}

fn bytes(body: Vec<u8>) -> Response {
    Response {
        status: 200,
        content_type: "application/octet-stream",
        body,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    }
}

/// Reads one request and writes one answer.
fn answer(shared: &Shared, mut stream: TcpStream) {
    let response = match read_target(&mut stream, shared.config.read_timeout) {
        Ok(target) => respond(shared, &target),
        Err(response) => response,
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    let _ = stream.set_write_timeout(Some(shared.config.write_timeout));
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&response.body));
    let _ = stream.shutdown(Shutdown::Both);
}

/// The target of a `GET` request, read within `within` in all, however the
/// client spaces its bytes.
fn read_target(stream: &mut TcpStream, within: Duration) -> Result<String, Response> {
    let deadline = Instant::now() + within;
    let mut head = Vec::new();
    let mut buffer = [0u8; 512];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return Err(text(408, "the request did not arrive in time"));
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return Err(text(408, "the request did not arrive in time")),
            Ok(n) => head.extend_from_slice(&buffer[..n]),
        }
        if head.len() > MAX_REQUEST {
            return Err(text(431, "the request is too long"));
        }
    }
    let head = String::from_utf8_lossy(&head);
    let mut line = head.lines().next().unwrap_or_default().split(' ');
    match (line.next(), line.next(), line.next()) {
        (Some("GET"), Some(target), Some(version)) if version.starts_with("HTTP/1.") => {
            Ok(target.to_string())
        }
        (Some(_), Some(_), Some(version)) if version.starts_with("HTTP/1.") => {
            Err(text(405, "only GET is answered"))
        }
        _ => Err(text(400, "not an HTTP request")),
    }
}

fn respond(shared: &Shared, target: &str) -> Response {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments[..] {
        ["health"] => health(shared),
        ["proof", signature] => proof(shared, signature, query),
        ["finality", slot] => match slot.parse::<u64>() {
            Ok(slot) => held_certificate(&shared.store, &shared.trust, slot)
                .and_then(|certificate| encode_certificate(&certificate))
                .map(bytes)
                .unwrap_or_else(|| text(404, format!("no certificate is held for slot {slot}"))),
            Err(_) => text(400, "a slot is a number"),
        },
        ["set", epoch] => match epoch.parse::<u64>() {
            Ok(epoch) => match shared.trust.set_file(epoch) {
                Some(file) => Response {
                    status: 200,
                    content_type: "application/json",
                    body: file.to_json().into_bytes(),
                },
                None => text(
                    404,
                    format!(
                        "no set is pinned for epoch {epoch} (pinned: {:?})",
                        shared.trust.epochs()
                    ),
                ),
            },
            Err(_) => text(400, "an epoch is a number"),
        },
        _ => text(
            404,
            "nothing here: try /proof/<signature>, /finality/<slot>, /set/<epoch> or /health",
        ),
    }
}

fn health(shared: &Shared) -> Response {
    let usage = shared.store.usage();
    let status = shared.status.lock().unwrap();
    let body = json!({
        "status": if status.paused { "paused: peers are not answering" } else { "ok" },
        "cluster": shared.trust.cluster(),
        "shred_version": shared.trust.shred_version(),
        "epochs": shared.trust.epochs(),
        "peers": status.peers,
        "peers_answering": status.answering,
        "requests_sent": status.requests,
        "proofs_built": status.built,
        "refused": status.refused,
        "store": {
            "blocks": usage.blocks,
            "block_bytes": usage.block_bytes,
            "proofs_and_certificates": usage.kept,
            "proof_and_certificate_bytes": usage.kept_bytes,
            "cap_bytes": usage.cap,
        },
    });
    Response {
        status: 200,
        content_type: "application/json",
        body: (body.to_string() + "\n").into_bytes(),
    }
}

fn proof(shared: &Shared, signature: &str, query: &str) -> Response {
    let signature: [u8; 64] = match bs58::decode(signature)
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
    {
        Some(signature) => signature,
        None => return text(400, "not a transaction signature: 64 bytes in base58"),
    };
    if let Some(proof) = held_proof(&shared.store, &shared.trust, &signature) {
        return bytes(proof);
    }
    let given = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("slot="))
        .map(str::parse::<u64>);
    let slot = match given {
        Some(Ok(slot)) => slot,
        Some(Err(_)) => return text(400, "a slot is a number"),
        // Asked from this thread: a slow RPC node holds up one answer, and
        // not the fetching.
        None => match shared.hints.slot_of(&signature) {
            Ok(Some(slot)) => slot,
            Ok(None) => {
                return text(
                    404,
                    "the RPC node does not know this transaction; if you know its slot, add \
                     ?slot=N",
                )
            }
            Err(why) => return text(503, format!("no slot hint from the RPC node: {why}")),
        },
    };
    let (reply, result) = mpsc::channel();
    let job = Job {
        signature,
        slot,
        reply,
    };
    match shared.jobs.try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            return text(503, "too many proofs are waiting to be built; ask again")
        }
        Err(TrySendError::Disconnected(_)) => return text(503, "shutting down"),
    }
    match result.recv_timeout(shared.config.proof_wait) {
        Ok(Ok(proof)) => bytes(proof),
        Ok(Err(refusal)) if refusal.is_temporary() => text(503, refusal.to_string()),
        Ok(Err(refusal)) => text(404, refusal.to_string()),
        Err(_) => text(503, "the proof is still being built; ask again"),
    }
}
