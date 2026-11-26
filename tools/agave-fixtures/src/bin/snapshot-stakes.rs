//! Reads the validator sets out of the bank snapshots that nodes serve.
//!
//! Every bank snapshot carries the epoch-stakes maps for the epochs from
//! three back to one ahead: the exact stake the cluster ranks validators by,
//! already filtered for admission. A node that serves snapshots over HTTP
//! sends the bank file first, so the maps can be had from the first tens of
//! megabytes of an archive that is hundreds of megabytes long.
//!
//! ```text
//! snapshot-stakes --cluster <name> --out <dir> --rpc <url> [--count 3]
//! snapshot-stakes --cluster <name> --out <dir> --shred-version <n> --node <host:port> ...
//! ```
//!
//! With `--rpc` and no `--node`, nodes are found with `getClusterNodes` and
//! tried in a shuffled order until `--count` of them, no two on one network,
//! have given an extract. With `--node`, exactly those are read; `--rpc` is
//! then only asked for their identities and the shred version. Some nodes
//! serve a snapshot that is weeks old: when `--rpc` is given, a snapshot
//! more than `--max-age` slots (default 20,000) behind the cluster is not
//! downloaded.
//!
//! For each node this follows the redirect from
//! `/incremental-snapshot.tar.bz2`, streams the archive, and stops as soon
//! as the bank file is complete or `--max-bytes` (default 256 MiB) have been
//! read. The bank file is parsed by Agave's own snapshot code. Each epoch's
//! map is then ranked twice, by Agave and by solana-thin, and the two must
//! give the same list. One extract per node is written to `<dir>`, in the
//! format `setlog agree` reads:
//!
//! ```text
//! {"format":"solana-thin/snapshot-extract/v1","cluster":"...","shred_version":n,
//!  "node":"<identity or address>","slot":n,
//!  "epochs":[{"epoch":n,"accounts":[{"vote_pubkey":"<hex>","node_pubkey":"<hex>",
//!                                    "bls_pubkey":"<hex or null>","stake":n},...]},...]}
//! ```
//!
//! A node is asked for one thing at a time and is never asked twice. Nothing
//! in an archive vouches for the maps: they are not an input to the bank
//! hash. An extract is what one node said, to be compared with others.

use {
    agave_fs::io_setup::IoSetupState,
    agave_snapshots::snapshot_archive_info::FullSnapshotArchiveInfo,
    serde_json::{Value, json},
    solana_runtime::{epoch_stakes::VersionedEpochStakes, snapshot_utils},
    solana_thin::{Error as ThinError, Validator, ValidatorSet, VoteAccount},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File},
        io::{self, BufWriter, Read, Write},
        net::{IpAddr, SocketAddr},
        path::{Path, PathBuf},
        process::ExitCode,
        thread,
        time::{Duration, Instant, SystemTime},
    },
};

const EXTRACT_FORMAT: &str = "solana-thin/snapshot-extract/v1";
/// Says what is asking and nothing about who runs it.
const USER_AGENT: &str = "snapshot-stakes";
/// Where every node redirects to its newest incremental snapshot.
const ENTRY_PATH: &str = "/incremental-snapshot.tar.bz2";
/// Compressed bytes read from one node before giving up on it. The bank file
/// has been complete by 68 to 80 MB on mainnet.
const DEFAULT_MAX_BYTES: u64 = 256 << 20;
/// Largest bank file written to disk. Mainnet's is about 170 MB.
const MAX_BANK_BYTES: u64 = 2 << 30;
/// Longest a download may take before it is abandoned.
const MAX_DOWNLOAD: Duration = Duration::from_secs(600);
/// How far behind the cluster a snapshot may be, in slots: a couple of
/// hours. An older one lacks the map for the next epoch, the one usually
/// wanted.
const DEFAULT_MAX_AGE: u64 = 20_000;
/// Nodes probed at once while looking for ones that serve snapshots. Each
/// node still gets one connection.
const PROBES_AT_ONCE: usize = 8;

const USAGE: &str = "\
usage: snapshot-stakes --cluster <name> --out <dir> [--rpc <url>] [--node <host:port> ...]
                       [--shred-version <n>] [--count <n>] [--max-bytes <n>] [--max-age <slots>]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("snapshot-stakes: {why}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    cluster: String,
    out: PathBuf,
    rpc: Option<String>,
    nodes: Vec<String>,
    shred_version: Option<u16>,
    count: usize,
    max_bytes: u64,
    max_age: u64,
}

fn options() -> Result<Options, String> {
    let mut options = Options {
        cluster: String::new(),
        out: PathBuf::new(),
        rpc: None,
        nodes: Vec::new(),
        shred_version: None,
        count: 3,
        max_bytes: DEFAULT_MAX_BYTES,
        max_age: DEFAULT_MAX_AGE,
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value\n{USAGE}"));
        let number = |text: String| {
            text.parse::<u64>()
                .map_err(|_| format!("{text}: not a number"))
        };
        match arg.as_str() {
            "--cluster" => options.cluster = value()?,
            "--out" => options.out = PathBuf::from(value()?),
            "--rpc" => options.rpc = Some(value()?),
            "--node" => options.nodes.push(value()?),
            "--shred-version" => {
                let version = number(value()?)?;
                options.shred_version =
                    Some(u16::try_from(version).map_err(|_| "--shred-version: too large")?);
            }
            "--count" => options.count = number(value()?)? as usize,
            "--max-bytes" => options.max_bytes = number(value()?)?,
            "--max-age" => options.max_age = number(value()?)?,
            _ => return Err(format!("unknown argument {arg}\n{USAGE}")),
        }
    }
    let name_ok = !options.cluster.is_empty()
        && options.cluster.len() <= 32
        && options
            .cluster
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !name_ok {
        return Err(format!(
            "--cluster must be lowercase letters, digits and '-'\n{USAGE}"
        ));
    }
    if options.out.as_os_str().is_empty() {
        return Err(format!("--out is required\n{USAGE}"));
    }
    if options.rpc.is_none() && (options.nodes.is_empty() || options.shred_version.is_none()) {
        return Err(format!(
            "without --rpc, give the nodes with --node and the cluster's --shred-version\n{USAGE}"
        ));
    }
    if options.count == 0 {
        return Err("--count must be at least 1".into());
    }
    Ok(options)
}

/// A node to read a snapshot from.
#[derive(Clone, Debug, PartialEq)]
struct Node {
    /// What names it in the extract: its identity if known, else its address.
    label: String,
    address: SocketAddr,
}

fn run() -> Result<(), String> {
    let options = options()?;
    fs::create_dir_all(&options.out).map_err(|e| format!("{}: {e}", options.out.display()))?;
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(MAX_DOWNLOAD)
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let (gossip, tip) = match &options.rpc {
        Some(url) => (
            cluster_nodes(&client, url)?,
            Some(cluster_slot(&client, url)?),
        ),
        None => (Vec::new(), None),
    };
    let shred_version = match options.shred_version {
        Some(version) => version,
        None => common_shred_version(&gossip)?,
    };
    let chosen = !options.nodes.is_empty();
    let candidates = if chosen {
        options
            .nodes
            .iter()
            .map(|text| named_node(text, &gossip))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut found = discovered_nodes(&gossip, shred_version);
        shuffle(&mut found);
        println!(
            "{} nodes advertise RPC on shred version {shred_version}; probing for snapshots",
            found.len()
        );
        found
    };

    let mut used: Vec<Node> = Vec::new();
    let mut failed = false;
    // Probe a few at a time, then download from the ones that answered, one
    // after another.
    for batch in candidates.chunks(if chosen { 1 } else { PROBES_AT_ONCE }) {
        let probed: Vec<Result<Snapshot, String>> = thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|node| scope.spawn(|| probe(&client, node)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("probe panicked"))
                .collect()
        });
        for (node, snapshot) in batch.iter().zip(probed) {
            if !chosen && (used.len() >= options.count || used.iter().any(|u| related(u, node))) {
                continue;
            }
            let result = snapshot.and_then(|snapshot| {
                let behind = tip.map_or(0, |tip| tip.saturating_sub(snapshot.slot));
                if behind > options.max_age {
                    return Err(format!(
                        "its snapshot, of slot {}, is {behind} slots behind the cluster",
                        snapshot.slot
                    ));
                }
                read_node(&client, &options, shred_version, node, &snapshot)
            });
            match result {
                Ok(()) => used.push(node.clone()),
                // A node that was named has to work; one that was found may
                // simply not serve snapshots.
                Err(why) if chosen => {
                    eprintln!("node {} ({}): {why}", node.label, node.address);
                    failed = true;
                }
                Err(why) if why != NO_SNAPSHOT => {
                    println!("node {} ({}): skipped: {why}", node.label, node.address)
                }
                Err(_) => {}
            }
        }
        if !chosen && used.len() >= options.count {
            break;
        }
    }
    if failed {
        return Err("not every node named gave an extract".into());
    }
    if !chosen && used.len() < options.count {
        return Err(format!(
            "{} of the {} extracts asked for: no more nodes serve a snapshot",
            used.len(),
            options.count
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Finding nodes
// ---------------------------------------------------------------------------

/// One entry of `getClusterNodes`, as far as this tool reads it.
#[derive(Clone, Debug)]
struct GossipNode {
    identity: String,
    rpc: Option<SocketAddr>,
    shred_version: Option<u16>,
}

/// Calls one JSON-RPC method. Waits and tries again when told to slow down,
/// a few times.
fn rpc(
    client: &reqwest::blocking::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut wait = Duration::from_secs(2);
    for _ in 0..5 {
        let response = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            // The client's error text can repeat the URL, and a URL can hold a key.
            .map_err(|e| format!("{method}: {}", e.without_url()))?;
        let status = response.status().as_u16();
        if matches!(status, 429 | 502 | 503 | 504) {
            thread::sleep(wait);
            wait *= 2;
            continue;
        }
        let mut answer: Value = response
            .json()
            .map_err(|_| format!("{method}: HTTP {status}, and the body is not JSON"))?;
        return match answer.get_mut("result") {
            Some(result) => Ok(result.take()),
            None => Err(format!("{method}: {}", answer["error"])),
        };
    }
    Err(format!("{method}: the endpoint kept asking to slow down"))
}

/// Asks an RPC node who is in the cluster.
fn cluster_nodes(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<GossipNode>, String> {
    let nodes = rpc(client, url, "getClusterNodes", json!([]))?;
    let nodes = nodes.as_array().ok_or("getClusterNodes: not a list")?;
    Ok(nodes
        .iter()
        .filter_map(|node| {
            Some(GossipNode {
                identity: node["pubkey"].as_str()?.to_string(),
                rpc: node["rpc"].as_str().and_then(|a| a.parse().ok()),
                shred_version: node["shredVersion"]
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok()),
            })
        })
        .collect())
}

/// The slot the cluster has finalized, to tell a fresh snapshot from an old one.
fn cluster_slot(client: &reqwest::blocking::Client, url: &str) -> Result<u64, String> {
    rpc(client, url, "getSlot", json!([{"commitment": "finalized"}]))?
        .as_u64()
        .ok_or_else(|| "getSlot: not a number".to_string())
}

/// The shred version most nodes report.
fn common_shred_version(gossip: &[GossipNode]) -> Result<u16, String> {
    let mut counts: BTreeMap<u16, usize> = BTreeMap::new();
    for version in gossip.iter().filter_map(|node| node.shred_version) {
        *counts.entry(version).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(version, _)| version)
        .ok_or_else(|| "getClusterNodes named no shred version; pass --shred-version".to_string())
}

/// An address this tool will connect to when it came from gossip: gossip is
/// written by strangers, and must not be able to point the tool at the
/// machine it runs on or at its local network.
fn public_address(address: &SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                // Carrier-grade NAT, 100.64.0.0/10.
                || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64))
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some())
        }
    }
}

fn discovered_nodes(gossip: &[GossipNode], shred_version: u16) -> Vec<Node> {
    gossip
        .iter()
        .filter(|node| node.shred_version == Some(shred_version))
        .filter_map(|node| {
            let address = node.rpc.filter(public_address)?;
            Some(Node {
                label: node.identity.clone(),
                address,
            })
        })
        .collect()
}

/// A node the operator named, labeled with its identity if gossip knows the
/// address.
fn named_node(text: &str, gossip: &[GossipNode]) -> Result<Node, String> {
    let address: SocketAddr = text
        .parse()
        .map_err(|_| format!("--node {text}: not an address like 192.0.2.1:8899"))?;
    let label = gossip
        .iter()
        .find(|node| node.rpc == Some(address))
        .map_or_else(|| address.to_string(), |node| node.identity.clone());
    Ok(Node { label, address })
}

/// Whether two nodes are likely run by one operator: the same host, or the
/// same /16 (IPv4) or /32 (IPv6) network. Crude, and it errs toward refusing.
fn related(a: &Node, b: &Node) -> bool {
    match (a.address.ip(), b.address.ip()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..2] == b.octets()[..2],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..2] == b.segments()[..2],
        _ => false,
    }
}

/// Puts nodes in an order that differs from run to run, so that repeated
/// runs do not all land on the same few nodes.
fn shuffle(nodes: &mut [Node]) {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    nodes.sort_by_cached_key(|node| {
        solana_sha256_hasher::hashv(&[&nonce.to_le_bytes(), node.label.as_bytes()]).to_bytes()
    });
}

// ---------------------------------------------------------------------------
// Reading one node
// ---------------------------------------------------------------------------

/// The newest incremental snapshot a node offers.
#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    /// The path on the node, as its redirect gave it.
    path: String,
    slot: u64,
    /// The hash in the archive's name, in base58.
    hash: String,
}

const NO_SNAPSHOT: &str = "serves no snapshot";

/// Parses the path a node redirects to. Only a path on the same node that
/// names a zstd-compressed incremental snapshot is accepted.
fn snapshot_from_location(location: &str) -> Option<Snapshot> {
    let name = location.strip_prefix("/incremental-snapshot-")?;
    let name = name.strip_suffix(".tar.zst")?;
    let mut parts = name.split('-');
    let (base, slot, hash) = (parts.next()?, parts.next()?, parts.next()?);
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let base58 = (32..=44).contains(&hash.len()) && hash.bytes().all(|b| b.is_ascii_alphanumeric());
    if parts.next().is_some() || !digits(base) || !digits(slot) || !base58 {
        return None;
    }
    Some(Snapshot {
        path: location.to_string(),
        slot: slot.parse().ok()?,
        hash: hash.to_string(),
    })
}

/// Asks a node, without downloading anything, which snapshot it would send.
fn probe(client: &reqwest::blocking::Client, node: &Node) -> Result<Snapshot, String> {
    let response = client
        .head(format!("http://{}{ENTRY_PATH}", node.address))
        .timeout(Duration::from_secs(8))
        .send()
        .map_err(|_| NO_SNAPSHOT.to_string())?;
    if !response.status().is_redirection() {
        return Err(NO_SNAPSHOT.into());
    }
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .and_then(snapshot_from_location)
        .ok_or_else(|| {
            "its redirect is not to an incremental .tar.zst snapshot of its own".to_string()
        })
}

/// Counts what is read from a download and ends it at a byte or time limit.
struct Capped<R> {
    inner: R,
    read: u64,
    max_bytes: u64,
    deadline: Instant,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.read >= self.max_bytes {
            return Err(io::Error::other("the byte cap was reached"));
        }
        if Instant::now() > self.deadline {
            return Err(io::Error::other("the download took too long"));
        }
        let n = self.inner.read(buffer)?;
        self.read += n as u64;
        Ok(n)
    }
}

/// What the front of an archive held.
#[derive(Debug, PartialEq)]
struct Head {
    /// Contents of the `version` member.
    version: Vec<u8>,
    /// The slot in the bank file's path.
    slot: u64,
    /// Compressed bytes taken from the node.
    compressed_bytes: u64,
}

/// Reads a zstd-compressed snapshot archive from `body` until the bank file
/// (`snapshots/<slot>/<slot>`) has been copied to `bank_out`, and no further.
///
/// Paths in the archive are only compared, never used: the one file written
/// is `bank_out`.
fn read_head(body: impl Read, max_bytes: u64, bank_out: &Path) -> Result<Head, String> {
    let mut capped = Capped {
        inner: body,
        read: 0,
        max_bytes,
        deadline: Instant::now() + MAX_DOWNLOAD,
    };
    let mut version = None;
    let mut slot = None;
    {
        let decoder =
            zstd::stream::read::Decoder::new(&mut capped).map_err(|e| format!("zstd: {e}"))?;
        let mut archive = tar::Archive::new(decoder);
        let entries = archive.entries().map_err(|e| format!("archive: {e}"))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| format!("archive: {e}"))?;
            let path = entry
                .path()
                .map_err(|e| format!("archive: {e}"))?
                .into_owned();
            let parts: Vec<&str> = path.iter().filter_map(|part| part.to_str()).collect();
            let is_file = entry.header().entry_type().is_file();
            match parts[..] {
                ["version"] if is_file => {
                    let mut text = Vec::new();
                    (&mut entry)
                        .take(64)
                        .read_to_end(&mut text)
                        .map_err(|e| format!("archive: {e}"))?;
                    version = Some(text);
                }
                ["snapshots", dir, file]
                    if is_file && dir == file && dir.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    if entry.size() > MAX_BANK_BYTES {
                        return Err(format!("the bank file is {} bytes", entry.size()));
                    }
                    let mut out = BufWriter::new(
                        File::create(bank_out)
                            .map_err(|e| format!("{}: {e}", bank_out.display()))?,
                    );
                    io::copy(&mut entry, &mut out).map_err(|e| format!("bank file: {e}"))?;
                    out.flush()
                        .map_err(|e| format!("{}: {e}", bank_out.display()))?;
                    slot = dir.parse().ok();
                    break;
                }
                // Account files follow the bank file. Seeing one first means
                // the bank file is not where this tool can reach it cheaply.
                ["accounts", ..] => break,
                _ => {}
            }
        }
    }
    let slot = slot.ok_or("no bank file at the front of the archive")?;
    let version = version.ok_or("no version file before the bank file")?;
    Ok(Head {
        version,
        slot,
        compressed_bytes: capped.read,
    })
}

/// The epoch-stakes maps of a bank file, by epoch: every vote account with
/// its stake.
type EpochMaps = BTreeMap<u64, Vec<VoteAccount>>;

/// Parses a bank file with Agave's snapshot code and returns the bank's slot
/// and its epoch-stakes maps, each checked against Agave's own ranking.
///
/// Agave's public entry point for bank fields takes a snapshot archive and
/// nothing smaller, so the bank file is packed into an archive that holds no
/// accounts, under the name a full snapshot of that slot would have.
fn parse_bank(
    work: &Path,
    head: &Head,
    bank: &Path,
    hash: &str,
) -> Result<(u64, EpochMaps), String> {
    let slot = head.slot;
    let archive_path = work.join(format!("snapshot-{slot}-{hash}.tar.zst"));
    let io_error = |e: io::Error| format!("packing the bank file: {e}");
    {
        let file = File::create(&archive_path).map_err(io_error)?;
        let mut archive = tar::Builder::new(zstd::Encoder::new(file, 1).map_err(io_error)?);
        let mut header = tar::Header::new_gnu();
        header.set_size(head.version.len() as u64);
        header.set_mode(0o644);
        archive
            .append_data(&mut header, "version", &head.version[..])
            .map_err(io_error)?;
        archive
            .append_path_with_name(bank, format!("snapshots/{slot}/{slot}"))
            .map_err(io_error)?;
        // Agave links the status cache into place after it has parsed the
        // bank file and fails if there is none. It never reads it on this
        // path, so an empty one stands in for the 15 MB not downloaded.
        header.set_size(0);
        archive
            .append_data(&mut header, "snapshots/status_cache", &[][..])
            .map_err(io_error)?;
        archive
            .into_inner()
            .map_err(io_error)?
            .finish()
            .map_err(io_error)?;
    }
    let (unpack_dir, accounts_dir) = (work.join("unpack"), work.join("accounts"));
    fs::create_dir_all(&unpack_dir).map_err(io_error)?;
    fs::create_dir_all(&accounts_dir).map_err(io_error)?;
    let info = FullSnapshotArchiveInfo::new_from_path(archive_path)
        .map_err(|e| format!("the snapshot's name: {e}"))?;
    let (unarchived, _guard) = snapshot_utils::verify_and_unarchive_snapshots(
        &unpack_dir,
        &info,
        None,
        &[accounts_dir],
        &IoSetupState::default(),
    )
    .map_err(|e| format!("Agave could not read the bank file: {e}"))?;
    let fields = unarchived.bank_fields.collapse_into();

    let mut maps = EpochMaps::new();
    for (epoch, stakes) in fields.versioned_epoch_stakes {
        let stakes = VersionedEpochStakes::from(stakes);
        let mut accounts: Vec<VoteAccount> = stakes
            .stakes()
            .vote_accounts()
            .inner()
            .iter()
            .map(|(vote_pubkey, (stake, account))| {
                let view = account.vote_state_view();
                VoteAccount {
                    vote_pubkey: vote_pubkey.to_bytes(),
                    node_pubkey: view.node_pubkey().to_bytes(),
                    bls_pubkey: view.bls_pubkey_compressed(),
                    stake: *stake,
                }
            })
            .collect();
        accounts.sort_by_key(|account| account.vote_pubkey);

        // The same map ranked by both implementations. Agave's rank map
        // cannot be built for a map that ranks nobody, so that case is
        // decided by this crate alone.
        match ValidatorSet::from_vote_accounts(&accounts) {
            Ok(set) => {
                let ranks = stakes.bls_pubkey_to_rank_map();
                let agave: Option<Vec<Validator>> = (0..ranks.len())
                    .map(|rank| {
                        let entry = ranks.get_pubkey_stake_entry(rank)?;
                        let vote = entry.vote_account_pubkey.to_bytes();
                        let account = accounts.iter().find(|a| a.vote_pubkey == vote)?;
                        Some(Validator {
                            bls_pubkey: account.bls_pubkey?,
                            stake: entry.stake.get(),
                        })
                    })
                    .collect();
                if agave.as_deref() != Some(set.validators()) {
                    return Err(format!(
                        "epoch {epoch}: Agave ranks the map differently from solana-thin"
                    ));
                }
            }
            Err(ThinError::EmptyValidatorSet) => {}
            Err(e) => return Err(format!("epoch {epoch}: {e}")),
        }
        maps.insert(epoch, accounts);
    }
    Ok((fields.slot, maps))
}

fn extract_json(
    cluster: &str,
    shred_version: u16,
    node: &Node,
    slot: u64,
    maps: &EpochMaps,
) -> Value {
    let epochs: Vec<Value> = maps
        .iter()
        .map(|(epoch, accounts)| {
            let accounts: Vec<Value> = accounts
                .iter()
                .map(|account| {
                    json!({
                        "vote_pubkey": hex::encode(account.vote_pubkey),
                        "node_pubkey": hex::encode(account.node_pubkey),
                        "bls_pubkey": account.bls_pubkey.map(hex::encode),
                        "stake": account.stake,
                    })
                })
                .collect();
            json!({"epoch": epoch, "accounts": accounts})
        })
        .collect();
    json!({
        "format": EXTRACT_FORMAT,
        "cluster": cluster,
        "shred_version": shred_version,
        "node": node.label,
        "slot": slot,
        "epochs": epochs,
    })
}

/// Downloads the head of `snapshot` from `node`, parses it and writes the
/// extract.
fn read_node(
    client: &reqwest::blocking::Client,
    options: &Options,
    shred_version: u16,
    node: &Node,
    snapshot: &Snapshot,
) -> Result<(), String> {
    let work = tempfile::Builder::new()
        .prefix("snapshot-stakes-")
        .tempdir_in(&options.out)
        .map_err(|e| format!("{}: {e}", options.out.display()))?;
    let bank = work.path().join("bank");
    let started = Instant::now();
    let response = client
        .get(format!("http://{}{}", node.address, snapshot.path))
        .send()
        .map_err(|e| format!("download: {}", e.without_url()))?;
    if response.status().as_u16() != 200 {
        return Err(format!("download: HTTP {}", response.status().as_u16()));
    }
    let head = read_head(response, options.max_bytes, &bank)?;
    let took = started.elapsed();
    if head.slot != snapshot.slot {
        return Err(format!(
            "the archive is named for slot {} and holds the bank of slot {}",
            snapshot.slot, head.slot
        ));
    }
    let (slot, maps) = parse_bank(work.path(), &head, &bank, &snapshot.hash)?;
    if slot != snapshot.slot {
        return Err(format!(
            "the bank file says slot {slot}, its path slot {}",
            snapshot.slot
        ));
    }

    let file_label: String = node
        .label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = options
        .out
        .join(format!("{}-{slot}-{file_label}.json", options.cluster));
    let document = extract_json(&options.cluster, shred_version, node, slot, &maps);
    fs::write(&path, document.to_string()).map_err(|e| format!("{}: {e}", path.display()))?;

    println!(
        "node {} ({}): slot {slot}, bank file complete after {:.1} MB in {:.1} s",
        node.label,
        node.address,
        head.compressed_bytes as f64 / 1e6,
        took.as_secs_f64()
    );
    for (epoch, accounts) in &maps {
        match ValidatorSet::from_vote_accounts(accounts) {
            Ok(set) => println!(
                "  epoch {epoch}: {} of {} vote accounts ranked, as Agave ranks them; set hash {}",
                set.len(),
                accounts.len(),
                hex::encode(set.hash())
            ),
            Err(_) => println!(
                "  epoch {epoch}: {} vote accounts, none ranked",
                accounts.len()
            ),
        }
    }
    println!("  wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes that do not compress, so that sizes in the archive are sizes on
    /// the wire.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// A snapshot archive as a node sends it: members in `members` order,
    /// compressed as several zstd frames.
    fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in members {
            let mut header = tar::Header::new_gnu();
            if name.ends_with('/') {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_size(0);
                header.set_mode(0o755);
                tar.append_data(&mut header, name, &[][..]).unwrap();
            } else {
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                tar.append_data(&mut header, name, *data).unwrap();
            }
        }
        let tar = tar.into_inner().unwrap();
        tar.chunks(tar.len() / 3 + 1)
            .flat_map(|frame| zstd::encode_all(frame, 1).unwrap())
            .collect()
    }

    fn bank_path(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        (dir, path)
    }

    #[test]
    fn reading_stops_when_the_bank_file_is_complete() {
        let bank = noise(300_000, 1);
        let accounts = noise(4_000_000, 2);
        let bytes = archive(&[
            ("version", b"1.2.0"),
            ("snapshots/", b""),
            ("snapshots/77/", b""),
            ("snapshots/77/77", &bank),
            ("snapshots/status_cache", &noise(50_000, 3)),
            ("accounts/77.1", &accounts),
        ]);
        let (_dir, out) = bank_path("bank");
        let head = read_head(&bytes[..], u64::MAX, &out).unwrap();
        assert_eq!(head.version, b"1.2.0");
        assert_eq!(head.slot, 77);
        assert_eq!(fs::read(&out).unwrap(), bank);
        // The account file, most of the archive, was never asked for.
        assert!(head.compressed_bytes >= 300_000);
        assert!(head.compressed_bytes < 800_000, "{}", head.compressed_bytes);
        assert!(bytes.len() > 4_000_000);
    }

    #[test]
    fn the_byte_cap_ends_a_download() {
        let bytes = archive(&[
            ("version", b"1.2.0"),
            ("snapshots/77/77", &noise(900_000, 1)),
        ]);
        let (_dir, out) = bank_path("bank");
        let error = read_head(&bytes[..], 200_000, &out).unwrap_err();
        assert!(error.contains("the byte cap was reached"), "{error}");
        assert!(read_head(&bytes[..], 2_000_000, &out).is_ok());
    }

    #[test]
    fn an_archive_without_a_bank_file_up_front_is_refused() {
        let (_dir, out) = bank_path("bank");
        let cases: [&[(&str, &[u8])]; 5] = [
            &[
                ("version", b"1.2.0"),
                ("accounts/77.1", b"x"),
                ("snapshots/77/77", b"bank"),
            ],
            &[("version", b"1.2.0"), ("snapshots/status_cache", b"x")],
            // Not a bank file: the two numbers differ, or are not numbers.
            &[("version", b"1.2.0"), ("snapshots/77/78", b"bank")],
            &[("version", b"1.2.0"), ("snapshots/x/x", b"bank")],
            &[("version", b"1.2.0"), ("other/snapshots/77/77", b"bank")],
        ];
        for members in cases {
            assert_eq!(
                read_head(&archive(members)[..], u64::MAX, &out),
                Err("no bank file at the front of the archive".into())
            );
            assert!(!out.exists());
        }
        let no_version = archive(&[("snapshots/77/77", b"bank")]);
        assert_eq!(
            read_head(&no_version[..], u64::MAX, &out),
            Err("no version file before the bank file".into())
        );
        assert!(read_head(&b"not zstd at all"[..], u64::MAX, &out).is_err());
    }

    #[test]
    fn only_a_nodes_own_incremental_zstd_snapshot_is_followed() {
        let hash = "FTH94m6BqgpmHUqYpa3Cv3YBvUt58NUHfsHVFwErLCvw";
        let good = format!("/incremental-snapshot-473786941-473835192-{hash}.tar.zst");
        assert_eq!(
            snapshot_from_location(&good),
            Some(Snapshot {
                path: good.clone(),
                slot: 473835192,
                hash: hash.into()
            })
        );
        for bad in [
            format!("http://elsewhere.example{good}"),
            format!("//elsewhere.example{good}"),
            good.replace(".tar.zst", ".tar.bz2"),
            good.replace("/incremental-snapshot-", "/snapshot-"),
            good.replace("473835192", "47383x192"),
            good.replace(hash, "../../etc/passwd"),
            good.replace(hash, "short"),
            format!("{good}?x=1"),
            good.replace("-473835192", ""),
            String::new(),
        ] {
            assert_eq!(snapshot_from_location(&bad), None, "{bad}");
        }
    }

    fn node(address: &str) -> Node {
        Node {
            label: address.into(),
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn nodes_on_one_network_count_as_related() {
        assert!(related(&node("192.0.2.1:8899"), &node("192.0.2.1:80")));
        assert!(related(&node("192.0.2.1:8899"), &node("192.0.77.9:8899")));
        assert!(!related(&node("192.0.2.1:8899"), &node("192.1.2.1:8899")));
        assert!(related(
            &node("[2001:db8::1]:8899"),
            &node("[2001:db8:5::1]:8899")
        ));
        assert!(!related(
            &node("[2001:db8::1]:8899"),
            &node("192.0.2.1:8899")
        ));
    }

    #[test]
    fn gossip_cannot_point_the_tool_at_a_local_address() {
        for local in [
            "127.0.0.1:8899",
            "10.1.2.3:8899",
            "192.168.1.1:80",
            "172.16.0.1:80",
            "169.254.169.254:80",
            "100.64.0.1:80",
            "0.0.0.0:80",
            "[::1]:80",
            "[fd00::1]:80",
            "[fe80::1]:80",
            "[::ffff:127.0.0.1]:80",
        ] {
            assert!(!public_address(&local.parse().unwrap()), "{local}");
        }
        assert!(public_address(&"8.8.8.8:8899".parse().unwrap()));
        assert!(public_address(&"[2606:4700::1]:8899".parse().unwrap()));

        let gossip = [
            GossipNode {
                identity: "a".into(),
                rpc: "8.8.8.8:8899".parse().ok(),
                shred_version: Some(7),
            },
            GossipNode {
                identity: "b".into(),
                rpc: "10.0.0.1:8899".parse().ok(),
                shred_version: Some(7),
            },
            GossipNode {
                identity: "c".into(),
                rpc: None,
                shred_version: Some(7),
            },
            GossipNode {
                identity: "d".into(),
                rpc: "8.8.4.4:8899".parse().ok(),
                shred_version: Some(8),
            },
        ];
        assert_eq!(common_shred_version(&gossip), Ok(7));
        assert!(common_shred_version(&[]).is_err());
        let found = discovered_nodes(&gossip, 7);
        assert_eq!(
            found,
            [Node {
                label: "a".into(),
                address: "8.8.8.8:8899".parse().unwrap()
            }]
        );
        // A node named by the operator takes its label from gossip if listed.
        assert_eq!(named_node("8.8.8.8:8899", &gossip).unwrap().label, "a");
        assert_eq!(
            named_node("192.0.2.1:8899", &gossip).unwrap().label,
            "192.0.2.1:8899"
        );
        assert!(named_node("example.com", &gossip).is_err());
    }
}
