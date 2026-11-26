//! `prover`: fetch finalized blocks from validators and prove that
//! transactions are in them.
//!
//! See `docs/PROVER.md` for what it trusts, what it costs and what it is
//! not.

mod args;

use args::Args;
use solana_thin::{Finality, FinalityCert, TxProof};
use solana_thin_prover::fetch::{FetchConfig, Fetcher};
use solana_thin_prover::peers::{common_shred_version, PeerBook};
use solana_thin_prover::prove::{HeldBlock, Prover, ProverConfig};
use solana_thin_prover::rpc::Node;
use solana_thin_prover::serve::{serve, ServeConfig, SlotHints};
use solana_thin_prover::{Net, Refusal, Schedule, Store, Trust};
use solana_thin_setlog::{parse, signer_key_from_hex, verify, SetFile};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

const USAGE: &str = "\
prover: fetch finalized Solana blocks from validators and prove transactions

  prover fetch <options> [--prove-all] <slot> ...
      Fetch each slot's finalized block by its certified id and keep it.
      With --prove-all, also build and verify a proof for every transaction.
  prover prove <options> [--slot <N>] [--out <file>] <signature>
      Write a verified proof that the transaction is in a finalized block.
      Without --slot, the RPC node is asked where it landed.
  prover serve <options> --listen <addr> [--workers <N>]
      Serve GET /proof/<signature>, /finality/<slot>, /set/<epoch>, /health.

Options:
  --rpc <url>              an RPC node of the cluster: it lists the validators
                           and hints at slots, and is trusted for neither
  --set <file>             the validator set to verify an epoch with; repeat
                           for each epoch. Around an epoch boundary, both.
  --log <file>             take each set's hash from this set log, checked with
  --signer <hex key> ...     these signer keys, of which
  --threshold <N>            this many must have signed. Without a log, each
                           set file is pinned by its own hash.
  --shred-version <N>      refuse to start unless the set files are for this
                           shred version (they name it themselves)
  --slots-per-epoch <N>    for a cluster that is not mainnet-beta, testnet or
  --warmup                   devnet: its epoch length, and whether it began
                             with warm-up epochs
  --store <dir>            where blocks and proofs are kept (default prover-store)
  --store-cap-mb <N>       how large that may grow (default 1024)
  --rate <N>               requests a second to validators (default 300)
  --bind <addr>            the UDP address to ask from (default 0.0.0.0:0)

Needs `curl` on the path, for the RPC node.";

const OPTIONS: &[&str] = &[
    "rpc",
    "set",
    "log",
    "signer",
    "threshold",
    "shred-version",
    "slots-per-epoch",
    "store",
    "store-cap-mb",
    "rate",
    "bind",
    "slot",
    "out",
    "listen",
    "workers",
];
const SWITCHES: &[&str] = &["warmup", "prove-all"];

type Outcome = Result<(), String>;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let run: fn(&Args) -> Outcome = match command.as_str() {
        "fetch" => fetch,
        "prove" => prove,
        "serve" => run_server,
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match Args::parse(args, OPTIONS, SWITCHES).and_then(|args| run(&args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("prover {command}: {why}");
            ExitCode::FAILURE
        }
    }
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// What the prover verifies with, from the set files and the log.
fn trust(args: &Args) -> Result<Trust, String> {
    let paths = args.all("set");
    if paths.is_empty() {
        return Err("--set is required: the set file of each epoch to verify with".into());
    }
    let files = paths
        .iter()
        .map(|path| SetFile::from_json(&read(path)?).map_err(|e| format!("{path}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let log = match args.optional("log")? {
        Some(path) => {
            let signers = args
                .all("signer")
                .iter()
                .map(|key| signer_key_from_hex(key).map_err(|e| format!("--signer {key}: {e}")))
                .collect::<Result<Vec<_>, _>>()?;
            let threshold = args
                .number("threshold")?
                .ok_or("--log needs --signer keys and a --threshold")?;
            let records = parse(&read(path)?).map_err(|e| format!("{path}: {e}"))?;
            Some(verify(&records, &signers, threshold).map_err(|e| format!("{path}: {e}"))?)
        }
        None if !args.all("signer").is_empty() || args.optional("threshold")?.is_some() => {
            return Err("--signer and --threshold are for checking a --log".into())
        }
        None => None,
    };
    let schedule = match (args.number("slots-per-epoch")?, args.has("warmup")) {
        (None, false) => Schedule::Known,
        (None, true) => return Err("--warmup needs --slots-per-epoch".into()),
        (Some(slots), false) => Schedule::Flat(slots),
        (Some(slots), true) => Schedule::Warmup(slots),
    };
    let trust = Trust::new(files, log.as_ref(), schedule)?;
    if let Some(expected) = args.number::<u16>("shred-version")? {
        if expected != trust.shred_version() {
            return Err(format!(
                "the set files are for shred version {}, not {expected}",
                trust.shred_version()
            ));
        }
    }
    for epoch in trust.epochs() {
        let file = trust.set_file(epoch).expect("an epoch that is pinned");
        eprintln!(
            "prover: epoch {epoch} of {}: {} validators, set hash {}, pinned from {}",
            trust.cluster(),
            file.validators(),
            hex::encode(file.set_hash()),
            if log.is_some() {
                "the log"
            } else {
                "the set file itself"
            }
        );
    }
    Ok(trust)
}

/// The validators that can be asked, as `node` lists them now.
fn peers(node: &Node, trust: &Trust) -> Result<PeerBook, String> {
    let nodes = node.cluster_nodes()?;
    let reported =
        common_shred_version(&nodes).ok_or("the RPC node lists no nodes with a shred version")?;
    if reported != trust.shred_version() {
        return Err(format!(
            "the cluster's nodes are on shred version {reported} and the pinned sets are for \
             {}: the cluster restarted, or this is another one",
            trust.shred_version()
        ));
    }
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).map_err(|e| format!("no randomness from the system: {e}"))?;
    let (book, census) = PeerBook::from_cluster_nodes(&nodes, reported, u64::from_le_bytes(seed));
    eprintln!(
        "prover: {} of {} nodes can be asked ({} on another shred version, {} without a repair \
         address, {} on a release that does not answer, {} unusable)",
        census.kept,
        census.listed,
        census.other_shred_version,
        census.no_repair_address,
        census.old_release,
        census.unusable
    );
    if book.is_empty() {
        return Err("the RPC node lists no validator that can be asked".into());
    }
    Ok(book)
}

/// Everything the three commands share.
fn setup(args: &Args) -> Result<(Prover, Node, Arc<Trust>), String> {
    let trust = Arc::new(trust(args)?);
    let node = Node::new(args.required("rpc")?)?;
    let book = peers(&node, &trust)?;
    // The schedule decides which set a certificate is checked against. A
    // node that reports another one means the wrong flags, not a proof.
    match node.epoch_schedule() {
        Ok(reported) => {
            let ours = trust.client().params();
            if (
                reported.slots_per_epoch,
                reported.first_normal_epoch,
                reported.first_normal_slot,
            ) != (
                ours.slots_per_epoch,
                ours.first_normal_epoch,
                ours.first_normal_slot,
            ) {
                return Err(format!(
                    "the RPC node reports epochs of {} slots, full length from epoch {} at slot \
                     {}; that is not the schedule configured (see --slots-per-epoch, --warmup)",
                    reported.slots_per_epoch,
                    reported.first_normal_epoch,
                    reported.first_normal_slot
                ));
            }
        }
        Err(why) => eprintln!("prover: the epoch schedule was not checked: {why}"),
    }
    let rate: u32 = args.number("rate")?.unwrap_or(300);
    if !(1..=1_000).contains(&rate) {
        return Err("--rate is between 1 and 1000 requests a second".into());
    }
    let bind: SocketAddr = args
        .optional("bind")?
        .unwrap_or("0.0.0.0:0")
        .parse()
        .map_err(|_| "--bind is an address and a port")?;
    let net = Net::open(bind, rate).map_err(|e| format!("{bind}: {e}"))?;
    let dir = args.optional("store")?.unwrap_or("prover-store");
    let cap: u64 = args.number("store-cap-mb")?.unwrap_or(1_024);
    let store = Store::open(Path::new(dir), cap.saturating_mul(1 << 20))
        .map_err(|e| format!("{dir}: {e}"))?;
    let prover = Prover::new(
        Arc::clone(&trust),
        Arc::new(store),
        Fetcher::new(net, book, FetchConfig::default()),
        ProverConfig::default(),
    );
    Ok((prover, node, trust))
}

fn kind(certificate: &FinalityCert) -> &'static str {
    match certificate {
        FinalityCert::Fast { .. } => "fast",
        FinalityCert::Slow { .. } => "slow",
        _ => "unknown",
    }
}

fn describe(held: &HeldBlock) -> String {
    let certificate = &held.anchor.certificate;
    let mut said = format!(
        "block {}, {} certificate for slot {}",
        hex::encode(held.block.id),
        kind(certificate),
        certificate.block().slot
    );
    if let Some(found_in) = held.found_in {
        said += &format!(" from the footer of slot {found_in}");
    }
    if !held.anchor.links.is_empty() {
        said += &format!(", {} parent links down", held.anchor.links.len());
    }
    match &held.fetch {
        Some(stats) => {
            said += &format!(
                "; {} shreds from {} holders in {} requests and {:.2} s, {} retried, {} refused, \
                 {} duplicated",
                held.shreds,
                stats.holders,
                stats.requests,
                stats.elapsed.as_secs_f64(),
                stats.retries,
                stats.rejected,
                stats.duplicates
            )
        }
        None => said += &format!("; {} shreds already held", held.shreds),
    }
    said + &format!("; {} transactions", held.signatures.len())
}

fn fetch(args: &Args) -> Outcome {
    let slots = args
        .positional()
        .iter()
        .map(|slot| {
            slot.parse::<u64>()
                .map_err(|_| format!("{slot}: not a slot"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if slots.is_empty() {
        return Err("give at least one slot".into());
    }
    let (mut prover, _, _) = setup(args)?;
    let (mut fetched, mut refused) = (0, 0);
    let (mut transactions, mut proven) = (0, 0);
    for slot in slots {
        let held = match prover.fetch(slot) {
            Ok(held) => held,
            Err(refusal) => {
                println!("slot {slot}: refused: {refusal}");
                refused += 1;
                // Peers that have gone quiet are not asked about the rest.
                if matches!(refusal, Refusal::PeersSilent { .. }) {
                    break;
                }
                continue;
            }
        };
        fetched += 1;
        let mut line = format!("slot {slot}: {}", describe(&held));
        if args.has("prove-all") {
            let all = prover
                .prove_all(slot)
                .map_err(|refusal| format!("slot {slot}: {refusal}"))?;
            transactions += held.signatures.len();
            proven += all.proof_sizes.len();
            line += &format!(", {} proven and verified", all.proof_sizes.len());
            if let (Some(least), Some(most)) =
                (all.proof_sizes.iter().min(), all.proof_sizes.iter().max())
            {
                line += &format!(" (proofs of {least} to {most} bytes)");
            }
            for (signature, refusal) in &all.failures {
                line += &format!(
                    "\nslot {slot}: transaction {} not proven: {refusal}",
                    bs58::encode(signature).into_string()
                );
            }
        }
        println!("{line}");
    }
    let stats = prover.fetcher().net_stats();
    println!(
        "{fetched} blocks fetched by certified id, {refused} slots refused; {} requests and {} \
         bytes sent, {} bytes received, {} peers answered",
        stats.requests,
        stats.bytes_sent,
        stats.bytes_received,
        prover.fetcher().peers().answering()
    );
    if args.has("prove-all") {
        println!("{proven} of {transactions} transactions proven and verified");
    }
    if refused > 0 || proven < transactions {
        return Err("not everything asked for was done".into());
    }
    Ok(())
}

fn signature_of(text: &str) -> Result<[u8; 64], String> {
    bs58::decode(text)
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{text}: not a transaction signature (64 bytes in base58)"))
}

fn prove(args: &Args) -> Outcome {
    let [text] = args.positional() else {
        return Err("give one transaction signature".into());
    };
    let signature = signature_of(text)?;
    let (mut prover, node, trust) = setup(args)?;
    let slot = match args.number("slot")? {
        Some(slot) => slot,
        None => {
            let slot = node
                .slot_of(&signature)?
                .ok_or("the RPC node does not know this transaction; give its --slot")?;
            eprintln!("prover: {} says slot {slot}", node.label());
            slot
        }
    };
    let proof = prover
        .prove(&signature, slot)
        .map_err(|refusal| refusal.to_string())?;
    let default = format!("{text}.proof");
    let out = args.optional("out")?.unwrap_or(&default);
    std::fs::write(out, &proof).map_err(|e| format!("{out}: {e}"))?;
    // Already verified; read again for what to tell the operator.
    let client = trust.client();
    let verified = TxProof::from_bytes(&proof, client.limits())
        .and_then(|proof| client.verify_signature(&proof, &signature))
        .map_err(|e| e.to_string())?;
    let how = match verified.finalized_by.finality {
        Finality::Fast => "fast",
        Finality::Slow => "slow",
        _ => "unknown",
    };
    println!(
        "{text} is in block {} of slot {}, final by a {how} certificate for slot {}; proof of \
         {} bytes written to {out}",
        hex::encode(verified.block.id),
        verified.block.slot,
        verified.finalized_by.block.slot,
        proof.len()
    );
    Ok(())
}

fn run_server(args: &Args) -> Outcome {
    let listen = args.required("listen")?;
    let mut config = ServeConfig::default();
    if let Some(workers) = args.number::<usize>("workers")? {
        if !(1..=256).contains(&workers) {
            return Err("--workers is between 1 and 256".into());
        }
        config.workers = workers;
    }
    let (prover, node, trust) = setup(args)?;
    let listener = TcpListener::bind(listen).map_err(|e| format!("{listen}: {e}"))?;
    let refresh = {
        let (node, trust) = (node.clone(), Arc::clone(&trust));
        Box::new(move || peers(&node, &trust))
    };
    let server = serve(listener, prover, Arc::new(node), Some(refresh), config)
        .map_err(|e| format!("{listen}: {e}"))?;
    eprintln!("prover: listening on http://{}", server.addr());
    server.wait();
    Ok(())
}
