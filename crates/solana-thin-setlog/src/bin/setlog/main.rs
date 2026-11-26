//! `setlog`: produce, sign, extend and check a log of validator-set hashes.
//!
//! See `docs/SETS.md` for the procedure and for what each step is worth.

mod admission;
mod args;
mod sources;

use args::Args;
use solana_thin::ValidatorSet;
use solana_thin_setlog::rpc;
use solana_thin_setlog::{
    agree, check_links, parse, signer_key_from_hex, to_text, verify, Error, SetFile, SignedRecord,
    SignerKey, SigningKey, Source, KIND_ADMISSION,
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

/// The environment variable the signing key is read from: 64 hex digits.
const KEY_VARIABLE: &str = "SETLOG_SIGNING_KEY";

/// The node the admission debits are read from.
const ADMISSION_URL: &str = "admission-url";
/// Skips the admission check, and leaves it out of the record.
const NO_ADMISSION_CHECK: &str = "no-admission-check";

const USAGE: &str = "\
setlog: a signed, hash-chained log of Solana validator-set hashes

Reading a set and checking that sources agree:
  setlog from-rank-map --cluster <name> --epoch <E> --url <rpc> [--url <rpc> ...]
                       --quorum <N> --set <out> --record <out> [--log <log>]
                       [--admission-url <rpc> | --no-admission-check]
  setlog agree --epoch <E> --quorum <N> --set <out> --record <out> [--log <log>]
               (--admission-url <rpc> | --no-admission-check)
               <set file or snapshot extract> ...

  Both print the set hash each source gives, and check the vote accounts
  each source names against those charged the admission ticket in the first
  block of epoch E - 1, read from --admission-url (for from-rank-map, the
  first --url if not given). Only if every source gives the same set, every
  source's accounts match, and at least N distinct sources agree, they write
  the set file and a record for it: unsigned, and linked to the end of <log>
  if one is given. --no-admission-check skips the check, and the record then
  does not claim it.

Signing and publishing:
  setlog keygen                      print a new signing key; its public half
                                     goes to standard error
  setlog pubkey                      print the public half of $SETLOG_SIGNING_KEY
  setlog sign --record <file> --set <file>
                                     add a signature to a record, if the set
                                     file you produced says what it says
  setlog append --log <log> --record <file>
                                     add a signed record to the end of a log

Checking:
  setlog verify --log <log> --signer <hex key> [--signer ...] --threshold <N>
                                     check every signature and link, and print
                                     the hash to pin for each epoch
  setlog show <log, record or set file>
                                     print what a file holds, verified or not

The signing key is read from the environment variable SETLOG_SIGNING_KEY and
from nowhere else.";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let result = match command.as_str() {
        "from-rank-map" => from_rank_map(args),
        "agree" => agree_inputs(args),
        "keygen" => keygen(args),
        "pubkey" => pubkey(args),
        "sign" => sign(args),
        "append" => append(args),
        "verify" => verify_log(args),
        "show" => show(args),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("setlog {command}: {why}");
            ExitCode::FAILURE
        }
    }
}

type Outcome = Result<(), String>;

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// Writes a file that must not exist yet, so that a record someone has
/// signed is never written over by a new candidate.
fn write_new(path: &str, text: &str) -> Outcome {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    file.write_all(text.as_bytes())
        .map_err(|e| format!("{path}: {e}"))
}

/// Replaces a file in one step, so that a reader never sees half of it.
fn replace(path: &str, text: &str) -> Outcome {
    let part = format!("{path}.part");
    fs::write(&part, text).map_err(|e| format!("{part}: {e}"))?;
    fs::rename(&part, path).map_err(|e| format!("{path}: {e}"))
}

/// Says which line of which file an error is about. Lines count from one.
fn in_file(path: &str, error: Error) -> String {
    let (Error::InvalidRecord { index, .. }
    | Error::InvalidSignature { index }
    | Error::TooFewSignatures { index, .. }
    | Error::BrokenLink { index }
    | Error::ClusterChanged { index }
    | Error::EpochWentBackward { index }
    | Error::ConflictingSet { index, .. }) = error
    else {
        return format!("{path}: {error}");
    };
    // The library counts records from zero; a person opens the file at a line.
    let text = error.to_string();
    let what = text
        .strip_prefix(&format!("record {index}: "))
        .unwrap_or(&text);
    format!("{path}, line {}: {what}", index + 1)
}

fn read_log(path: &str) -> Result<Vec<SignedRecord>, String> {
    parse(&read(path)?).map_err(|e| in_file(path, e))
}

/// A record file is a log of one line.
fn read_record(path: &str) -> Result<SignedRecord, String> {
    let mut records = read_log(path)?;
    match (records.pop(), records.is_empty()) {
        (Some(record), true) => Ok(record),
        _ => Err(format!("{path}: expected one record")),
    }
}

fn read_set(path: &str) -> Result<SetFile, String> {
    SetFile::from_json(&read(path)?).map_err(|e| format!("{path}: {e}"))
}

fn describe(file: &SetFile) -> String {
    format!(
        "{} ({} validators)",
        hex::encode(file.set_hash()),
        file.validators()
    )
}

/// The node to read the admission debits from, or `None` if the check is
/// skipped. The check is on unless skipped by name.
fn admission_url<'a>(args: &'a Args, default: Option<&'a str>) -> Result<Option<&'a str>, String> {
    let given = args.optional(ADMISSION_URL)?;
    if args.switch(NO_ADMISSION_CHECK) {
        return match given {
            Some(_) => Err("give --admission-url or --no-admission-check, not both".into()),
            None => Ok(None),
        };
    }
    let url = given
        .or(default)
        .ok_or("--admission-url is required, or --no-admission-check to skip the check")?;
    rpc::host_label(url)?;
    Ok(Some(url))
}

fn fetch_debits(rpc: &rpc::Rpc, url: &str, epoch: u64) -> Result<admission::Debits, String> {
    let host = rpc::host_label(url)?;
    let debits = admission::fetch(rpc, url, epoch)
        .map_err(|e| format!("no admission debits from {host}: {e}"))?;
    println!(
        "admission: the block at slot {} debited {} vote accounts, from {host}; \
         it is the first of epoch {}",
        debits.slot,
        debits.accounts.len(),
        epoch - 1
    );
    Ok(debits)
}

fn from_rank_map(args: impl Iterator<Item = String>) -> Outcome {
    let args = Args::parse_with_switches(
        args,
        &[
            "cluster",
            "epoch",
            "url",
            "quorum",
            "set",
            "record",
            "log",
            ADMISSION_URL,
        ],
        &[NO_ADMISSION_CHECK],
    )?;
    args.no_positional()?;
    let cluster = args.required("cluster")?;
    let epoch: u64 = args.number("epoch")?;
    let urls = args.all("url");
    if urls.is_empty() {
        return Err("--url is required".into());
    }
    let admission_url = admission_url(&args, urls.first().map(String::as_str))?;
    let curl = rpc::Curl::new("setlog");
    let rpc = rpc::Rpc::polite(&curl);
    let mut readings = Vec::new();
    for url in urls {
        // Only the host is ever printed: the rest of a URL can hold a key.
        let label = rpc::host_label(url)?;
        match sources::set_file_from_rank_map(&rpc, url, cluster, epoch) {
            Ok(reading) => {
                println!(
                    "rank-map {label} at slot {}: {}",
                    reading.file.sources()[0].slot(),
                    describe(&reading.file)
                );
                readings.push((label, reading));
            }
            // A node that cannot answer is not a node that disagrees.
            Err(why) => println!("rank-map {label}: no answer: {why}"),
        }
    }
    let inputs = readings.iter().map(|(_, r)| r.file.clone()).collect();
    conclude(&args, inputs, || {
        let Some(url) = admission_url else {
            return Ok(None);
        };
        let debits = fetch_debits(&rpc, url, epoch)?;
        for (label, reading) in &readings {
            let left_out = admission::check_rank_map(&debits, &reading.ranked, |accounts| {
                admission::keys_now(&rpc, url, accounts)
            })
            .map_err(|e| format!("rank-map {label}: {e}"))?;
            let ranked = reading.ranked.len();
            if left_out == 0 {
                println!("admission: rank-map {label} ranks the {ranked} accounts debited");
            } else {
                println!(
                    "admission: rank-map {label}: its {ranked} ranked accounts were all debited; \
                     the {left_out} debited accounts it does not rank share a BLS key or node \
                     identity, by their vote accounts now"
                );
            }
        }
        Ok(Some(debits.source()))
    })
}

fn agree_inputs(args: impl Iterator<Item = String>) -> Outcome {
    let args = Args::parse_with_switches(
        args,
        &["epoch", "quorum", "set", "record", "log", ADMISSION_URL],
        &[NO_ADMISSION_CHECK],
    )?;
    let epoch: u64 = args.number("epoch")?;
    let admission_url = admission_url(&args, None)?;
    let mut inputs = Vec::new();
    for path in args.positional() {
        let input = sources::set_file_from_input(&read(path)?, epoch)
            .map_err(|why| format!("{path}: {why}"))?;
        for source in input.file.sources() {
            if source.kind() == KIND_ADMISSION {
                continue;
            }
            println!(
                "{} {} at slot {}: {}",
                source.kind(),
                source.label(),
                source.slot(),
                describe(&input.file)
            );
        }
        inputs.push((path, input));
    }
    let files = inputs.iter().map(|(_, input)| input.file.clone()).collect();
    conclude(&args, files, || {
        let Some(url) = admission_url else {
            return Ok(None);
        };
        let curl = rpc::Curl::new("setlog");
        let debits = fetch_debits(&rpc::Rpc::polite(&curl), url, epoch)?;
        // Every input is the same set by now, so one input whose accounts
        // match is enough; every input that names accounts must match.
        let mut checked = 0;
        for (path, input) in &inputs {
            if let Some(members) = &input.members {
                admission::check_map(&debits, members).map_err(|e| format!("{path}: {e}"))?;
                println!(
                    "admission: {path}: its {} vote accounts are the ones debited",
                    members.len()
                );
                checked += 1;
                continue;
            }
            let carried = input
                .file
                .sources()
                .iter()
                .find(|s| s.kind() == KIND_ADMISSION);
            match carried {
                Some(source) if source.slot() == debits.slot => {
                    println!("admission: {path}: a set file checked against this block");
                    checked += 1;
                }
                Some(source) => {
                    return Err(format!(
                        "{path}: a set file checked against the block at slot {}, not {}",
                        source.slot(),
                        debits.slot
                    ))
                }
                None => println!(
                    "admission: {path}: a set file, which names no vote accounts to compare"
                ),
            }
        }
        if checked == 0 {
            return Err(
                "no input lists the vote accounts to compare with the debits: a set \
                        file holds keys, not accounts. Add a snapshot extract or a set file \
                        made with the check, or pass --no-admission-check"
                    .into(),
            );
        }
        Ok(Some(debits.source()))
    })
}

/// The common end of `from-rank-map` and `agree`: refuse unless the sources
/// agree and `admission` passes, then write the set file and the candidate
/// record. `admission` checks the members and returns the source that says
/// so, or `None` if the check was skipped.
fn conclude(
    args: &Args,
    inputs: Vec<SetFile>,
    admission: impl FnOnce() -> Result<Option<Source>, String>,
) -> Outcome {
    let quorum: usize = args.number("quorum")?;
    let (set_path, record_path) = (args.required("set")?, args.required("record")?);
    // Before anything is written, so that it is both files or neither.
    for path in [set_path, record_path] {
        if Path::new(path).exists() {
            return Err(format!("nothing written: {path} already exists"));
        }
    }
    let agreed = agree(&inputs, quorum).map_err(|e| format!("nothing written: {e}"))?;
    // The verifier's full check of the bytes: every key, and the rank order.
    let set = ValidatorSet::from_bytes(agreed.set_bytes())
        .map_err(|e| format!("nothing written: the set is not one the verifier accepts: {e}"))?;

    let mut log = match args.optional("log")? {
        Some(path) if Path::new(path).exists() => read_log(path)?,
        _ => Vec::new(),
    };
    let prev = if log.is_empty() {
        [0; 32]
    } else {
        check_links(&log).map_err(|e| format!("the log does not hold together: {e}"))?
    };

    let checked = admission().map_err(|e| format!("nothing written: {e}"))?;
    if checked.is_none() {
        println!("admission: not checked (--{NO_ADMISSION_CHECK}); the record will not claim it");
    }
    // The record says what this run checked: a check an input carries in
    // is replaced, or dropped if this run made none.
    let mut sources: Vec<Source> = agreed
        .sources()
        .iter()
        .filter(|s| s.kind() != KIND_ADMISSION)
        .cloned()
        .collect();
    let readings = sources.len();
    sources.extend(checked);
    let agreed = SetFile::new(
        agreed.cluster(),
        agreed.shred_version(),
        agreed.epoch(),
        agreed.set_bytes().to_vec(),
        sources,
    )
    .map_err(|e| format!("nothing written: {e}"))?;

    let record = agreed.candidate(prev).map_err(|e| e.to_string())?;
    log.push(SignedRecord::unsigned(record));
    check_links(&log)
        .map_err(|e| format!("nothing written: the log cannot take this record: {e}"))?;
    let candidate = &log[log.len() - 1];

    write_new(set_path, &agreed.to_json())?;
    write_new(record_path, &to_text(std::slice::from_ref(candidate)))?;
    println!(
        "agreed: {readings} sources give epoch {} of {} (shred version {}) the set {}, \
         total stake {}",
        agreed.epoch(),
        agreed.cluster(),
        agreed.shred_version(),
        describe(&agreed),
        set.total_stake()
    );
    println!("wrote {set_path} and {record_path} (unsigned)");
    Ok(())
}

/// Prints a file's sources, the admission check apart from the readings.
fn print_sources(sources: &[Source]) {
    let mut checked = false;
    for source in sources {
        if source.kind() == KIND_ADMISSION {
            checked = true;
            println!(
                "  members checked against the admission debits in the block at slot {}",
                source.slot()
            );
        } else {
            println!(
                "  source {} {} at slot {}",
                source.kind(),
                source.label(),
                source.slot()
            );
        }
    }
    if !checked {
        println!("  members not checked against the admission debits");
    }
}

fn signing_key() -> Result<SigningKey, String> {
    let seed = std::env::var(KEY_VARIABLE)
        .map_err(|_| format!("the environment variable {KEY_VARIABLE} is not set"))?;
    SigningKey::from_hex(&seed)
        .map_err(|_| format!("{KEY_VARIABLE} is not a signing key: 64 hex digits, not all zero"))
}

fn keygen(args: impl Iterator<Item = String>) -> Outcome {
    Args::parse(args, &[])?.no_positional()?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("no randomness from the system: {e}"))?;
    let key = SigningKey::from_seed(seed).map_err(|e| e.to_string())?;
    // The secret alone on standard output, so that it can go straight into
    // a secret store: `setlog keygen | your-secret-tool`.
    println!("{}", hex::encode(seed));
    eprintln!("public key: {}", hex::encode(key.public_key()));
    eprintln!("The line on standard output is the secret. Keep it out of files in a repository;");
    eprintln!("setlog reads it from the environment variable {KEY_VARIABLE}.");
    Ok(())
}

fn pubkey(args: impl Iterator<Item = String>) -> Outcome {
    Args::parse(args, &[])?.no_positional()?;
    println!("{}", hex::encode(signing_key()?.public_key()));
    Ok(())
}

fn sign(args: impl Iterator<Item = String>) -> Outcome {
    let args = Args::parse(args, &["record", "set"])?;
    args.no_positional()?;
    let record_path = args.required("record")?;
    let mut record = read_record(record_path)?;
    let set = read_set(args.required("set")?)?;
    // A signature says "I read this set myself". The set file is the
    // signer's evidence of having done so.
    if !set.supports(record.record()) {
        return Err(format!(
            "not signed: the set file is for epoch {} of {} (shred version {}) with set {}, \
             and the record is for epoch {} of {} (shred version {}) with set {} ({} validators)",
            set.epoch(),
            set.cluster(),
            set.shred_version(),
            describe(&set),
            record.record().epoch(),
            record.record().cluster(),
            record.record().shred_version(),
            hex::encode(record.record().set_hash()),
            record.record().validators(),
        ));
    }
    if !record.signatures_valid() {
        return Err("not signed: the record carries a signature that does not verify".into());
    }
    let key = signing_key()?;
    record.sign(&key);
    replace(record_path, &to_text(std::slice::from_ref(&record)))?;
    println!(
        "signed record {} as {}; it now has {} signature(s)",
        hex::encode(record.record().hash()),
        hex::encode(key.public_key()),
        record.signatures().len()
    );
    Ok(())
}

fn append(args: impl Iterator<Item = String>) -> Outcome {
    let args = Args::parse(args, &["log", "record"])?;
    args.no_positional()?;
    let log_path = args.required("log")?;
    let record = read_record(args.required("record")?)?;
    if record.signatures().is_empty() {
        return Err("not appended: the record is not signed".into());
    }
    let mut log = if Path::new(log_path).exists() {
        read_log(log_path)?
    } else {
        Vec::new()
    };
    log.push(record);
    let head = check_links(&log).map_err(|e| {
        let line = log.len();
        match e {
            Error::BrokenLink { index } if index + 1 == line => {
                "not appended: the record does not link to the end of the log".to_string()
            }
            other => format!("not appended: {}", in_file(log_path, other)),
        }
    })?;
    replace(log_path, &to_text(&log))?;
    println!(
        "appended; {log_path} has {} record(s), head {}",
        log.len(),
        hex::encode(head)
    );
    Ok(())
}

fn verify_log(args: impl Iterator<Item = String>) -> Outcome {
    let args = Args::parse(args, &["log", "signer", "threshold"])?;
    args.no_positional()?;
    let log_path = args.required("log")?;
    let threshold: usize = args.number("threshold")?;
    let signers = args
        .all("signer")
        .iter()
        .map(|text| {
            signer_key_from_hex(text).map_err(|_| format!("--signer {text}: not 64 hex digits"))
        })
        .collect::<Result<Vec<SignerKey>, String>>()?;
    if signers.is_empty() {
        return Err("--signer is required".into());
    }
    let records = read_log(log_path)?;
    let log = verify(&records, &signers, threshold).map_err(|e| in_file(log_path, e))?;
    println!(
        "verified: {} record(s) for {}, each signed by at least {threshold} of {} listed keys",
        log.len(),
        log.cluster(),
        signers.len()
    );
    // The block each epoch's members were checked against, from the latest
    // record for the epoch that names one.
    let mut checked: BTreeMap<u64, u64> = BTreeMap::new();
    for signed in &records {
        let record = signed.record();
        for source in record.sources() {
            if source.kind() == KIND_ADMISSION {
                checked.insert(record.epoch(), source.slot());
            }
        }
    }
    for (epoch, pin) in log.pins() {
        println!(
            "epoch {epoch}: pin {} ({} validators, shred version {})",
            hex::encode(pin.set_hash),
            pin.validators,
            pin.shred_version
        );
        match checked.get(epoch) {
            Some(slot) => println!(
                "  members checked against the admission debits in the block at slot {slot}"
            ),
            None => println!("  members not checked against the admission debits"),
        }
    }
    println!("head {}", hex::encode(log.head()));
    Ok(())
}

fn show(args: impl Iterator<Item = String>) -> Outcome {
    let args = Args::parse(args, &[])?;
    let [path] = args.positional() else {
        return Err("give one file".into());
    };
    let text = read(path)?;
    if let Ok(set) = SetFile::from_json(&text) {
        println!(
            "set file: epoch {} of {} (shred version {})",
            set.epoch(),
            set.cluster(),
            set.shred_version()
        );
        println!("  set hash {}", describe(&set));
        match ValidatorSet::from_bytes(set.set_bytes()) {
            Ok(valid) => println!("  a valid ranked set, total stake {}", valid.total_stake()),
            Err(why) => println!("  NOT a set the verifier accepts: {why}"),
        }
        print_sources(set.sources());
        return Ok(());
    }
    let records = parse(&text).map_err(|e| in_file(path, e))?;
    let mut prev = [0; 32];
    for (index, signed) in records.iter().enumerate() {
        let record = signed.record();
        println!(
            "record {}: epoch {} of {} (shred version {})",
            index + 1,
            record.epoch(),
            record.cluster(),
            record.shred_version()
        );
        println!(
            "  set hash {} ({} validators)",
            hex::encode(record.set_hash()),
            record.validators()
        );
        print_sources(record.sources());
        let linked = if index == 0 && record.prev() == &prev {
            "starts a log"
        } else if index == 0 {
            "continues a log"
        } else if record.prev() == &prev {
            "links to the record before"
        } else {
            "DOES NOT LINK to the record before"
        };
        println!("  prev {} ({linked})", hex::encode(record.prev()));
        prev = record.hash();
        println!("  hash {}", hex::encode(prev));
        for signature in signed.signatures() {
            let valid = signature.verifies(record);
            println!(
                "  signed by {} ({})",
                hex::encode(signature.signer),
                if valid { "valid" } else { "INVALID" }
            );
        }
        if signed.signatures().is_empty() {
            println!("  not signed");
        }
    }
    println!("This shows what the file says. `setlog verify` checks who signed it.");
    Ok(())
}
