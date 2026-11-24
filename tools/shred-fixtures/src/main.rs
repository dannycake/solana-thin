//! Runs Firedancer's shred-parse conformance fixtures through solana-thin.
//!
//! Each fixture is a list of raw shreds plus what Agave's harness said about
//! them. Three things are compared, and only these:
//!
//! 1. per shred, whether `RawDataShred::parse` accepts it against the
//!    reference's "parses as a chained Merkle shred";
//! 2. per completed FEC set, the Merkle root the light client computes from
//!    the data shreds against the reference's, plus the header fields;
//! 3. per slot, whether `BlockData::from_shreds` can index what is there
//!    (reported, never a failure: the reference has no comparable verdict).
//!
//! The fixtures' block verdict is deliberately ignored. It follows a
//! pre-Alpenglow configuration (tick verification) that this verifier does not
//! implement and should not match.

mod fetch;
mod reference;

use prost::Message;
use protosol::protos::{FecSetParseResult, ShredParseFixture};
use reference::Kind;
use solana_thin::prover::BlockData;
use solana_thin::shred::{RawDataShred, DATA_SHRED_SIZE};
use solana_thin::Error;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
usage: shred-fixtures --tag <release> [--cache DIR] [--expected FILE] [--offline] [--list]

  --tag       firedancer-io/test-vectors release, e.g. 54829b38
  --cache     where to keep the download (default: $XDG_CACHE_HOME/solana-thin/shred-fixtures)
  --expected  allow-list of intended differences (default: expected-differences.toml beside Cargo.toml)
  --offline   never touch the network; fail if the fixtures are not cached
  --list      print every per-shred disagreement, not one example per class";

/// One place a class of outcome was seen.
#[derive(Clone)]
struct Example {
    fixture: String,
    shred: Option<usize>,
    detail: String,
}

/// How often a class was seen, where first, and in which variants.
#[derive(Default)]
struct Tally {
    count: usize,
    fixtures: BTreeSet<String>,
    first: Option<Example>,
    variants: BTreeMap<u8, usize>,
}

type Classes = BTreeMap<String, Tally>;

fn note(classes: &mut Classes, class: &str, example: Example, variant: Option<u8>) {
    let tally = classes.entry(class.to_string()).or_default();
    tally.count += 1;
    tally.fixtures.insert(example.fixture.clone());
    if let Some(v) = variant {
        *tally.variants.entry(v).or_default() += 1;
    }
    tally.first.get_or_insert(example);
}

/// A difference that fails the run unless the allow-list names it.
struct Finding {
    kind: &'static str,
    class: String,
    fixture: String,
    shred: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowed {
    /// `accepts-rejected` or `fec-root`.
    kind: String,
    /// The class exactly as the summary prints it.
    class: String,
    /// Restrict to one fixture file.
    fixture: Option<String>,
    /// Restrict to one shred of that fixture.
    shred: Option<usize>,
    /// Why the difference is intended. Required.
    reason: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AllowFile {
    #[serde(default)]
    difference: Vec<Allowed>,
}

#[derive(Default)]
struct Report {
    fixtures: usize,
    undecodable: Classes,
    shreds: usize,
    variants: BTreeMap<Option<u8>, usize>,
    lengths: BTreeMap<usize, usize>,
    result_count_mismatch: Classes,
    both_accept: usize,
    both_reject: Classes,
    stricter: Classes,
    looser: Classes,
    model_gap: Classes,
    fixtures_all_agree: usize,
    fixtures_stricter_only: usize,
    fixtures_with_looser: usize,

    fec_results: usize,
    fec_not_completed: usize,
    fec: Classes,
    fec_fields: BTreeMap<&'static str, [usize; 3]>,
    fec_stray_shreds: usize,

    block_groups: usize,
    block_indexed: usize,
    block_shreds: usize,
    block_components: usize,
    block_footers: usize,
    block_transactions: usize,
    block_refused: Classes,

    findings: Vec<Finding>,
    listing: Vec<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("shred-fixtures: {message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let (mut tag, mut cache, mut expected) = (None, None, None);
    let (mut offline, mut list) = (false, false);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value\n{USAGE}"));
        match arg.as_str() {
            "--tag" => tag = Some(value("--tag")?),
            "--cache" => cache = Some(PathBuf::from(value("--cache")?)),
            "--expected" => expected = Some(PathBuf::from(value("--expected")?)),
            "--offline" => offline = true,
            "--list" => list = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    let tag = tag.ok_or(format!("--tag is required\n{USAGE}"))?;
    let cache = match cache {
        Some(dir) => dir,
        None => fetch::default_cache()?,
    };
    let expected = expected
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("expected-differences.toml"));
    let allow: AllowFile = match std::fs::read_to_string(&expected) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", expected.display()))?,
        Err(e) => return Err(format!("{}: {e}", expected.display())),
    };
    for entry in &allow.difference {
        if !matches!(entry.kind.as_str(), "accepts-rejected" | "fec-root") {
            return Err(format!(
                "{}: unknown kind {:?}",
                expected.display(),
                entry.kind
            ));
        }
        if entry.reason.trim().is_empty() {
            return Err(format!("{}: an entry has no reason", expected.display()));
        }
    }

    let fixtures = fetch::ensure(&tag, &cache, offline)?;
    let mut files: Vec<PathBuf> = std::fs::read_dir(&fixtures.dir)
        .map_err(|e| format!("read {}: {e}", fixtures.dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|x| x == "fix"))
        .collect();
    files.sort();

    let mut report = Report::default();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = std::fs::read(path).map_err(|e| format!("read {name}: {e}"))?;
        check_fixture(&name, &bytes, list, &mut report);
    }

    println!("release        firedancer-io/test-vectors {tag}, shred.tar.gz");
    println!(
        "archive sha256 {} ({}; {})",
        fixtures.archive_sha256,
        if fixtures.pinned {
            "matches SHA256SUMS and the digest pinned in this tool"
        } else {
            "matches SHA256SUMS only: this tag has no pinned digest"
        },
        if fixtures.downloaded {
            "downloaded this run"
        } else {
            "from cache"
        },
    );
    println!("fixtures dir   {}", fixtures.dir.display());
    println!(
        "allow-list     {} ({} entries)",
        expected.display(),
        allow.difference.len()
    );
    println!();
    print!("{}", render(&report));

    let mut used = vec![false; allow.difference.len()];
    let mut failing = Vec::new();
    for finding in &report.findings {
        let hit = allow.difference.iter().position(|a| {
            a.kind == finding.kind
                && a.class == finding.class
                && a.fixture.as_ref().is_none_or(|f| *f == finding.fixture)
                && a.shred.is_none_or(|s| Some(s) == finding.shred)
        });
        match hit {
            Some(i) => used[i] = true,
            None => failing.push(finding),
        }
    }
    println!("VERDICT");
    println!(
        "  differences that fail the run: {} ({} allow-listed, {} not)",
        report.findings.len(),
        report.findings.len() - failing.len(),
        failing.len()
    );
    for (entry, used) in allow.difference.iter().zip(&used) {
        if !used {
            println!(
                "  note: allow-list entry matched nothing: [{}] {}",
                entry.kind, entry.class
            );
        }
    }
    for finding in failing.iter().take(20) {
        println!(
            "  FAIL [{}] {} -- {}{}",
            finding.kind,
            finding.class,
            finding.fixture,
            finding
                .shred
                .map(|s| format!(" shred {s}"))
                .unwrap_or_default()
        );
    }
    if failing.len() > 20 {
        println!("  ... and {} more", failing.len() - 20);
    }
    if !report.listing.is_empty() {
        println!();
        println!("EVERY PER-SHRED DISAGREEMENT");
        for line in &report.listing {
            println!("  {line}");
        }
    }
    Ok(if failing.is_empty() {
        println!("  PASS");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The bytes that identify a shred: everything after the signature up to the
/// end of the longer (coding) header, plus a little of the body.
fn describe(payload: &[u8]) -> String {
    let (from, to) = if payload.len() > 64 {
        (64, payload.len().min(96))
    } else {
        (0, payload.len())
    };
    format!(
        "len={} bytes[{from}..{to}]={}",
        payload.len(),
        fetch::hex(&payload[from..to])
    )
}

fn light_client_reason(error: &Error) -> String {
    match error {
        Error::InvalidShred(what) => (*what).to_string(),
        other => format!("{other:?}"),
    }
}

fn check_fixture(name: &str, bytes: &[u8], list: bool, report: &mut Report) {
    report.fixtures += 1;
    let at = |shred: Option<usize>, detail: String| Example {
        fixture: name.to_string(),
        shred,
        detail,
    };
    let fixture = match ShredParseFixture::decode(bytes) {
        Ok(fixture) => fixture,
        Err(e) => {
            return note(
                &mut report.undecodable,
                "protobuf decode",
                at(None, e.to_string()),
                None,
            )
        }
    };
    let (Some(input), Some(output)) = (fixture.input, fixture.output) else {
        return note(
            &mut report.undecodable,
            "no input or no output",
            at(None, String::new()),
            None,
        );
    };
    if input.shreds.len() != output.shred_results.len() {
        let detail = format!(
            "{} shreds, {} results",
            input.shreds.len(),
            output.shred_results.len()
        );
        return note(
            &mut report.result_count_mismatch,
            "shred_results length",
            at(None, detail),
            None,
        );
    }

    // 1. Per-shred verdicts.
    let mut parsed: Vec<Option<RawDataShred>> = Vec::with_capacity(input.shreds.len());
    let (mut any_stricter, mut any_looser) = (false, false);
    for (i, payload) in input.shreds.iter().enumerate() {
        report.shreds += 1;
        let expected = output.shred_results[i];
        let ours = RawDataShred::parse(payload);
        let model = reference::parses(payload);
        let variant = payload.get(64).copied();
        *report.variants.entry(variant).or_default() += 1;
        *report.lengths.entry(payload.len()).or_default() += 1;
        let example = at(Some(i), describe(payload));
        if model.is_ok() != expected {
            let class = match model {
                Ok(_) => "fixture rejects, model accepts".to_string(),
                Err(rule) => format!("fixture accepts, model rejects: {rule}"),
            };
            note(&mut report.model_gap, &class, example.clone(), variant);
        }
        let mut disagreement = None;
        match (&ours, expected) {
            (Ok(_), true) => report.both_accept += 1,
            (Err(error), false) => {
                let rule = model.err().unwrap_or("(this tool's model would accept it)");
                let class = format!(
                    "reference: {rule}; light client: {}",
                    light_client_reason(error)
                );
                note(&mut report.both_reject, &class, example, variant);
            }
            (Err(error), true) => {
                any_stricter = true;
                let ours = light_client_reason(error);
                let class = match model {
                    Ok(Kind::Code { .. }) => "coding shred (0x6_/0x7_): the light client reads data shreds only".to_string(),
                    Ok(Kind::Data { proof_size, .. }) if proof_size != 6 => {
                        "data shred whose Merkle proof size is not 6 (not a 32:32 FEC set)".to_string()
                    }
                    Ok(Kind::Data { .. }) => format!("UNEXPLAINED: 0x96/0xb6 data shred refused by the light client ({ours})"),
                    Err(rule) => format!("UNEXPLAINED: model says the reference rejects ({rule}); light client: {ours}"),
                };
                disagreement = Some(format!("stricter | {class}"));
                note(&mut report.stricter, &class, example, variant);
            }
            (Ok(_), false) => {
                any_looser = true;
                let class = match model {
                    Err(rule) => rule.to_string(),
                    Ok(_) => {
                        "UNEXPLAINED: this tool's model of the reference accepts it too".to_string()
                    }
                };
                report.findings.push(Finding {
                    kind: "accepts-rejected",
                    class: class.clone(),
                    fixture: name.to_string(),
                    shred: Some(i),
                });
                disagreement = Some(format!("LOOSER   | {class}"));
                note(&mut report.looser, &class, example, variant);
            }
        }
        if let (true, Some(what)) = (list, disagreement) {
            report
                .listing
                .push(format!("{name} shred {i}: {what} | {}", describe(payload)));
        }
        parsed.push(ours.ok());
    }
    match (any_stricter, any_looser) {
        (false, false) => report.fixtures_all_agree += 1,
        (true, false) => report.fixtures_stricter_only += 1,
        (_, true) => report.fixtures_with_looser += 1,
    }

    // 2. Completed FEC sets.
    for result in &output.fec_set_results {
        report.fec_results += 1;
        if !result.completed {
            report.fec_not_completed += 1;
            continue;
        }
        check_fec_set(name, result, &parsed, report);
    }

    // 3. Whole slots, as far as the light client's prover is concerned.
    let mut slots: BTreeMap<u64, BTreeMap<&[u8], u32>> = BTreeMap::new();
    for (payload, shred) in input.shreds.iter().zip(&parsed) {
        if let Some(shred) = shred {
            // Exact repeats of one shred are the same shred.
            slots
                .entry(shred.slot)
                .or_default()
                .insert(&payload[..DATA_SHRED_SIZE], shred.index);
        }
    }
    for (slot, group) in slots {
        report.block_groups += 1;
        let payloads: Vec<&[u8]> = group.keys().copied().collect();
        match BlockData::from_shreds(&payloads) {
            Ok(block) => {
                report.block_indexed += 1;
                report.block_shreds += block.shred_count() as usize;
                report.block_components += block.components().count();
                report.block_footers += usize::from(block.footer().is_some());
                report.block_transactions += block.signatures().len();
            }
            Err(error) => {
                let class = match &error {
                    // `MissingShred` covers four shapes; say which one this is.
                    Error::MissingShred(_) => {
                        let mut indices: Vec<u32> = group.values().copied().collect();
                        indices.sort_unstable();
                        let shape = if indices.windows(2).any(|w| w[0] == w[1]) {
                            "two different shreds claim one index"
                        } else if indices[0] != 0 {
                            "no shred 0: the slot's first FEC set is absent"
                        } else if indices.windows(2).any(|w| w[1] != w[0] + 1) {
                            "a gap in the shred indices (absent, or refused by the parser)"
                        } else {
                            "shred count is not a multiple of 32"
                        };
                        format!("missing shreds: {shape}")
                    }
                    Error::InvalidShred(what) => format!("invalid shred: {what}"),
                    Error::InvalidComponent(what) => format!("invalid component: {what}"),
                    Error::UpdateParentBlock => "leader switched parent mid-block".to_string(),
                    other => format!("{other:?}"),
                };
                let detail = format!("slot {slot}, {} data shreds: {error}", payloads.len());
                note(&mut report.block_refused, &class, at(None, detail), None);
            }
        }
    }
}

fn check_fec_set(
    name: &str,
    result: &FecSetParseResult,
    parsed: &[Option<RawDataShred>],
    report: &mut Report,
) {
    // Every data shred of the input that claims to sit in this set. There can
    // be several per index: the fuzzer replays and equivocates.
    let mut positions: Vec<Vec<(usize, &RawDataShred, bool)>> = vec![Vec::new(); 32];
    for (i, shred) in parsed.iter().enumerate() {
        let Some(shred) = shred else { continue };
        if shred.slot != result.slot || shred.fec_set_index != result.fec_set_index {
            continue;
        }
        let Some(position) = shred
            .index
            .checked_sub(shred.fec_set_index)
            .filter(|p| *p < 32)
        else {
            continue;
        };
        let agrees = shred
            .fec_set_root()
            .is_ok_and(|root| root[..] == result.merkle_root[..]);
        positions[position as usize].push((i, shred, agrees));
    }
    let agreeing = positions.iter().filter(|p| p.iter().any(|c| c.2)).count();
    let conflicting = positions
        .iter()
        .filter(|p| !p.is_empty() && !p.iter().any(|c| c.2))
        .count();
    let absent = positions.iter().filter(|p| p.is_empty()).count();
    report.fec_stray_shreds += positions.iter().flatten().filter(|c| !c.2).count();

    let detail = format!(
        "slot {} fec_set_index {} root {}: {agreeing} positions agree, {conflicting} only disagree, {absent} absent",
        result.slot,
        result.fec_set_index,
        fetch::hex(&result.merkle_root),
    );
    let example = Example {
        fixture: name.to_string(),
        shred: None,
        detail,
    };
    let class = if conflicting > 0 {
        "ROOT DIFFERS: a position holds data shreds, none of which gives the reference root"
    } else if agreeing == 32 {
        "root equal: all 32 data shreds present, every one gives the reference root"
    } else if agreeing > 0 {
        "root equal on the data shreds present (the reference recovered the rest from coding shreds)"
    } else {
        "not comparable: no data shred of the set in the input (recovered from coding shreds)"
    };
    if conflicting > 0 {
        report.findings.push(Finding {
            kind: "fec-root",
            class: class.to_string(),
            fixture: name.to_string(),
            shred: positions
                .iter()
                .find(|p| !p.is_empty() && !p.iter().any(|c| c.2))
                .map(|p| p[0].0),
        });
    }
    note(&mut report.fec, class, example, None);
    if agreeing == 0 {
        return;
    }

    // Header fields, read from the shreds whose root agreed. Slot and FEC set
    // index were the selection key, so they are equal by construction; the
    // rest are real comparisons.
    let good: Vec<Option<(usize, &RawDataShred)>> = positions
        .iter()
        .map(|p| p.iter().find(|c| c.2).map(|c| (c.0, c.1)))
        .collect();
    let present = || good.iter().flatten().map(|c| c.1);
    let mut field = |name: &'static str, outcome: Option<bool>| {
        let slot = match outcome {
            Some(true) => 0,
            Some(false) => 1,
            None => 2,
        };
        report.fec_fields.entry(name).or_default()[slot] += 1;
    };
    field("slot, fec_set_index (selection key)", Some(true));
    field(
        "chained_merkle_root",
        Some(present().all(|s| s.chained_root[..] == result.chained_merkle_root[..])),
    );
    field(
        "shred_version",
        Some(present().all(|s| u32::from(s.shred_version) == result.shred_version)),
    );
    // The reference reports the first shred's parent offset.
    field(
        "parent_offset (of the set's first shred)",
        good[0].map(|(_, s)| u32::from(s.shred.parent_offset) == result.parent_offset),
    );
    field("num_data_shreds == 32", Some(result.num_data_shreds == 32));
    // XXH64 of the 32 data regions, which checks `size` handling end to end.
    let payload_hash = (agreeing == 32).then(|| {
        let mut data = Vec::new();
        for (_, shred) in good.iter().flatten() {
            shred
                .shred
                .append_data(&mut data)
                .expect("parse checked the size");
        }
        let hash = if data.is_empty() {
            0
        } else {
            xxhash_rust::xxh64::xxh64(&data, 0)
        };
        hash == result.payload_hash
    });
    field("payload_hash (XXH64 of the data regions)", payload_hash);
}

fn render(report: &Report) -> String {
    let mut out = String::new();
    let o = &mut out;
    let classes = |o: &mut String, classes: &Classes, indent: &str| {
        for (class, tally) in classes {
            let _ = writeln!(o, "{indent}{:>7}  {class}", tally.count);
            if !tally.variants.is_empty() {
                let variants: Vec<String> = tally
                    .variants
                    .iter()
                    .map(|(v, n)| format!("0x{v:02x} x{n}"))
                    .collect();
                let _ = writeln!(o, "{indent}         variants: {}", variants.join(", "));
            }
            if let Some(first) = &tally.first {
                let shred = first
                    .shred
                    .map(|s| format!(" shred {s}"))
                    .unwrap_or_default();
                let _ = writeln!(
                    o,
                    "{indent}         in {} fixture(s); e.g. {}{shred}: {}",
                    tally.fixtures.len(),
                    first.fixture,
                    first.detail
                );
            }
        }
    };
    let total = |classes: &Classes| classes.values().map(|t| t.count).sum::<usize>();

    let _ = writeln!(o, "FIXTURES");
    let _ = writeln!(o, "  {:>7}  fixture files", report.fixtures);
    let _ = writeln!(
        o,
        "  {:>7}  could not be decoded or compared",
        total(&report.undecodable) + total(&report.result_count_mismatch)
    );
    classes(o, &report.undecodable, "  ");
    classes(o, &report.result_count_mismatch, "  ");
    let _ = writeln!(
        o,
        "  {:>7}  every shred verdict agrees",
        report.fixtures_all_agree
    );
    let _ = writeln!(
        o,
        "  {:>7}  differ only where the light client is stricter",
        report.fixtures_stricter_only
    );
    let _ = writeln!(
        o,
        "  {:>7}  hold a shred the light client accepts and the reference rejects",
        report.fixtures_with_looser
    );
    let _ = writeln!(o);

    let _ = writeln!(o, "1. PER-SHRED: RawDataShred::parse vs shred_results");
    let _ = writeln!(o, "  {:>7}  shreds", report.shreds);
    let variants: Vec<String> = report
        .variants
        .iter()
        .map(|(v, n)| match v {
            Some(v) => format!("0x{v:02x} x{n}"),
            None => format!("none x{n}"),
        })
        .collect();
    let lengths: Vec<String> = report
        .lengths
        .iter()
        .map(|(l, n)| format!("{l} x{n}"))
        .collect();
    let _ = writeln!(o, "           by variant byte: {}", variants.join(", "));
    let _ = writeln!(o, "           by length: {}", lengths.join(", "));
    let _ = writeln!(o, "  {:>7}  agree: both accept", report.both_accept);
    let _ = writeln!(
        o,
        "  {:>7}  agree: both reject, by the reference rule that refuses it:",
        total(&report.both_reject)
    );
    classes(o, &report.both_reject, "    ");
    let _ = writeln!(
        o,
        "  {:>7}  light client STRICTER (rejects what the reference parses):",
        total(&report.stricter)
    );
    classes(o, &report.stricter, "    ");
    let _ = writeln!(
        o,
        "  {:>7}  light client LOOSER (accepts what the reference rejects) -- fails the run:",
        total(&report.looser)
    );
    classes(o, &report.looser, "    ");
    let _ = writeln!(
        o,
        "  {:>7}  shreds where this tool's model of the reference rules differs from the fixture:",
        total(&report.model_gap)
    );
    classes(o, &report.model_gap, "    ");
    let _ = writeln!(o);

    let _ = writeln!(
        o,
        "2. FEC SETS: fec_set_root() of the data shreds vs merkle_root"
    );
    let _ = writeln!(
        o,
        "  {:>7}  fec_set_results entries ({} with completed == false, skipped)",
        report.fec_results, report.fec_not_completed
    );
    classes(o, &report.fec, "  ");
    let _ = writeln!(
        o,
        "  {:>7}  data shreds in those sets with a different root (replays the reference dropped)",
        report.fec_stray_shreds
    );
    let _ = writeln!(o, "  fields, over sets with at least one agreeing data shred:  equal / differ / not comparable");
    for (name, [equal, differ, na]) in &report.fec_fields {
        let _ = writeln!(o, "    {equal:>6} / {differ:>3} / {na:>4}  {name}");
    }
    let _ = writeln!(o);

    let _ = writeln!(
        o,
        "3. BLOCKS: BlockData::from_shreds per (fixture, slot) -- informational"
    );
    let _ = writeln!(
        o,
        "  {:>7}  (fixture, slot) groups of data shreds the light client parsed",
        report.block_groups
    );
    let _ = writeln!(
        o,
        "  {:>7}  indexed ({} shreds, {} components, {} with a footer, {} transactions)",
        report.block_indexed,
        report.block_shreds,
        report.block_components,
        report.block_footers,
        report.block_transactions
    );
    let _ = writeln!(o, "  {:>7}  refused:", total(&report.block_refused));
    classes(o, &report.block_refused, "    ");
    let _ = writeln!(o);
    out
}
