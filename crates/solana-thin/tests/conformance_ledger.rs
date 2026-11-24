//! Keeps `docs/conformance.toml` honest.
//!
//! The ledger lists every check a validator applies and says, for each,
//! which test shows the verifier enforcing it or which premise makes it
//! unnecessary. A ledger nobody checks rots: a test is renamed, a premise is
//! dropped, and the row still reads as covered. This fails when a row names
//! a test or a premise that does not exist, when a row is missing what its
//! status requires, or when `docs/CONFORMANCE.md` is stale.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A table of the ledger: its kind (`check` or `premise`) and its keys.
/// The file is written by hand in a narrow subset of TOML (one `key = value`
/// per line, strings in double quotes), so that reading it needs no parser
/// dependency.
fn tables(text: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut out: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(kind) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
            out.push((kind.to_string(), BTreeMap::new()));
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            panic!("ledger line is not `key = value`: {line}");
        };
        let value = value.trim().trim_matches('"').to_string();
        if let Some((_, table)) = out.last_mut() {
            assert!(
                table.insert(key.to_string(), value).is_none(),
                "duplicate key {key}"
            );
        }
    }
    out
}

/// Every `fn name(` in the crate's sources and tests.
fn test_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for dir in ["crates/solana-thin/src", "crates/solana-thin/tests"] {
        for entry in std::fs::read_dir(repo().join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let mut after_test_attribute = false;
            for line in text.lines() {
                let line = line.trim();
                if line == "#[test]" {
                    after_test_attribute = true;
                } else if let Some(rest) = line.strip_prefix("fn ") {
                    if after_test_attribute {
                        names.insert(rest.split('(').next().unwrap().to_string());
                    }
                    after_test_attribute = false;
                } else if !line.starts_with("#[") {
                    after_test_attribute = false;
                }
            }
        }
    }
    names
}

/// The `name` of every frozen oracle case.
fn oracle_case_names() -> BTreeSet<String> {
    let dir = repo().join("crates/solana-thin/tests/vectors/oracle");
    let mut names = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        names.insert(doc["name"].as_str().unwrap().to_string());
    }
    names
}

#[test]
fn every_row_of_the_ledger_resolves() {
    let text = std::fs::read_to_string(repo().join("docs/conformance.toml")).unwrap();
    let tables = tables(&text);
    let tests = test_names();
    let premises: BTreeSet<&str> = tables
        .iter()
        .filter(|(kind, _)| kind == "premise")
        .map(|(_, t)| t["id"].as_str())
        .collect();
    assert!(!premises.is_empty());

    let mut ids = Vec::new();
    let mut problems = Vec::new();
    for (_, row) in tables.iter().filter(|(kind, _)| kind == "check") {
        let id: u32 = row["id"].parse().unwrap();
        ids.push(id);
        for key in ["layer", "check", "agave", "error", "consequence", "status"] {
            if !row.contains_key(key) {
                problems.push(format!("row {id}: no `{key}`"));
            }
        }
        match row["status"].as_str() {
            // A planned row names the test that will exist; it is allowed
            // not to exist yet, and must not silently exist either.
            "planned" => match row.get("test") {
                None => problems.push(format!("row {id}: planned without a test name")),
                Some(test) if tests.contains(test) => problems.push(format!(
                    "row {id}: test `{test}` exists; the row is no longer planned"
                )),
                Some(_) => {}
            },
            "enforced" => match row.get("test") {
                None => problems.push(format!("row {id}: enforced without a test")),
                Some(test) if !tests.contains(test) => {
                    problems.push(format!("row {id}: no test named `{test}`"))
                }
                Some(_) => {}
            },
            "implied" => match row.get("premise") {
                None => problems.push(format!("row {id}: implied without a premise")),
                Some(premise) if !premises.contains(premise.as_str()) => {
                    problems.push(format!("row {id}: no premise named `{premise}`"))
                }
                Some(_) => {}
            },
            "documented" | "na" => {}
            other => problems.push(format!("row {id}: unknown status `{other}`")),
        }
    }
    // Every premise that a row leans on is shown by at least one case that
    // Agave's own code judged, and every case named is in the frozen corpus.
    let frozen = oracle_case_names();
    let used: BTreeSet<&str> = tables
        .iter()
        .filter(|(kind, _)| kind == "check")
        .filter_map(|(_, row)| row.get("premise").map(String::as_str))
        .collect();
    for (_, premise) in tables.iter().filter(|(kind, _)| kind == "premise") {
        let id = &premise["id"];
        let cases: Vec<&str> = premise["oracle_cases"]
            .trim_matches(|c| c == '[' || c == ']')
            .split(", ")
            .map(|c| c.trim_matches('"'))
            .filter(|c| !c.is_empty())
            .collect();
        if cases.is_empty() && used.contains(id.as_str()) {
            problems.push(format!(
                "premise {id}: rows lean on it and no oracle case shows it"
            ));
        }
        for case in cases {
            if !frozen.contains(case) {
                problems.push(format!(
                    "premise {id}: no frozen oracle case named `{case}`"
                ));
            }
        }
    }

    let expected: Vec<u32> = (1..=ids.len() as u32).collect();
    assert_eq!(ids, expected, "row ids are not 1..n in order");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_readable_ledger_is_up_to_date() {
    let python = std::process::Command::new("python3")
        .arg(repo().join("scripts/conformance.py"))
        .arg("--check")
        .output();
    match python {
        Ok(output) => assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        ),
        // No Python on this machine: nothing to compare with.
        Err(error) => eprintln!("skipped: python3 did not run: {error}"),
    }
}
