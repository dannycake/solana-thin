//! Keeps `scripts/nightly.sh` from reporting a run that left a step out as a
//! run that passed.
//!
//! The nightly run stands behind everything CI is too small for, the oracle
//! above all. A line saying every step passed, on a machine where the oracle
//! never ran, is worse than no nightly. This runs the real script in a
//! stand-in repository with no Agave checkout and a stub for the fuzz step,
//! and checks what it says and how it exits.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Outcome {
    code: Option<i32>,
    output: String,
    state: PathBuf,
}

impl Outcome {
    fn has(&self, marker: &str) -> bool {
        self.state.join("nightly").join(marker).exists()
    }
}

/// Runs `scripts/nightly.sh <steps>` from a directory that holds nothing but
/// the script and a `scripts/fuzz.sh` that exits with `fuzz_status`. There
/// is no `tools/agave` there, so the oracle step has nothing to build.
///
/// Steps are always named, and only `fuzz` and `oracle`: the others would
/// run for real, and the `tests` step is `cargo test`, which from here would
/// find this workspace and start this test again.
fn nightly(name: &str, steps: &[&str], fuzz_status: u8) -> Outcome {
    assert!(!steps.is_empty() && steps.iter().all(|s| *s != "tests"));
    let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/nightly.sh");
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("nightly-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    let scripts = root.join("repo/scripts");
    std::fs::create_dir_all(&scripts).unwrap();
    std::fs::copy(&real, scripts.join("nightly.sh")).unwrap();
    let stub = scripts.join("fuzz.sh");
    std::fs::write(
        &stub,
        format!("#!/bin/sh\necho stub fuzz step\nexit {fuzz_status}\n"),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

    let state = root.join("state");
    let output = Command::new("bash")
        .arg(scripts.join("nightly.sh"))
        .args(steps)
        // A bare environment: nothing of the developer's session, so a
        // failing run cannot raise a desktop notification from a test.
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &root)
        .env("SOLANA_THIN_STATE", &state)
        .env("SOLANA_THIN_BUILD", root.join("build"))
        .output()
        .expect("bash runs");
    Outcome {
        code: output.status.code(),
        output: String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr),
        state,
    }
}

#[test]
fn a_run_whose_steps_all_ran_and_passed_is_a_pass() {
    let run = nightly("pass", &["fuzz"], 0);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(run.output.contains("all steps passed"), "{}", run.output);
    assert!(run.has("last-ok"));
    assert!(!run.has("FAILED") && !run.has("INCOMPLETE"));
}

#[test]
fn a_failed_step_fails_the_run() {
    let run = nightly("fail", &["fuzz"], 3);
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(run.output.contains("FAILED (fuzz)"), "{}", run.output);
    assert!(!run.output.contains("all steps passed"), "{}", run.output);
    assert!(run.has("FAILED"));
    assert!(!run.has("last-ok"));
}

/// The oracle step cannot run without an Agave checkout. Asked for, alone or
/// with steps that pass, it makes the run incomplete: not a pass by its
/// summary, its exit status, or the marker a later look at the state finds.
#[test]
fn a_skipped_step_is_not_a_pass() {
    for (name, steps) in [
        ("skip-alone", &["oracle"][..]),
        ("skip-with-pass", &["fuzz", "oracle"]),
    ] {
        let run = nightly(name, steps, 0);
        assert_eq!(run.code, Some(2), "{}", run.output);
        assert!(!run.output.contains("all steps passed"), "{}", run.output);
        assert!(
            run.output.contains("INCOMPLETE") && run.output.contains("skipped: oracle"),
            "{}",
            run.output
        );
        assert!(run.has("INCOMPLETE"));
        assert!(!run.has("last-ok"));
    }

    // A failure next to a skip is still a failure, and still says what was
    // skipped.
    let run = nightly("skip-with-fail", &["fuzz", "oracle"], 1);
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert!(run.output.contains("FAILED (fuzz)"), "{}", run.output);
    assert!(run.output.contains("skipped: oracle"), "{}", run.output);
    assert!(!run.has("last-ok"));

    // Not asked for, the oracle is not a skipped step.
    let run = nightly("not-asked", &["fuzz"], 0);
    assert_eq!(run.code, Some(0), "{}", run.output);
    assert!(!run.output.contains("skip"), "{}", run.output);
}

/// A step name the script does not know selects nothing. Running nothing
/// and reporting that all of it passed is the same mistake.
#[test]
fn an_unknown_step_is_refused() {
    let run = nightly("unknown", &["fuzzz"], 0);
    assert_eq!(run.code, Some(64), "{}", run.output);
    assert!(run.output.contains("unknown step"), "{}", run.output);
    assert!(!run.output.contains("all steps passed"), "{}", run.output);
    assert!(!run.has("last-ok"));
}
