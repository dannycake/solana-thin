//! Getting the fixtures: download, checksum, extract.
//!
//! The archive is third-party data with no license, so it is fetched at run
//! time into a cache outside the repository and is only ever read as bytes.
//! Nothing in it is trusted: the checksum is verified before the archive is
//! opened, and extraction ignores every path the archive states, writing
//! regular `*.fix` members under their bare file name into a fresh directory.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const REPO: &str = "https://github.com/firedancer-io/test-vectors";
const ARCHIVE: &str = "shred.tar.gz";
const SUMS: &str = "SHA256SUMS";

/// Archive digests recorded when a release was first examined. `SHA256SUMS`
/// comes from the same release as the archive, so on its own it only shows the
/// download was not damaged; a pin also shows the release was not replaced.
const PINNED: &[(&str, &str)] = &[(
    "54829b38",
    "85f87febc5d4f2a62e154a62bd00e936a41b23f6f0ed10cd1afb2acb179765ca",
)];

/// Largest archive, largest member and largest extracted total accepted.
const MAX_ARCHIVE_BYTES: u64 = 256 << 20;
const MAX_MEMBER_BYTES: u64 = 16 << 20;
const MAX_TOTAL_BYTES: u64 = 2 << 30;
const MAX_MEMBERS: usize = 100_000;

/// Where the fixtures ended up and how they got there.
pub struct Fixtures {
    /// Directory holding the `*.fix` files and nothing else.
    pub dir: PathBuf,
    /// SHA-256 of the archive they were extracted from.
    pub archive_sha256: String,
    /// Whether that digest was also checked against a pin in this source.
    pub pinned: bool,
    /// Whether this run used the network.
    pub downloaded: bool,
}

/// Default cache root: `$XDG_CACHE_HOME/solana-thin/shred-fixtures`.
pub fn default_cache() -> Result<PathBuf, String> {
    let base = match std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(
            std::env::var_os("HOME")
                .ok_or("neither XDG_CACHE_HOME nor HOME is set; pass --cache")?,
        )
        .join(".cache"),
    };
    Ok(base.join("solana-thin").join("shred-fixtures"))
}

/// Makes sure the fixtures of release `tag` are extracted under `cache`.
pub fn ensure(tag: &str, cache: &Path, offline: bool) -> Result<Fixtures, String> {
    if !(7..=40).contains(&tag.len())
        || !tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("tag {tag:?} is not a lowercase hex commit prefix"));
    }
    let pin = PINNED.iter().find(|(t, _)| *t == tag).map(|(_, d)| *d);
    let dir = cache.join(tag);
    let fixtures = dir.join("fixtures");
    let marker = dir.join("extracted.sha256");

    if fixtures.is_dir() {
        if let Ok(digest) = fs::read_to_string(&marker) {
            let digest = digest.trim().to_string();
            if pin.is_none_or(|p| p == digest) {
                return Ok(Fixtures {
                    dir: fixtures,
                    archive_sha256: digest,
                    pinned: pin.is_some(),
                    downloaded: false,
                });
            }
        }
    }
    if offline {
        return Err(format!(
            "no extracted fixtures under {} and --offline was given",
            dir.display()
        ));
    }

    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let sums_path = dir.join(SUMS);
    download(
        &format!("{REPO}/releases/download/{tag}/{SUMS}"),
        &sums_path,
    )?;
    let sums = fs::read_to_string(&sums_path).map_err(|e| format!("read {SUMS}: {e}"))?;
    let expected = digest_for(&sums, ARCHIVE)
        .ok_or_else(|| format!("{SUMS} of release {tag} has no line for {ARCHIVE}"))?;
    if let Some(pin) = pin {
        if pin != expected {
            return Err(format!(
                "release {tag} now lists {ARCHIVE} as {expected}, but this tool pinned {pin}"
            ));
        }
    }

    let archive = dir.join(ARCHIVE);
    let have = archive.is_file() && sha256_file(&archive)? == expected;
    if !have {
        let part = dir.join(format!("{ARCHIVE}.part"));
        download(&format!("{REPO}/releases/download/{tag}/{ARCHIVE}"), &part)?;
        let got = sha256_file(&part)?;
        if got != expected {
            let _ = fs::remove_file(&part);
            return Err(format!(
                "{ARCHIVE} has sha256 {got}, but {SUMS} says {expected}; nothing was extracted"
            ));
        }
        fs::rename(&part, &archive).map_err(|e| format!("rename archive: {e}"))?;
    }

    // Extract beside the final place, then move, so a half-extracted
    // directory is never mistaken for a complete one.
    let staging = dir.join(format!("fixtures.partial-{}", std::process::id()));
    for stale in [&staging, &fixtures] {
        if stale.exists() {
            fs::remove_dir_all(stale).map_err(|e| format!("remove {}: {e}", stale.display()))?;
        }
    }
    let _ = fs::remove_file(&marker);
    fs::create_dir(&staging).map_err(|e| format!("create {}: {e}", staging.display()))?;
    extract(&archive, &staging)?;
    fs::rename(&staging, &fixtures).map_err(|e| format!("rename fixtures: {e}"))?;
    fs::write(&marker, format!("{expected}\n")).map_err(|e| format!("write marker: {e}"))?;

    Ok(Fixtures {
        dir: fixtures,
        archive_sha256: expected,
        pinned: pin.is_some(),
        downloaded: true,
    })
}

/// A plain anonymous GET. The only things sent are the URL and a generic
/// client name.
fn download(url: &str, to: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location"])
        .args(["--proto", "=https", "--proto-redir", "=https"])
        .args(["--max-time", "900", "--retry", "2"])
        .args(["--max-filesize", &MAX_ARCHIVE_BYTES.to_string()])
        .args(["--user-agent", "shred-fixtures"])
        .arg("--output")
        .arg(to)
        .arg("--")
        .arg(url)
        .status()
        .map_err(|e| format!("could not run curl: {e}"))?;
    if !status.success() {
        let _ = fs::remove_file(to);
        return Err(format!("curl {url}: {status}"));
    }
    Ok(())
}

/// The digest `sha256sum` recorded for `name`.
fn digest_for(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (digest, file) = line.split_once(char::is_whitespace)?;
        let file = file.trim_start().trim_start_matches('*');
        let hex = digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit());
        (hex && file == name).then(|| digest.to_ascii_lowercase())
    })
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(hex(&hasher.finalize()))
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes every regular `*.fix` member of the archive into `dest` under its
/// bare file name. Directories are skipped; any other kind of member (links,
/// devices) or a name that is not plain makes the whole extraction fail.
fn extract(archive: &Path, dest: &Path) -> Result<(), String> {
    let file = File::open(archive).map_err(|e| format!("open archive: {e}"))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let (mut members, mut total) = (0usize, 0u64);
    for entry in tar.entries().map_err(|e| format!("read archive: {e}"))? {
        let entry = entry.map_err(|e| format!("read archive: {e}"))?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| format!("member name: {e}"))?
            .into_owned();
        if !kind.is_file() {
            return Err(format!("archive member {path:?} is not a regular file"));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| {
                n.ends_with(".fix")
                    && !n.starts_with('.')
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            })
            .ok_or_else(|| format!("archive member {path:?} is not a plainly named .fix file"))?
            .to_string();
        let size = entry.size();
        members += 1;
        total += size;
        if size > MAX_MEMBER_BYTES || total > MAX_TOTAL_BYTES || members > MAX_MEMBERS {
            return Err(format!("archive is larger than expected at member {name}"));
        }
        let mut data = Vec::with_capacity(size as usize);
        entry
            .take(MAX_MEMBER_BYTES)
            .read_to_end(&mut data)
            .map_err(|e| format!("read member {name}: {e}"))?;
        // create_new: two members with the same file name is an error, not an overwrite.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest.join(&name))
            .and_then(|mut out| out.write_all(&data))
            .map_err(|e| format!("write {name}: {e}"))?;
    }
    if members == 0 {
        return Err("archive holds no .fix files".into());
    }
    Ok(())
}
