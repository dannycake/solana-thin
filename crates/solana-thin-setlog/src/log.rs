//! A log: records in a file, one per line, each naming the one before.

use crate::error::{Error, Result};
use crate::keys::SignerKey;
use crate::record::SignedRecord;
use crate::Hash;
use std::collections::{BTreeMap, BTreeSet};

/// What a verified log says about one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    /// The validator-set hash to pin for the epoch.
    pub set_hash: Hash,
    /// How many validators that set ranks.
    pub validators: u32,
    /// The cluster's shred version, from the latest record for the epoch.
    pub shred_version: u16,
}

/// A log whose every link and signature checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLog {
    cluster: String,
    hashes: Vec<Hash>,
    pins: BTreeMap<u64, Pin>,
}

impl VerifiedLog {
    /// The cluster every record names.
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// What to pin, by epoch.
    pub fn pins(&self) -> &BTreeMap<u64, Pin> {
        &self.pins
    }

    /// What to pin for `epoch`, if the log has a record for it.
    pub fn pin(&self, epoch: u64) -> Option<&Pin> {
        self.pins.get(&epoch)
    }

    /// Hash of the last record. A client that keeps it can tell, next time,
    /// whether the log it is handed still [`contains`](Self::contains) the
    /// one it saw.
    pub fn head(&self) -> &Hash {
        self.hashes.last().expect("a verified log is not empty")
    }

    /// Whether a record with this hash is in the log. A log that no longer
    /// contains a head seen earlier was rewritten, not extended.
    pub fn contains(&self, record_hash: &Hash) -> bool {
        self.hashes.contains(record_hash)
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Always false: an empty log does not verify.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

/// Checks a log against the keys a client trusts and returns what to pin.
///
/// Every record must carry valid signatures from at least `threshold`
/// distinct keys of `signer_keys`. Refused, with the index of the record at
/// fault:
///
/// * a signature that does not verify, whoever it claims to be from;
/// * fewer than `threshold` signatures from listed keys;
/// * a record that does not name the hash of the one before it, or a first
///   record that names anything but the all-zero hash;
/// * a change of cluster name;
/// * an epoch earlier than the previous record's;
/// * a second record for an epoch with a different set.
///
/// A repeated epoch with the same set is fine, and so is a new shred
/// version: that is what a cluster restart looks like.
///
/// What this cannot see is a log that was cut short: the first records of a
/// valid log are a valid log. Keep [`VerifiedLog::head`] to notice.
pub fn verify(
    records: &[SignedRecord],
    signer_keys: &[SignerKey],
    threshold: usize,
) -> Result<VerifiedLog> {
    let listed: BTreeSet<&SignerKey> = signer_keys.iter().collect();
    if listed.len() != signer_keys.len() {
        return Err(Error::DuplicateSignerKey);
    }
    if threshold == 0 || threshold > listed.len() {
        return Err(Error::InvalidThreshold);
    }
    walk(records, |index, signed| {
        let have = signed
            .signatures()
            .iter()
            .filter(|s| listed.contains(&s.signer))
            .count();
        if have < threshold {
            return Err(Error::TooFewSignatures {
                index,
                have,
                need: threshold,
            });
        }
        Ok(())
    })
}

/// Checks everything [`verify`] checks except who signed, and returns the
/// hash of the last record.
///
/// For tools that extend a log. It returns no pins on purpose: a log that
/// passes this may be signed by nobody you trust, or by nobody at all.
pub fn check_links(records: &[SignedRecord]) -> Result<Hash> {
    walk(records, |_, _| Ok(())).map(|log| *log.head())
}

fn walk(
    records: &[SignedRecord],
    mut signed_by_enough: impl FnMut(usize, &SignedRecord) -> Result<()>,
) -> Result<VerifiedLog> {
    let first = records.first().ok_or(Error::EmptyLog)?;
    let cluster = first.record().cluster();
    let mut prev = [0u8; 32];
    let mut last_epoch = 0;
    let mut hashes = Vec::with_capacity(records.len());
    let mut pins: BTreeMap<u64, Pin> = BTreeMap::new();
    for (index, signed) in records.iter().enumerate() {
        let record = signed.record();
        if record.prev() != &prev {
            return Err(Error::BrokenLink { index });
        }
        if !signed.signatures_valid() {
            return Err(Error::InvalidSignature { index });
        }
        signed_by_enough(index, signed)?;
        if record.cluster() != cluster {
            return Err(Error::ClusterChanged { index });
        }
        if record.epoch() < last_epoch {
            return Err(Error::EpochWentBackward { index });
        }
        let pin = Pin {
            set_hash: *record.set_hash(),
            validators: record.validators(),
            shred_version: record.shred_version(),
        };
        if let Some(earlier) = pins.insert(record.epoch(), pin) {
            if (earlier.set_hash, earlier.validators) != (pin.set_hash, pin.validators) {
                return Err(Error::ConflictingSet {
                    index,
                    epoch: record.epoch(),
                });
            }
        }
        last_epoch = record.epoch();
        prev = record.hash();
        hashes.push(prev);
    }
    Ok(VerifiedLog {
        cluster: cluster.to_string(),
        hashes,
        pins,
    })
}

/// Reads a log file: one record per line, every line ended by a line feed.
///
/// Each line must be exactly what [`SignedRecord::to_json`] writes. A line
/// that is not is [`Error::InvalidRecord`] with its index; a file that does
/// not end in a line feed was cut short.
pub fn parse(text: &str) -> Result<Vec<SignedRecord>> {
    let mut records = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let index = records.len();
        let at = |error| Error::InvalidRecord {
            index,
            error: Box::new(error),
        };
        let (line, after) = rest.split_once('\n').ok_or_else(|| at(Error::Truncated))?;
        records.push(SignedRecord::from_json(line).map_err(at)?);
        rest = after;
    }
    Ok(records)
}

/// Writes a log file: the inverse of [`parse`].
pub fn to_text(records: &[SignedRecord]) -> String {
    records
        .iter()
        .map(|record| record.to_json() + "\n")
        .collect()
}
