//! One record: which validator set an epoch has, who looked, and what came
//! before.
//!
//! A record has two encodings. The *bytes* ([`Record::to_bytes`]) are what
//! gets hashed and signed. The *line* ([`SignedRecord::to_json`]) is how a
//! record and its signatures travel in a log. Both are canonical: a record
//! has exactly one of each, and anything else is refused on reading.

use crate::error::{Error, Result};
use crate::keys::{self, SignerKey, SigningKey};
use crate::Hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Starts the bytes of every record, so that a signature over a record can
/// never be taken for a signature over anything else.
pub const RECORD_DOMAIN: &[u8] = b"solana-thin/set-record/v1";
/// Longest cluster name and source kind, in bytes.
pub const MAX_NAME_LEN: usize = 32;
/// Longest source label, in bytes.
pub const MAX_LABEL_LEN: usize = 96;
/// Most sources one record names.
pub const MAX_SOURCES: usize = 32;

/// Source kind: the epoch-stakes map in a bank snapshot a node served.
pub const KIND_SNAPSHOT: &str = "snapshot";
/// Source kind: an RPC node's answer to `getVatActiveSetRankMap`.
pub const KIND_RANK_MAP: &str = "rank-map";

/// Where a set was read: one of the places that agreed on it.
///
/// A description for people, not evidence. Nothing in a source can be
/// checked later; it records what the signers say they looked at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    kind: String,
    label: String,
    slot: u64,
}

impl Source {
    /// A source of `kind` (lowercase letters, digits and `-`), named by
    /// `label` (printable ASCII without spaces), whose answer reflects the
    /// cluster at `slot`.
    pub fn new(kind: &str, label: &str, slot: u64) -> Result<Self> {
        if !is_name(kind) {
            return Err(Error::InvalidField("source kind"));
        }
        let printable = label.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if label.is_empty() || label.len() > MAX_LABEL_LEN || !printable {
            return Err(Error::InvalidField("source label"));
        }
        Ok(Self {
            kind: kind.to_string(),
            label: label.to_string(),
            slot,
        })
    }

    /// What kind of source this is, such as [`KIND_SNAPSHOT`].
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Which one: a node identity, a host name.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The slot its answer reflects.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Whether two sources are the same place, whatever slot each was read at.
    pub(crate) fn same_place(&self, other: &Self) -> bool {
        self.kind == other.kind && self.label == other.label
    }
}

/// Lowercase letters, digits and `-`, one to [`MAX_NAME_LEN`] bytes.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Sorts sources into the order records keep them in and refuses a place
/// listed twice.
pub(crate) fn canonical_sources(mut sources: Vec<Source>) -> Result<Vec<Source>> {
    if sources.is_empty() || sources.len() > MAX_SOURCES {
        return Err(Error::InvalidField("sources"));
    }
    sources.sort();
    if sources.windows(2).any(|pair| pair[0].same_place(&pair[1])) {
        return Err(Error::InvalidField("sources"));
    }
    Ok(sources)
}

/// The statement a signer makes: on this cluster, this epoch's ranked
/// validator set has this hash.
///
/// Fields cannot be set to values the format does not allow, so every
/// `Record` has bytes and a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    cluster: String,
    shred_version: u16,
    epoch: u64,
    set_hash: Hash,
    validators: u32,
    sources: Vec<Source>,
    prev: Hash,
}

impl Record {
    /// Builds a record.
    ///
    /// `cluster` is lowercase letters, digits and `-`. `set_hash` is
    /// `ValidatorSet::hash` of the set certificates in `epoch` are checked
    /// against, and `validators` its length. `sources` is one to
    /// [`MAX_SOURCES`] distinct places; they are kept sorted. `prev` is the
    /// [`hash`](Self::hash) of the record before this one, or all zeros for
    /// the first record of a log.
    pub fn new(
        cluster: &str,
        shred_version: u16,
        epoch: u64,
        set_hash: Hash,
        validators: u32,
        sources: Vec<Source>,
        prev: Hash,
    ) -> Result<Self> {
        if !is_name(cluster) {
            return Err(Error::InvalidField("cluster"));
        }
        if validators == 0 {
            return Err(Error::InvalidField("validators"));
        }
        Ok(Self {
            cluster: cluster.to_string(),
            shred_version,
            epoch,
            set_hash,
            validators,
            sources: canonical_sources(sources)?,
            prev,
        })
    }

    /// The cluster's name, such as `mainnet-beta`.
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// The cluster's shred version when the record was made. A restart
    /// changes it, and shows in a log as a record with a new one.
    pub fn shred_version(&self) -> u16 {
        self.shred_version
    }

    /// The epoch whose certificates the set verifies.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The hash to pin.
    pub fn set_hash(&self) -> &Hash {
        &self.set_hash
    }

    /// How many validators the set ranks.
    pub fn validators(&self) -> u32 {
        self.validators
    }

    /// The places that gave this set, sorted.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// Hash of the record before this one; all zeros in a log's first record.
    pub fn prev(&self) -> &Hash {
        &self.prev
    }

    /// The bytes that are hashed and signed.
    ///
    /// ```text
    /// "solana-thin/set-record/v1"                   25 bytes
    /// cluster      len:u8, bytes
    /// shred version    u16
    /// epoch            u64
    /// set hash         32 bytes
    /// validators       u32
    /// prev             32 bytes
    /// sources      count:u8, then per source:
    ///     kind     len:u8, bytes
    ///     label    len:u8, bytes
    ///     slot         u64
    /// ```
    ///
    /// Integers are little-endian. Sources are in ascending order of kind,
    /// then label.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.sources.len() * 64);
        out.extend_from_slice(RECORD_DOMAIN);
        put_text(&mut out, &self.cluster);
        out.extend_from_slice(&self.shred_version.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.set_hash);
        out.extend_from_slice(&self.validators.to_le_bytes());
        out.extend_from_slice(&self.prev);
        // The constructors keep every length under 256.
        out.push(self.sources.len() as u8);
        for source in &self.sources {
            put_text(&mut out, &source.kind);
            put_text(&mut out, &source.label);
            out.extend_from_slice(&source.slot.to_le_bytes());
        }
        out
    }

    /// Reads the output of [`to_bytes`](Self::to_bytes) and nothing else:
    /// every rule of [`new`](Self::new) is checked again, and sources out of
    /// order are refused, so bytes this accepts are the bytes `to_bytes`
    /// writes for the record it returns.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(RECORD_DOMAIN.len()).ok() != Some(RECORD_DOMAIN) {
            return Err(Error::WrongDomain);
        }
        let cluster = r.text()?;
        let shred_version = u16::from_le_bytes(r.array()?);
        let epoch = u64::from_le_bytes(r.array()?);
        let set_hash = r.array()?;
        let validators = u32::from_le_bytes(r.array()?);
        let prev = r.array()?;
        let count = r.take(1)?[0] as usize;
        let mut sources = Vec::with_capacity(count.min(MAX_SOURCES));
        for _ in 0..count {
            let kind = r.text()?;
            let label = r.text()?;
            let slot = u64::from_le_bytes(r.array()?);
            sources.push(Source::new(kind, label, slot)?);
        }
        if !r.0.is_empty() {
            return Err(Error::TrailingBytes);
        }
        let record = Self::new(
            cluster,
            shred_version,
            epoch,
            set_hash,
            validators,
            sources.clone(),
            prev,
        )?;
        if record.sources != sources {
            return Err(Error::InvalidField("sources"));
        }
        Ok(record)
    }

    /// SHA-256 of [`to_bytes`](Self::to_bytes): what the next record's `prev`
    /// names. It does not cover signatures, so adding one changes no link.
    pub fn hash(&self) -> Hash {
        Sha256::digest(self.to_bytes()).into()
    }
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    out.push(text.len() as u8);
    out.extend_from_slice(text.as_bytes());
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("take returns N bytes"))
    }

    fn text(&mut self) -> Result<&'a str> {
        let len = self.take(1)?[0] as usize;
        core::str::from_utf8(self.take(len)?).map_err(|_| Error::InvalidField("text"))
    }
}

/// One signer's signature over a record's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSignature {
    /// The signer's Ed25519 public key.
    pub signer: SignerKey,
    /// Its signature over [`Record::to_bytes`].
    pub signature: [u8; 64],
}

impl RecordSignature {
    /// Whether this is the named signer's signature over `record`.
    pub fn verifies(&self, record: &Record) -> bool {
        keys::verify(&self.signer, &record.to_bytes(), &self.signature)
    }
}

/// A record with the signatures collected for it so far: a line of a log.
///
/// Holding one says nothing about whether its signatures are good or whose
/// they are. [`verify`](crate::verify) decides that for a whole log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    record: Record,
    /// In ascending order of signer key, one per signer.
    signatures: Vec<RecordSignature>,
}

impl SignedRecord {
    /// A record nobody has signed yet: a candidate.
    pub fn unsigned(record: Record) -> Self {
        Self {
            record,
            signatures: Vec::new(),
        }
    }

    /// The record.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// The signatures, in ascending order of signer key.
    pub fn signatures(&self) -> &[RecordSignature] {
        &self.signatures
    }

    /// Adds `key`'s signature. Signing again with the same key changes
    /// nothing.
    pub fn sign(&mut self, key: &SigningKey) {
        let signer = key.public_key();
        let signature = RecordSignature {
            signer,
            signature: key.sign(&self.record.to_bytes()),
        };
        match self.signatures.binary_search_by(|s| s.signer.cmp(&signer)) {
            Ok(at) => self.signatures[at] = signature,
            Err(at) => self.signatures.insert(at, signature),
        }
    }

    /// Whether every signature carried verifies under the key it names.
    pub fn signatures_valid(&self) -> bool {
        let message = self.record.to_bytes();
        self.signatures
            .iter()
            .all(|s| keys::verify(&s.signer, &message, &s.signature))
    }

    /// The record as one line of JSON, without a line ending.
    pub fn to_json(&self) -> String {
        let wire = WireRecord {
            cluster: self.record.cluster.clone(),
            shred_version: self.record.shred_version,
            epoch: self.record.epoch,
            set_hash: hex::encode(self.record.set_hash),
            validators: self.record.validators,
            sources: self.record.sources.iter().map(WireSource::from).collect(),
            prev: hex::encode(self.record.prev),
            signatures: self
                .signatures
                .iter()
                .map(|s| WireSignature {
                    signer: hex::encode(s.signer),
                    signature: hex::encode(s.signature),
                })
                .collect(),
        };
        serde_json::to_string(&wire).expect("strings and integers always serialize")
    }

    /// Reads a line written by [`to_json`](Self::to_json).
    ///
    /// The line has to be exactly what `to_json` writes for the record it
    /// describes: same field order, lowercase hex, no spaces, sources and
    /// signatures in order. So no byte of a line can change without the
    /// line being refused here or its signatures failing later.
    pub fn from_json(line: &str) -> Result<Self> {
        let wire: WireRecord =
            serde_json::from_str(line).map_err(|e| Error::Json(e.to_string()))?;
        let sources = wire
            .sources
            .iter()
            .map(Source::try_from)
            .collect::<Result<Vec<_>>>()?;
        let record = Record::new(
            &wire.cluster,
            wire.shred_version,
            wire.epoch,
            unhex(&wire.set_hash, "set_hash")?,
            wire.validators,
            sources,
            unhex(&wire.prev, "prev")?,
        )?;
        let signatures = wire
            .signatures
            .iter()
            .map(|s| {
                Ok(RecordSignature {
                    signer: unhex(&s.signer, "signer")?,
                    signature: unhex(&s.signature, "signature")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let ascending = signatures.windows(2).all(|s| s[0].signer < s[1].signer);
        let signed = Self { record, signatures };
        // Comparing with what would be written covers spelling, field order
        // and the order of sources. It cannot see signatures out of order,
        // since they would be written back the way they came.
        if !ascending || signed.to_json() != line {
            return Err(Error::NotCanonical);
        }
        Ok(signed)
    }
}

pub(crate) fn unhex<const N: usize>(text: &str, field: &'static str) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out).map_err(|_| Error::InvalidField(field))?;
    Ok(out)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireSource {
    kind: String,
    label: String,
    slot: u64,
}

impl From<&Source> for WireSource {
    fn from(source: &Source) -> Self {
        Self {
            kind: source.kind.clone(),
            label: source.label.clone(),
            slot: source.slot,
        }
    }
}

impl TryFrom<&WireSource> for Source {
    type Error = Error;

    fn try_from(wire: &WireSource) -> Result<Self> {
        Source::new(&wire.kind, &wire.label, wire.slot)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignature {
    signer: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    cluster: String,
    shred_version: u16,
    epoch: u64,
    set_hash: String,
    validators: u32,
    sources: Vec<WireSource>,
    prev: String,
    signatures: Vec<WireSignature>,
}
