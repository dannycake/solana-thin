//! A validator set on disk, with what it is the set of.
//!
//! The bytes of a set (`ValidatorSet::to_bytes` in the verifier) are keys and
//! stakes and nothing else: they do not say which cluster or epoch they
//! belong to. A set file carries that beside them, and the sources the bytes
//! were read from.

use crate::error::{Error, Result};
use crate::record::{canonical_sources, Record, Source, WireSource};
use crate::Hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `format` field of every set file.
pub const SET_FILE_FORMAT: &str = "solana-thin/set/v1";

/// Domain prefix of the verifier's set hash (`ValidatorSet::hash`).
const SET_HASH_DOMAIN: &[u8] = b"solana-thin/validator-set/v1";
/// Bytes one validator takes in an encoded set: a 48-byte key, a `u64` stake.
const ENCODED_VALIDATOR_SIZE: usize = 48 + 8;

/// A set's bytes, the cluster and epoch they are for, and where they came
/// from.
///
/// Nothing here is trusted. A client takes the hash to pin from a verified
/// log and hands these bytes to `ThinClient::trust_validator_set_bytes`,
/// which refuses them unless they hash to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetFile {
    cluster: String,
    shred_version: u16,
    epoch: u64,
    set_bytes: Vec<u8>,
    sources: Vec<Source>,
}

impl SetFile {
    /// Wraps `set_bytes`, the output of `ValidatorSet::to_bytes`, as the set
    /// for `epoch` of `cluster`, read from `sources`.
    ///
    /// Only the shape of the bytes is checked: a count and that many
    /// entries. Whether the keys are valid and ranked is for the verifier.
    pub fn new(
        cluster: &str,
        shred_version: u16,
        epoch: u64,
        set_bytes: Vec<u8>,
        sources: Vec<Source>,
    ) -> Result<Self> {
        let count = set_bytes
            .first_chunk::<4>()
            .map(|count| u32::from_le_bytes(*count) as usize)
            .ok_or(Error::InvalidField("set"))?;
        if count == 0 || set_bytes.len() - 4 != count.saturating_mul(ENCODED_VALIDATOR_SIZE) {
            return Err(Error::InvalidField("set"));
        }
        let file = Self {
            cluster: cluster.to_string(),
            shred_version,
            epoch,
            set_bytes,
            sources: canonical_sources(sources)?,
        };
        // Building the record checks the remaining fields.
        file.candidate([0; 32])?;
        Ok(file)
    }

    /// The cluster's name.
    pub fn cluster(&self) -> &str {
        &self.cluster
    }

    /// The cluster's shred version when the set was read.
    pub fn shred_version(&self) -> u16 {
        self.shred_version
    }

    /// The epoch whose certificates the set verifies.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The encoded set, for `ThinClient::trust_validator_set_bytes`.
    pub fn set_bytes(&self) -> &[u8] {
        &self.set_bytes
    }

    /// The places the set was read from, sorted.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// Number of validators the set ranks.
    pub fn validators(&self) -> u32 {
        // `new` checked the length against this count.
        (self.set_bytes.len() / ENCODED_VALIDATOR_SIZE) as u32
    }

    /// The hash of the set: what the verifier computes for these bytes and
    /// compares with the pinned hash.
    pub fn set_hash(&self) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(SET_HASH_DOMAIN);
        hasher.update(&self.set_bytes);
        hasher.finalize().into()
    }

    /// The record that says what this file says, linking to `prev`.
    pub fn candidate(&self, prev: Hash) -> Result<Record> {
        Record::new(
            &self.cluster,
            self.shred_version,
            self.epoch,
            self.set_hash(),
            self.validators(),
            self.sources.clone(),
            prev,
        )
    }

    /// Whether `record` is about this set: same cluster, shred version,
    /// epoch, hash and size. Sources and the link are not compared.
    pub fn supports(&self, record: &Record) -> bool {
        record.cluster() == self.cluster
            && record.shred_version() == self.shred_version
            && record.epoch() == self.epoch
            && record.set_hash() == &self.set_hash()
            && record.validators() == self.validators()
    }

    /// The file's text: one JSON object and a line feed.
    pub fn to_json(&self) -> String {
        let wire = WireSetFile {
            format: SET_FILE_FORMAT.to_string(),
            cluster: self.cluster.clone(),
            shred_version: self.shred_version,
            epoch: self.epoch,
            set_hash: hex::encode(self.set_hash()),
            validators: self.validators(),
            sources: self.sources.iter().map(WireSource::from).collect(),
            set: hex::encode(&self.set_bytes),
        };
        serde_json::to_string(&wire).expect("strings and integers always serialize") + "\n"
    }

    /// Reads a set file. The hash and count it states are for people; they
    /// are compared with the bytes and a file that misstates them is refused.
    pub fn from_json(text: &str) -> Result<Self> {
        let wire: WireSetFile =
            serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))?;
        if wire.format != SET_FILE_FORMAT {
            return Err(Error::InvalidField("format"));
        }
        let sources = wire
            .sources
            .iter()
            .map(Source::try_from)
            .collect::<Result<Vec<_>>>()?;
        let set_bytes = hex::decode(&wire.set).map_err(|_| Error::InvalidField("set"))?;
        let file = Self::new(
            &wire.cluster,
            wire.shred_version,
            wire.epoch,
            set_bytes,
            sources,
        )?;
        if wire.set_hash != hex::encode(file.set_hash()) {
            return Err(Error::InvalidField("set_hash"));
        }
        if wire.validators != file.validators() {
            return Err(Error::InvalidField("validators"));
        }
        Ok(file)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSetFile {
    format: String,
    cluster: String,
    shred_version: u16,
    epoch: u64,
    set_hash: String,
    validators: u32,
    sources: Vec<WireSource>,
    set: String,
}

/// Checks that set files read from different places describe one set, and
/// merges them.
///
/// All of `inputs` must be for the same cluster and epoch, and must give the
/// same set under the same shred version: one that differs is
/// [`Error::SourcesDisagree`], however many agree, because sources that are
/// each exact cannot differ. The places they name, counted once each, must
/// number at least `quorum`.
///
/// Returns the set with every source that gave it. What that is worth
/// depends on the sources being independent, which nothing here can check.
pub fn agree(inputs: &[SetFile], quorum: usize) -> Result<SetFile> {
    if quorum == 0 {
        return Err(Error::InvalidField("quorum"));
    }
    let first = inputs.first().ok_or(Error::NoInputs)?;
    let mut sources: Vec<Source> = Vec::new();
    for input in inputs {
        if input.cluster != first.cluster {
            return Err(Error::MixedInputs("cluster"));
        }
        if input.epoch != first.epoch {
            return Err(Error::MixedInputs("epoch"));
        }
        if input.shred_version != first.shred_version || input.set_bytes != first.set_bytes {
            return Err(Error::SourcesDisagree);
        }
        for source in &input.sources {
            match sources.iter_mut().find(|s| s.same_place(source)) {
                // One place read twice is one source; keep the later reading.
                Some(seen) => *seen = source.clone().max(seen.clone()),
                None => sources.push(source.clone()),
            }
        }
    }
    if sources.len() < quorum {
        return Err(Error::BelowQuorum {
            have: sources.len(),
            need: quorum,
        });
    }
    SetFile::new(
        &first.cluster,
        first.shred_version,
        first.epoch,
        first.set_bytes.clone(),
        sources,
    )
}
