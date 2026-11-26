//! The one error type this crate returns.

use core::fmt;

/// Why a record, a log or a set file was refused.
///
/// Every variant means "do not pin from this". `index` counts records from
/// zero, in the order they stand in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ---- encoding ----
    /// A field holds a value the format does not allow.
    InvalidField(&'static str),
    /// The bytes ended before the record did, or a log file before its last
    /// line did.
    Truncated,
    /// Bytes were left over after the record ended.
    TrailingBytes,
    /// The bytes do not start with this format's domain prefix.
    WrongDomain,
    /// The text is not JSON of the expected shape.
    Json(String),
    /// The text parses, but it is not byte for byte what this crate writes.
    /// A log has one spelling, so a changed byte is never read as the same
    /// record.
    NotCanonical,
    /// Bytes that are not an Ed25519 key this crate will use.
    InvalidKey,
    /// Line `index` of a log file is not a record; `error` says why.
    InvalidRecord {
        /// The line, counted from zero.
        index: usize,
        /// What is wrong with it.
        error: Box<Error>,
    },

    // ---- signatures ----
    /// A signature in record `index` does not verify.
    InvalidSignature {
        /// The record that carries it.
        index: usize,
    },
    /// Record `index` has fewer valid signatures from the listed keys than
    /// the threshold.
    TooFewSignatures {
        /// The record that fell short.
        index: usize,
        /// Signatures it has from distinct listed keys.
        have: usize,
        /// Signatures asked for.
        need: usize,
    },
    /// The threshold is zero or larger than the number of signer keys.
    InvalidThreshold,
    /// The same signer key was listed twice.
    DuplicateSignerKey,

    // ---- the chain ----
    /// The log holds no records.
    EmptyLog,
    /// Record `index` does not name the hash of the record before it (or, for
    /// the first record, the all-zero hash).
    BrokenLink {
        /// The record whose link is wrong.
        index: usize,
    },
    /// Record `index` names a different cluster from the records before it.
    ClusterChanged {
        /// The record that changed it.
        index: usize,
    },
    /// Record `index` is for an earlier epoch than the record before it.
    EpochWentBackward {
        /// The record that went back.
        index: usize,
    },
    /// Record `index` gives `epoch` a different set from an earlier record.
    ConflictingSet {
        /// The record that conflicts.
        index: usize,
        /// The epoch the two records disagree about.
        epoch: u64,
    },

    // ---- agreement between sources ----
    /// Nothing was given to compare.
    NoInputs,
    /// The inputs are not about the same thing; names what differs.
    MixedInputs(&'static str),
    /// The sources do not all give the same set.
    SourcesDisagree,
    /// Fewer distinct sources agree than the quorum asks for.
    BelowQuorum {
        /// Distinct sources that agree.
        have: usize,
        /// Sources asked for.
        need: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid {field}"),
            Self::Truncated => write!(f, "the record is cut short"),
            Self::TrailingBytes => write!(f, "bytes left over after the record"),
            Self::WrongDomain => write!(f, "not a set record: wrong domain prefix"),
            Self::Json(why) => write!(f, "not valid JSON for this format: {why}"),
            Self::NotCanonical => write!(f, "not in the one spelling this format has"),
            Self::InvalidKey => write!(f, "not a usable Ed25519 key"),
            Self::InvalidRecord { index, error } => write!(f, "record {index}: {error}"),
            Self::InvalidSignature { index } => {
                write!(f, "record {index}: a signature does not verify")
            }
            Self::TooFewSignatures { index, have, need } => write!(
                f,
                "record {index}: {have} valid signatures from the listed keys, {need} needed"
            ),
            Self::InvalidThreshold => write!(
                f,
                "the threshold must be at least one and at most the number of signer keys"
            ),
            Self::DuplicateSignerKey => write!(f, "a signer key is listed twice"),
            Self::EmptyLog => write!(f, "the log is empty"),
            Self::BrokenLink { index } => {
                write!(f, "record {index}: does not link to the record before it")
            }
            Self::ClusterChanged { index } => {
                write!(f, "record {index}: names a different cluster")
            }
            Self::EpochWentBackward { index } => {
                write!(
                    f,
                    "record {index}: its epoch is before the previous record's"
                )
            }
            Self::ConflictingSet { index, epoch } => write!(
                f,
                "record {index}: a different validator set for epoch {epoch} than an earlier record"
            ),
            Self::NoInputs => write!(f, "nothing to compare"),
            Self::MixedInputs(what) => write!(f, "the inputs differ in {what}"),
            Self::SourcesDisagree => write!(f, "the sources do not agree on the set"),
            Self::BelowQuorum { have, need } => {
                write!(f, "{have} distinct sources agree, {need} needed")
            }
        }
    }
}

impl std::error::Error for Error {}

/// `Result` with this crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
