//! The one error type every check in this crate returns.

use core::fmt;

/// Why a proof, certificate or validator set was rejected.
///
/// Every variant means "do not trust this". None of them is recoverable by
/// retrying the same bytes. Variants are grouped by the layer that failed so
/// that a caller can tell a hostile proof from a merely unlucky one (for
/// example [`Error::UpdateParentBlock`], where the block is fine but this
/// version cannot prove inclusion in it).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ---- encoding ----
    /// The bytes ended before the structure did.
    Truncated,
    /// Bytes were left over after the structure ended.
    TrailingBytes,
    /// The proof was written by a format version this build does not read.
    UnsupportedVersion(u8),
    /// A length or count is larger than this build will allocate for.
    LimitExceeded(&'static str),
    /// A field holds a value the format does not allow.
    Malformed(&'static str),

    // ---- validator set ----
    /// A BLS public key is not a valid point in the right subgroup.
    InvalidPublicKey,
    /// A validator was listed with zero stake.
    ZeroStake,
    /// The validator set is empty.
    EmptyValidatorSet,
    /// The same BLS key appears twice.
    DuplicateValidator,
    /// Validators are not in rank order (stake descending, then key bytes).
    UnsortedValidatorSet,
    /// The set's hash is not the one that was pinned.
    ValidatorSetHashMismatch,
    /// Total stake does not fit in 64 bits.
    StakeOverflow,
    /// No trusted validator set is known for the epoch this certificate is in.
    UnknownEpoch(u64),
    /// The slot is before the first slot this client's epoch schedule covers.
    SlotBeforeSchedule,
    /// A signer that is not in the trusted set came without a valid proof of
    /// possession.
    MissingProofOfPossession,

    // ---- certificate ----
    /// The signer bitmap is not a valid single-vector (base 2) encoding.
    InvalidBitmap,
    /// The bitmap names a rank that is not in the validator set.
    RankOutOfRange,
    /// The bitmap names no signers at all.
    NoSigners,
    /// The aggregate signature is not a valid curve point.
    InvalidSignature,
    /// The aggregate signature does not verify for the named signers.
    SignatureMismatch,
    /// The signers hold less stake than this kind of certificate needs.
    InsufficientStake {
        /// Stake held by the signers.
        signed: u64,
        /// Total stake in the set.
        total: u64,
        /// Required share, in basis points.
        required_bps: u32,
    },
    /// The certificate is for an epoch too far past the trusted set.
    TooStale,

    // ---- block structure ----
    /// A Merkle path or multiproof does not have the shape the tree requires.
    InvalidMerkleProof,
    /// The proven data does not hash up to the certified block id.
    BlockIdMismatch,
    /// A shred has an unknown variant, a bad size, or sits at the wrong index.
    InvalidShred(&'static str),
    /// The proof does not contain a shred the verifier needs.
    MissingShred(u32),
    /// The same FEC set or shred was supplied twice.
    DuplicateShred,
    /// The claimed start of a block component is not a real boundary.
    NotComponentStart,
    /// The component bytes are not what the claim says they are.
    InvalidComponent(&'static str),
    /// The block switched parent part way through, so part of it was never
    /// executed. This version refuses to prove inclusion in such blocks.
    UpdateParentBlock,
    /// The block's parent id is all zeros. Validators do not record such a
    /// header as naming a parent, so they would not notice a later switch to
    /// the same parent, and part of the block may never have been executed.
    /// Only a block built directly on a cluster's first block looks like
    /// this; nothing in it can be proven.
    ZeroParentId,
    /// A transaction in the component uses an encoding this build cannot walk.
    UnsupportedTransaction,
    /// The component has no transaction at the claimed position.
    TransactionNotFound,
    /// The transaction's first signature is not the one that was asked for.
    SignatureNotFound,

    // ---- chain ----
    /// The ancestry chain does not connect the certified block to the block
    /// the transaction is in.
    BrokenAncestry,
    /// A block claims a parent that is not in an earlier slot.
    InvalidParent,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "input ended early"),
            Error::TrailingBytes => write!(f, "unexpected bytes after the end"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported proof format version {v}"),
            Error::LimitExceeded(what) => write!(f, "{what} exceeds the allowed limit"),
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::InvalidPublicKey => write!(f, "invalid BLS public key"),
            Error::ZeroStake => write!(f, "validator with zero stake"),
            Error::EmptyValidatorSet => write!(f, "validator set is empty"),
            Error::DuplicateValidator => write!(f, "duplicate validator key"),
            Error::UnsortedValidatorSet => write!(f, "validator set is not in rank order"),
            Error::ValidatorSetHashMismatch => {
                write!(f, "validator set does not match the pinned hash")
            }
            Error::StakeOverflow => write!(f, "total stake overflows"),
            Error::UnknownEpoch(e) => write!(f, "no trusted validator set for epoch {e}"),
            Error::SlotBeforeSchedule => write!(f, "slot is before the epoch schedule starts"),
            Error::MissingProofOfPossession => {
                write!(f, "unknown signer without a valid proof of possession")
            }
            Error::InvalidBitmap => write!(f, "invalid signer bitmap"),
            Error::RankOutOfRange => write!(f, "signer rank is outside the validator set"),
            Error::NoSigners => write!(f, "certificate names no signers"),
            Error::InvalidSignature => write!(f, "aggregate signature is not a valid point"),
            Error::SignatureMismatch => write!(f, "aggregate signature does not verify"),
            Error::InsufficientStake {
                signed,
                total,
                required_bps,
            } => write!(
                f,
                "signers hold {signed} of {total} stake, below the required {}.{:02}%",
                required_bps / 100,
                required_bps % 100
            ),
            Error::TooStale => write!(f, "certificate is too many epochs past the trusted set"),
            Error::InvalidMerkleProof => write!(f, "invalid Merkle proof"),
            Error::BlockIdMismatch => write!(f, "data does not belong to the certified block"),
            Error::InvalidShred(what) => write!(f, "invalid shred: {what}"),
            Error::MissingShred(i) => write!(f, "proof is missing shred {i}"),
            Error::DuplicateShred => write!(f, "shred supplied twice"),
            Error::NotComponentStart => write!(f, "claimed component start is not a boundary"),
            Error::InvalidComponent(what) => write!(f, "invalid block component: {what}"),
            Error::ZeroParentId => write!(
                f,
                "the block's parent id is all zeros; a parent switch cannot be ruled out"
            ),
            Error::UpdateParentBlock => {
                write!(
                    f,
                    "block switched parent mid-way; inclusion cannot be proven"
                )
            }
            Error::UnsupportedTransaction => write!(f, "unsupported transaction encoding"),
            Error::TransactionNotFound => write!(f, "no transaction at the claimed position"),
            Error::SignatureNotFound => write!(f, "transaction signature does not match"),
            Error::BrokenAncestry => write!(f, "ancestry chain is broken"),
            Error::InvalidParent => write!(f, "parent is not in an earlier slot"),
        }
    }
}

impl std::error::Error for Error {}

/// Shorthand for results in this crate.
pub type Result<T> = core::result::Result<T, Error>;
