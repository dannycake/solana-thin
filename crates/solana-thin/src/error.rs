//! The one error type every check in this crate returns.

use core::fmt;

/// Why a proof, certificate or validator set was rejected.
///
/// Every variant means "do not trust this". None of them is recoverable by
/// retrying the same bytes. Variants are grouped by the layer that failed so
/// that a caller can tell a hostile proof from a merely unlucky one (for
/// example [`Error::UpdateParentBlock`], where the block is fine but this
/// version cannot prove inclusion in it).
///
/// There is one variant per refusal, and more arrive as the verifier gains
/// checks. To decide what to do next without naming them all, match on
/// [`Error::kind`].
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
    /// A proof built in memory holds more of something than the format's
    /// one- or two-byte counts can say. It was not encoded.
    TooLargeToEncode(&'static str),

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
    /// A different validator set is already pinned for this epoch. A pinned
    /// set is never replaced; forget it first if that is really intended.
    EpochAlreadyPinned(u64),
    /// Total stake does not fit in 64 bits.
    StakeOverflow,
    /// No trusted validator set is known for the epoch this certificate is in.
    UnknownEpoch(u64),
    /// The slot is before the first slot this client's epoch schedule covers.
    SlotBeforeSchedule,
    /// The cluster parameters describe an epoch schedule no cluster can have,
    /// so there is no telling which epoch a slot is in.
    InvalidClusterParams(&'static str),

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
    /// The claim names a transaction (or a footer) in the abandoned prefix of
    /// a block that switched parent, before the shred where execution resumed.
    /// The block is final and its executed suffix can be proven; this part of
    /// it never ran. Only returned with the `fast-leader-handover` feature,
    /// which is what makes the suffix provable at all.
    AbandonedPrefix,
    /// The block switched parent part way through. Without the
    /// `fast-leader-handover` feature this version refuses to prove inclusion
    /// in such a block at all. With the feature it is returned when the switch
    /// itself cannot be validated from the proof (no marker opened, a marker
    /// that does not name the block's parent, a switch that is not first in a
    /// leader window, or more than one marker).
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

/// What an [`Error`] means for the caller: the few cases an app acts on
/// differently, where [`Error`] has one variant per check.
///
/// The kinds are meant to outlast the variants. A new check adds a variant
/// to [`Error`] and files it under a kind that is already here, so code that
/// matches on kinds keeps saying the right thing. None of them makes the
/// same bytes worth trying again.
///
/// | Kind | What it means for an app | Variants of [`Error`] |
/// |---|---|---|
/// | [`Malformed`](Self::Malformed) | The bytes are not a proof or a validator set at all: cut short, padded, or holding a value the format does not allow. Whoever sent them is broken or hostile. Ask another source. | `Truncated`, `TrailingBytes`, `Malformed` |
/// | [`Unsupported`](Self::Unsupported) | The input is in a format this build does not read: a newer proof version, or a block holding a transaction encoding it cannot walk. A newer version of this library may read it. Not a sign of an attack. | `UnsupportedVersion`, `UnsupportedTransaction` |
/// | [`LimitExceeded`](Self::LimitExceeded) | Something is larger than this client allows, or than the format can say. Nothing was checked. If the input is legitimate, raise [`Limits`](crate::Limits). | `LimitExceeded`, `TooLargeToEncode` |
/// | [`InvalidValidatorSet`](Self::InvalidValidatorSet) | The validator set offered was refused: it is not the set the pinned hash names, or it breaks a rule every real set keeps. Nothing was pinned. Fetch the set from another source; if every source gives the same bytes, the hash is the wrong one. | `InvalidPublicKey`, `ZeroStake`, `EmptyValidatorSet`, `DuplicateValidator`, `UnsortedValidatorSet`, `ValidatorSetHashMismatch`, `StakeOverflow` |
/// | [`EpochNotPinned`](Self::EpochNotPinned) | The client holds no validator set that can judge this certificate: none is pinned for its epoch, or its slot is in a warm-up epoch the schedule does not cover. The proof may well be good. Pin that epoch's set and check it again. | `UnknownEpoch`, `SlotBeforeSchedule` |
/// | [`CertificateRejected`](Self::CertificateRejected) | The certificate does not show that the pinned validators finalized the block: its signature does not verify for the signers it names, or they hold too little stake. The cluster, the set or the certificate is the wrong one. Treat the block as not final. | `InvalidBitmap`, `RankOutOfRange`, `NoSigners`, `InvalidSignature`, `SignatureMismatch`, `InsufficientStake` |
/// | [`ProofRejected`](Self::ProofRejected) | The proof does not tie a transaction to the certified block: its shreds do not hash to the block id, do not chain back to it, or do not hold a transaction where the proof says (`AbandonedPrefix`: it holds one, but in a part of a switched block that never ran). From [`ThinClient::verify_transaction`](crate::ThinClient::verify_transaction) this comes after the certificate verified, so the block may be final; the transaction is not shown to be in it. | `InvalidMerkleProof`, `BlockIdMismatch`, `InvalidShred`, `MissingShred`, `DuplicateShred`, `NotComponentStart`, `InvalidComponent`, `AbandonedPrefix`, `TransactionNotFound`, `BrokenAncestry`, `InvalidParent` |
/// | [`WrongTransaction`](Self::WrongTransaction) | The proof is sound, but for another transaction than the one asked for. (From the prover: the block does not hold that transaction.) Nothing is known about the one asked for. | `SignatureNotFound` |
/// | [`UnprovableBlock`](Self::UnprovableBlock) | The block is final, but of a kind this version refuses to prove anything in, because part of it may never have run. No proof for that block will pass. Not a sign of an attack, and not a statement about the transaction. | `UpdateParentBlock`, `ZeroParentId` |
/// | [`InvalidParameters`](Self::InvalidParameters) | The call is wrong whatever the proof says: cluster parameters no cluster has, or a second, different set for an epoch that already has one. A bug in the caller, or two sources of trust that disagree. | `EpochAlreadyPinned`, `InvalidClusterParams` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The bytes do not decode.
    Malformed,
    /// A format this build does not read.
    Unsupported,
    /// Larger than a limit allows.
    LimitExceeded,
    /// The validator set is not the pinned one, or not a valid set.
    InvalidValidatorSet,
    /// No validator set is pinned that can judge the certificate.
    EpochNotPinned,
    /// The certificate does not carry the signature or the stake.
    CertificateRejected,
    /// The proof does not belong to the certified block.
    ProofRejected,
    /// A sound proof of a transaction other than the one asked for.
    WrongTransaction,
    /// A final block this version refuses to prove anything in.
    UnprovableBlock,
    /// The caller's own parameters are wrong.
    InvalidParameters,
}

impl ErrorKind {
    /// Every kind there is today, in the order of the table. For code that
    /// mirrors the kinds where a `match` cannot hold it to them, such as a
    /// binding for another language, so that it can test it has them all.
    pub const ALL: &'static [ErrorKind] = &[
        ErrorKind::Malformed,
        ErrorKind::Unsupported,
        ErrorKind::LimitExceeded,
        ErrorKind::InvalidValidatorSet,
        ErrorKind::EpochNotPinned,
        ErrorKind::CertificateRejected,
        ErrorKind::ProofRejected,
        ErrorKind::WrongTransaction,
        ErrorKind::UnprovableBlock,
        ErrorKind::InvalidParameters,
    ];
}

impl Error {
    /// What this error means for the caller. See the table on [`ErrorKind`].
    pub fn kind(&self) -> ErrorKind {
        // No wildcard arm: a new variant does not compile until it has a kind.
        match self {
            Error::Truncated | Error::TrailingBytes | Error::Malformed(_) => ErrorKind::Malformed,
            Error::UnsupportedVersion(_) | Error::UnsupportedTransaction => ErrorKind::Unsupported,
            Error::LimitExceeded(_) | Error::TooLargeToEncode(_) => ErrorKind::LimitExceeded,
            Error::InvalidPublicKey
            | Error::ZeroStake
            | Error::EmptyValidatorSet
            | Error::DuplicateValidator
            | Error::UnsortedValidatorSet
            | Error::ValidatorSetHashMismatch
            | Error::StakeOverflow => ErrorKind::InvalidValidatorSet,
            Error::UnknownEpoch(_) | Error::SlotBeforeSchedule => ErrorKind::EpochNotPinned,
            Error::InvalidBitmap
            | Error::RankOutOfRange
            | Error::NoSigners
            | Error::InvalidSignature
            | Error::SignatureMismatch
            | Error::InsufficientStake { .. } => ErrorKind::CertificateRejected,
            Error::InvalidMerkleProof
            | Error::BlockIdMismatch
            | Error::InvalidShred(_)
            | Error::MissingShred(_)
            | Error::DuplicateShred
            | Error::NotComponentStart
            | Error::InvalidComponent(_)
            | Error::AbandonedPrefix
            | Error::TransactionNotFound
            | Error::BrokenAncestry
            | Error::InvalidParent => ErrorKind::ProofRejected,
            Error::SignatureNotFound => ErrorKind::WrongTransaction,
            Error::UpdateParentBlock | Error::ZeroParentId => ErrorKind::UnprovableBlock,
            Error::EpochAlreadyPinned(_) | Error::InvalidClusterParams(_) => {
                ErrorKind::InvalidParameters
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "input ended early"),
            Error::TrailingBytes => write!(f, "unexpected bytes after the end"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported proof format version {v}"),
            Error::LimitExceeded(what) => write!(f, "{what} exceeds the allowed limit"),
            Error::Malformed(what) => write!(f, "malformed {what}"),
            Error::TooLargeToEncode(what) => {
                write!(f, "{what} is too large for the proof format")
            }
            Error::InvalidPublicKey => write!(f, "invalid BLS public key"),
            Error::ZeroStake => write!(f, "validator with zero stake"),
            Error::EmptyValidatorSet => write!(f, "validator set is empty"),
            Error::DuplicateValidator => write!(f, "duplicate validator key"),
            Error::UnsortedValidatorSet => write!(f, "validator set is not in rank order"),
            Error::ValidatorSetHashMismatch => {
                write!(f, "validator set does not match the pinned hash")
            }
            Error::EpochAlreadyPinned(e) => {
                write!(
                    f,
                    "a different validator set is already pinned for epoch {e}"
                )
            }
            Error::StakeOverflow => write!(f, "total stake overflows"),
            Error::UnknownEpoch(e) => write!(f, "no trusted validator set for epoch {e}"),
            Error::SlotBeforeSchedule => write!(f, "slot is before the epoch schedule starts"),
            Error::InvalidClusterParams(what) => {
                write!(f, "cluster parameters are not valid: {what}")
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
            Error::InvalidMerkleProof => write!(f, "invalid Merkle proof"),
            Error::BlockIdMismatch => write!(f, "data does not belong to the certified block"),
            Error::InvalidShred(what) => write!(f, "invalid shred: {what}"),
            Error::MissingShred(i) => write!(f, "proof is missing shred {i}"),
            Error::DuplicateShred => write!(f, "shred supplied twice"),
            Error::NotComponentStart => write!(f, "claimed component start is not a boundary"),
            Error::InvalidComponent(what) => write!(f, "invalid block component: {what}"),
            Error::AbandonedPrefix => write!(
                f,
                "the claim is in the abandoned prefix of a block that switched parent"
            ),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// One value of every variant of [`Error`].
    fn every_error() -> Vec<Error> {
        vec![
            Error::Truncated,
            Error::TrailingBytes,
            Error::UnsupportedVersion(9),
            Error::LimitExceeded("x"),
            Error::Malformed("x"),
            Error::TooLargeToEncode("x"),
            Error::InvalidPublicKey,
            Error::ZeroStake,
            Error::EmptyValidatorSet,
            Error::DuplicateValidator,
            Error::UnsortedValidatorSet,
            Error::ValidatorSetHashMismatch,
            Error::EpochAlreadyPinned(1),
            Error::StakeOverflow,
            Error::UnknownEpoch(1),
            Error::SlotBeforeSchedule,
            Error::InvalidClusterParams("x"),
            Error::InvalidBitmap,
            Error::RankOutOfRange,
            Error::NoSigners,
            Error::InvalidSignature,
            Error::SignatureMismatch,
            Error::InsufficientStake {
                signed: 1,
                total: 2,
                required_bps: 8_000,
            },
            Error::InvalidMerkleProof,
            Error::BlockIdMismatch,
            Error::InvalidShred("x"),
            Error::MissingShred(0),
            Error::DuplicateShred,
            Error::NotComponentStart,
            Error::InvalidComponent("x"),
            Error::AbandonedPrefix,
            Error::UpdateParentBlock,
            Error::ZeroParentId,
            Error::UnsupportedTransaction,
            Error::TransactionNotFound,
            Error::SignatureNotFound,
            Error::BrokenAncestry,
            Error::InvalidParent,
        ]
    }

    /// The first identifier in `text`.
    fn leading_name(text: &str) -> &str {
        let end = text
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(text.len());
        &text[..end]
    }

    /// The variants an enum in this file declares, read from its source so
    /// that the list cannot fall behind the enum.
    fn declared(name: &str) -> Vec<&'static str> {
        let source = include_str!("error.rs");
        let (_, rest) = source
            .split_once(&format!("pub enum {name} {{\n"))
            .expect("the enum is in this file");
        let (body, _) = rest.split_once("\n}").unwrap();
        body.lines()
            .filter_map(|line| line.strip_prefix("    "))
            .filter(|line| line.starts_with(|c: char| c.is_ascii_uppercase()))
            .map(leading_name)
            .collect()
    }

    /// The table in the docs of [`ErrorKind`]: each kind with the variants
    /// its row names.
    fn documented() -> Vec<(&'static str, Vec<&'static str>)> {
        include_str!("error.rs")
            .lines()
            .filter_map(|line| line.strip_prefix("/// | [`"))
            .map(|row| {
                let variants = row.trim_end_matches(" |").rsplit('|').next().unwrap();
                let variants = variants.split('`').skip(1).step_by(2).collect();
                (leading_name(row), variants)
            })
            .collect()
    }

    fn sorted<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        let mut names: Vec<_> = names.into_iter().collect();
        names.sort_unstable();
        names
    }

    /// A new variant needs an arm in `kind`, or the crate does not compile.
    /// It then needs a row in the table and a value above, or this fails.
    #[test]
    fn every_variant_has_the_one_kind_its_table_row_says() {
        let table = documented();
        let kinds: Vec<_> = table.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(kinds, declared("ErrorKind"), "one row per kind, in order");
        let all: Vec<_> = ErrorKind::ALL.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(all, kinds, "ALL lists every kind");

        let variants = sorted(declared("Error"));
        assert_eq!(variants.len(), 38);
        let listed = table.iter().flat_map(|(_, row)| row.iter().copied());
        assert_eq!(sorted(listed), variants, "each variant in one row");

        let errors = every_error();
        let names: Vec<_> = errors.iter().map(|e| format!("{e:?}")).collect();
        assert_eq!(sorted(names.iter().map(|n| leading_name(n))), variants);
        for (error, name) in errors.iter().zip(&names) {
            let name = leading_name(name);
            let (kind, _) = table.iter().find(|(_, row)| row.contains(&name)).unwrap();
            assert_eq!(format!("{:?}", error.kind()), *kind, "{name}");
        }
    }

    /// The kinds an app is most likely to branch on, spelled out.
    #[test]
    fn kinds_say_what_a_caller_can_do() {
        assert_eq!(Error::Truncated.kind(), ErrorKind::Malformed);
        assert_eq!(Error::UnsupportedVersion(2).kind(), ErrorKind::Unsupported);
        assert_eq!(Error::LimitExceeded("x").kind(), ErrorKind::LimitExceeded);
        assert_eq!(
            Error::ValidatorSetHashMismatch.kind(),
            ErrorKind::InvalidValidatorSet
        );
        assert_eq!(Error::UnknownEpoch(7).kind(), ErrorKind::EpochNotPinned);
        assert_eq!(
            Error::SignatureMismatch.kind(),
            ErrorKind::CertificateRejected
        );
        assert_eq!(Error::BlockIdMismatch.kind(), ErrorKind::ProofRejected);
        assert_eq!(Error::SignatureNotFound.kind(), ErrorKind::WrongTransaction);
        assert_eq!(Error::ZeroParentId.kind(), ErrorKind::UnprovableBlock);
        assert_eq!(
            Error::EpochAlreadyPinned(7).kind(),
            ErrorKind::InvalidParameters
        );
    }
}
