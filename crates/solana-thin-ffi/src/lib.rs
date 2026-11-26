//! Kotlin and Swift bindings for [`solana_thin`], generated with UniFFI.
//!
//! The surface is small on purpose: a [`Verifier`] that is told which
//! validator sets to trust and then checks proofs, with bytes in and plain
//! records out. Everything a foreign caller sees is declared in this file;
//! `uniffi-bindgen` reads it from the compiled library.
//!
//! A verifier is meant to live as long as the app does. Pinning a validator
//! set checks every key in it, which takes tens of milliseconds; checking a
//! proof against a set that is already pinned takes about one.

use solana_thin::{ClusterParams, Error, ErrorKind, ThinClient, TxProof};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

uniffi::setup_scaffolding!();

/// How the validators finalized a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Finality {
    /// In one round: validators holding 80% of the stake signed the block.
    Fast,
    /// In two rounds: 60% signed the block and 60% signed to finalize its slot.
    Slow,
}

/// A transaction shown to be in a block the pinned validators finalized.
///
/// It says the transaction is in the block, in a part validators executed.
/// It does not say the transaction succeeded: one whose program returned an
/// error is in its block too.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VerifiedTransaction {
    /// Slot of the block the transaction is in.
    pub slot: u64,
    /// Id of that block, 32 bytes.
    pub block_id: Vec<u8>,
    /// Epoch of the validator set that vouched for it: the epoch of the
    /// block the finality certificate names, which is the transaction's
    /// block or a later one.
    pub epoch: u64,
    /// The transaction id: its first signature, 64 bytes.
    pub transaction_id: Vec<u8>,
    /// The leader's clock for the block, in nanoseconds since the Unix
    /// epoch. Absent when the proof does not open the block's footer.
    pub block_time_nanos: Option<u64>,
    /// How the block was finalized.
    pub finality: Finality,
    /// The data of each Memo instruction in the transaction, in order.
    pub memos: Vec<Vec<u8>>,
}

/// Why a call was refused. Every case means "do not trust this", and none is
/// worth retrying with the same bytes.
///
/// The cases are the kinds of `solana_thin::ErrorKind`, whose table says
/// what each means for an app. `detail` is the verifier's own sentence about
/// what failed. It is for logs and bug reports: its wording may change, so
/// do not match on it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum VerifyError {
    /// The bytes are not a proof or a validator set at all. Ask another
    /// source.
    Malformed {
        /// What failed, in words.
        detail: String,
    },
    /// The input is in a format this build does not read. A newer version
    /// of the library may.
    Unsupported {
        /// What failed, in words.
        detail: String,
    },
    /// Something is larger than the verifier allows. Nothing was checked.
    LimitExceeded {
        /// What failed, in words.
        detail: String,
    },
    /// The validator set is not the one the pinned hash names, or breaks a
    /// rule every real set keeps. Nothing was pinned.
    InvalidValidatorSet {
        /// What failed, in words.
        detail: String,
    },
    /// No validator set is pinned that can judge this proof. Pin the set of
    /// its epoch and check the proof again.
    EpochNotPinned {
        /// What failed, in words.
        detail: String,
        /// The epoch the proof needs a set for, as the proof claims it.
        /// Absent when no set could help, as for a slot in a warm-up epoch.
        epoch: Option<u64>,
    },
    /// The certificate does not show that the pinned validators finalized
    /// the block. Treat the block as not final.
    CertificateRejected {
        /// What failed, in words.
        detail: String,
    },
    /// The proof does not tie a transaction to the certified block.
    ProofRejected {
        /// What failed, in words.
        detail: String,
    },
    /// The proof is sound, but for another transaction than the one asked
    /// for.
    WrongTransaction {
        /// What failed, in words.
        detail: String,
    },
    /// The block is final, but of a kind this version refuses to prove
    /// anything in. No proof for that block will pass.
    UnprovableBlock {
        /// What failed, in words.
        detail: String,
    },
    /// The call itself is wrong: an argument of the wrong length, cluster
    /// parameters no cluster has, or a second, different set for an epoch
    /// that already has one.
    InvalidParameters {
        /// What failed, in words.
        detail: String,
    },
    /// A kind this binding has no case for. The verifier and the binding
    /// are released together, and a test holds this to never being made.
    Other {
        /// What failed, in words.
        detail: String,
    },
}

impl VerifyError {
    /// The case for `kind`. `epoch` is kept only where the case carries one.
    fn new(kind: ErrorKind, detail: String, epoch: Option<u64>) -> Self {
        match kind {
            ErrorKind::Malformed => Self::Malformed { detail },
            ErrorKind::Unsupported => Self::Unsupported { detail },
            ErrorKind::LimitExceeded => Self::LimitExceeded { detail },
            ErrorKind::InvalidValidatorSet => Self::InvalidValidatorSet { detail },
            ErrorKind::EpochNotPinned => Self::EpochNotPinned { detail, epoch },
            ErrorKind::CertificateRejected => Self::CertificateRejected { detail },
            ErrorKind::ProofRejected => Self::ProofRejected { detail },
            ErrorKind::WrongTransaction => Self::WrongTransaction { detail },
            ErrorKind::UnprovableBlock => Self::UnprovableBlock { detail },
            ErrorKind::InvalidParameters => Self::InvalidParameters { detail },
            // `ErrorKind` may grow, so the compiler asks for this arm.
            _ => Self::Other { detail },
        }
    }

    /// An argument that has the wrong shape before any checking begins.
    fn argument(what: &str, got: usize, want: usize) -> Self {
        Self::InvalidParameters {
            detail: format!("the {what} is {got} bytes, not {want}"),
        }
    }
}

impl From<Error> for VerifyError {
    fn from(error: Error) -> Self {
        let epoch = match error {
            Error::UnknownEpoch(epoch) => Some(epoch),
            _ => None,
        };
        Self::new(error.kind(), error.to_string(), epoch)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Malformed { detail }
        | Self::Unsupported { detail }
        | Self::LimitExceeded { detail }
        | Self::InvalidValidatorSet { detail }
        | Self::EpochNotPinned { detail, .. }
        | Self::CertificateRejected { detail }
        | Self::ProofRejected { detail }
        | Self::WrongTransaction { detail }
        | Self::UnprovableBlock { detail }
        | Self::InvalidParameters { detail }
        | Self::Other { detail }) = self;
        f.write_str(detail)
    }
}

impl std::error::Error for VerifyError {}

/// Bytes from a foreign caller as the fixed-size array the verifier takes.
fn sized<const N: usize>(what: &str, bytes: &[u8]) -> Result<[u8; N], VerifyError> {
    bytes
        .try_into()
        .map_err(|_| VerifyError::argument(what, bytes.len(), N))
}

/// Checks proofs against the validator sets it has been told to trust.
///
/// A verifier is made for one cluster, trusts nothing at first, keeps no
/// chain state and makes no network calls. It can be shared between threads:
/// proofs are checked side by side, and pinning or forgetting a set waits
/// for the checks in flight.
#[derive(Debug, uniffi::Object)]
pub struct Verifier {
    client: RwLock<ThinClient>,
}

impl Verifier {
    fn for_cluster(params: ClusterParams) -> Arc<Self> {
        Arc::new(Self {
            client: RwLock::new(ThinClient::new(params)),
        })
    }

    // A panic while the lock was held would poison it. Each change to the
    // client is a single insert or removal that either happened or did not,
    // so the client behind a poisoned lock is still a consistent one.
    fn read(&self) -> RwLockReadGuard<'_, ThinClient> {
        self.client.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, ThinClient> {
        self.client.write().unwrap_or_else(PoisonError::into_inner)
    }
}

// Byte arguments are taken by value. UniFFI would hand a borrowed `&[u8]` to
// Kotlin as a `java.nio.ByteBuffer`; an owned one is the `ByteArray` and the
// `Data` a caller already holds, for one copy of at most a few tens of
// kilobytes.
#[uniffi::export]
impl Verifier {
    /// A verifier for mainnet-beta: epochs of 432,000 slots from slot zero.
    ///
    /// `shred_version` is what the cluster reports from `getClusterNodes`.
    /// It is part of every signed vote, and it changes when a cluster is
    /// restarted. It was 50093 when Alpenglow went live.
    #[uniffi::constructor]
    pub fn mainnet(shred_version: u16) -> Arc<Self> {
        Self::for_cluster(ClusterParams::mainnet(shred_version))
    }

    /// A verifier for a cluster whose epochs are `slots_per_epoch` long from
    /// slot zero, as on mainnet and on test validators.
    #[uniffi::constructor]
    pub fn without_warmup(
        shred_version: u16,
        slots_per_epoch: u64,
    ) -> Result<Arc<Self>, VerifyError> {
        let params = ClusterParams::without_warmup(shred_version, slots_per_epoch)?;
        Ok(Self::for_cluster(params))
    }

    /// A verifier for a cluster that began with warm-up epochs of 32, 64,
    /// 128, ... slots before reaching `slots_per_epoch`, as testnet and
    /// devnet did.
    #[uniffi::constructor]
    pub fn with_warmup(shred_version: u16, slots_per_epoch: u64) -> Result<Arc<Self>, VerifyError> {
        let params = ClusterParams::with_warmup(shred_version, slots_per_epoch)?;
        Ok(Self::for_cluster(params))
    }

    /// Trusts the validator set in `set` for `epoch`, provided it hashes to
    /// `pinned_hash` (32 bytes).
    ///
    /// The hash is the trust root: it has to come from somewhere you
    /// believe. The set can come from anywhere. The epoch is the caller's
    /// word too. Nothing about it is read from the set or from any proof.
    ///
    /// The hash is compared before any key is checked, so bytes that are
    /// not the pinned set cost one SHA-256. An epoch keeps the first set
    /// pinned for it: the same set again does nothing, and a different one
    /// is refused until the epoch is forgotten.
    pub fn pin_validator_set(
        &self,
        epoch: u64,
        set: Vec<u8>,
        pinned_hash: Vec<u8>,
    ) -> Result<(), VerifyError> {
        let pinned_hash = sized::<32>("pinned hash", &pinned_hash)?;
        self.write()
            .trust_validator_set_bytes(epoch, &set, &pinned_hash)?;
        Ok(())
    }

    /// The epochs a set is pinned for, in ascending order.
    pub fn pinned_epochs(&self) -> Vec<u64> {
        self.read().pinned_epochs().collect()
    }

    /// Drops the set pinned for `epoch`. Returns whether there was one.
    pub fn forget_epoch(&self, epoch: u64) -> bool {
        self.write().forget_validator_set(epoch).is_some()
    }

    /// Drops the sets pinned for every epoch before `epoch` and returns how
    /// many went. An app that follows the chain calls this as epochs pass,
    /// so that old keys stop being able to vouch for old slots.
    pub fn forget_epochs_before(&self, epoch: u64) -> u64 {
        self.write().forget_epochs_before(epoch) as u64
    }

    /// Checks a proof and says which transaction it is for.
    ///
    /// The proof shows that *a* transaction is final. Compare
    /// `transaction_id` or the memos with what you expected, or call
    /// [`verify_signature`](Self::verify_signature).
    pub fn verify_transaction(&self, proof: Vec<u8>) -> Result<VerifiedTransaction, VerifyError> {
        let client = self.read();
        let verified = client.verify_transaction_bytes(&proof)?;
        describe(&client, verified)
    }

    /// Checks a proof and that it is for the transaction whose id (its
    /// first signature, 64 bytes) is `signature`.
    pub fn verify_signature(
        &self,
        proof: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<VerifiedTransaction, VerifyError> {
        let signature = sized::<64>("expected signature", &signature)?;
        let client = self.read();
        let proof = TxProof::from_bytes(&proof, client.limits())?;
        let verified = client.verify_signature(&proof, &signature)?;
        describe(&client, verified)
    }
}

/// The verifier's answer as the record a foreign caller gets.
fn describe(
    client: &ThinClient,
    verified: solana_thin::VerifiedTransaction,
) -> Result<VerifiedTransaction, VerifyError> {
    let certified = verified.finalized_by;
    Ok(VerifiedTransaction {
        slot: verified.block.slot,
        block_id: verified.block.id.to_vec(),
        // The verifier found this epoch's set to check the certificate, so
        // the schedule covers the slot.
        epoch: client.params().epoch_of(certified.block.slot)?,
        // Every transaction the verifier parses has a signature. If that
        // ever stopped being so, an empty id must not be the answer.
        transaction_id: verified
            .transaction
            .signature()
            .ok_or(Error::UnsupportedTransaction)?
            .to_vec(),
        block_time_nanos: verified.block_time_nanos(),
        finality: match certified.finality {
            solana_thin::Finality::Fast => Finality::Fast,
            solana_thin::Finality::Slow => Finality::Slow,
            // `Finality` may grow. A way of finalizing this binding cannot
            // name is not one it can report.
            other => {
                return Err(VerifyError::Other {
                    detail: format!("finality {other:?} has no case in this binding"),
                })
            }
        },
        memos: verified.transaction.memos().map(<[u8]>::to_vec).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name of a case, as `Debug` prints it.
    fn case(error: &VerifyError) -> String {
        let debug = format!("{error:?}");
        debug.split(' ').next().unwrap().to_owned()
    }

    #[test]
    fn every_kind_of_the_verifier_has_a_case_of_its_own_name() {
        for kind in ErrorKind::ALL {
            let error = VerifyError::new(*kind, "why".into(), None);
            assert_eq!(case(&error), format!("{kind:?}"));
            assert_eq!(error.to_string(), "why");
        }
    }

    #[test]
    fn an_error_keeps_its_sentence_and_the_epoch_to_pin() {
        assert_eq!(
            VerifyError::from(Error::UnknownEpoch(1095)),
            VerifyError::EpochNotPinned {
                detail: "no trusted validator set for epoch 1095".into(),
                epoch: Some(1095),
            }
        );
        assert_eq!(
            VerifyError::from(Error::SlotBeforeSchedule),
            VerifyError::EpochNotPinned {
                detail: "slot is before the epoch schedule starts".into(),
                epoch: None,
            }
        );
        assert_eq!(
            VerifyError::from(Error::InsufficientStake {
                signed: 79,
                total: 100,
                required_bps: 8_000,
            }),
            VerifyError::CertificateRejected {
                detail: "signers hold 79 of 100 stake, below the required 80.00%".into()
            }
        );
        // The number of another case's error is not an epoch to pin.
        assert_eq!(
            VerifyError::from(Error::EpochAlreadyPinned(7)),
            VerifyError::InvalidParameters {
                detail: "a different validator set is already pinned for epoch 7".into()
            }
        );
    }
}
