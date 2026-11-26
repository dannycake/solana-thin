//! The thin client: holds what is trusted and checks proofs against it.

use crate::block::{self, Footer, Marker, TxPosition};
use crate::certificate::{
    check_stake, finalize_payload, notarize_payload, BlockRef, Finality, FinalityCert,
    FAST_FINALIZE_BPS, SLOW_FINALIZE_BPS,
};
use crate::error::{Error, Result};
use crate::merkle::Hash;
use crate::proof::{Limits, TxProof};
use crate::transaction::Transaction;
use crate::validator_set::{self, ValidatorSet};
use std::collections::BTreeMap;

/// The shortest epoch a cluster can have, and the length of the first
/// warm-up epoch: `MINIMUM_SLOTS_PER_EPOCH` in the `solana-epoch-schedule`
/// crate (`src/lib.rs:49` in 3.3.0, the version Agave v4.4.1 builds with).
const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

/// Facts about the cluster that are not in any proof.
///
/// The epoch fields decide which validator set a certificate is checked
/// against, so they are part of what is trusted. [`epoch_of`](Self::epoch_of)
/// refuses values that are not an epoch schedule a cluster can have; the
/// constructors only produce ones that are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClusterParams {
    /// The cluster's shred version. It is part of every signed vote and of
    /// every shred, and it changes when a cluster is restarted.
    pub shred_version: u16,
    /// Slots per epoch once the warm-up epochs are over. At least 32.
    pub slots_per_epoch: u64,
    /// First slot of the first full-length epoch. Zero on mainnet.
    pub first_normal_slot: u64,
    /// Number of that epoch. Zero on mainnet.
    pub first_normal_epoch: u64,
}

impl ClusterParams {
    /// Mainnet-beta: 432,000 slots per epoch from slot zero.
    ///
    /// `shred_version` is whatever the cluster currently reports from
    /// `getClusterNodes`; it was 50093 when Alpenglow went live.
    pub const fn mainnet(shred_version: u16) -> Self {
        Self {
            shred_version,
            slots_per_epoch: 432_000,
            first_normal_slot: 0,
            first_normal_epoch: 0,
        }
    }

    /// A cluster whose epochs are `slots_per_epoch` long from slot zero, as
    /// on mainnet and on test validators.
    pub fn without_warmup(shred_version: u16, slots_per_epoch: u64) -> Result<Self> {
        let params = Self {
            shred_version,
            slots_per_epoch,
            first_normal_slot: 0,
            first_normal_epoch: 0,
        };
        params.validate()?;
        Ok(params)
    }

    /// A cluster that began with warm-up epochs of 32, 64, 128, ... slots
    /// before reaching `slots_per_epoch`, as testnet and devnet did: with
    /// 432,000-slot epochs the first full-length one is epoch 14, at slot
    /// 524,256.
    pub fn with_warmup(shred_version: u16, slots_per_epoch: u64) -> Result<Self> {
        // The epoch length is judged first, so that a length no cluster has
        // is reported as that and not as a bad warm-up.
        let flat = Self::without_warmup(shred_version, slots_per_epoch)?;
        let (first_normal_epoch, first_normal_slot) =
            warmup_end(slots_per_epoch).ok_or(Error::InvalidClusterParams("warm-up schedule"))?;
        Ok(Self {
            first_normal_slot,
            first_normal_epoch,
            ..flat
        })
    }

    /// Checks that the epoch fields are a schedule a cluster can have.
    ///
    /// A cluster builds its schedule in one of two ways
    /// (`EpochSchedule::custom` in `solana-epoch-schedule`): full-length
    /// epochs of at least 32 slots from slot zero, or warm-up epochs that end
    /// where the epoch length says they do. Anything else is a mistake in
    /// the caller's numbers, and guessing an epoch from it could check a
    /// certificate against another epoch's validators.
    pub fn validate(&self) -> Result<()> {
        if self.slots_per_epoch < MINIMUM_SLOTS_PER_EPOCH {
            return Err(Error::InvalidClusterParams("slots per epoch"));
        }
        let start = (self.first_normal_epoch, self.first_normal_slot);
        if start != (0, 0) && Some(start) != warmup_end(self.slots_per_epoch) {
            return Err(Error::InvalidClusterParams("warm-up schedule"));
        }
        Ok(())
    }

    /// The epoch a slot falls in.
    ///
    /// Slots in the warm-up epochs are [`Error::SlotBeforeSchedule`], and
    /// parameters that fail [`validate`](Self::validate) are
    /// [`Error::InvalidClusterParams`].
    pub fn epoch_of(&self, slot: u64) -> Result<u64> {
        self.validate()?;
        let since = slot
            .checked_sub(self.first_normal_slot)
            .ok_or(Error::SlotBeforeSchedule)?;
        // `validate` leaves no values that overflow here. Checked all the
        // same: a wrapped epoch would select the wrong validator set.
        since
            .checked_div(self.slots_per_epoch)
            .and_then(|epochs| self.first_normal_epoch.checked_add(epochs))
            .ok_or(Error::InvalidClusterParams("epoch overflows"))
    }
}

/// Where warm-up ends for a cluster with this epoch length: the number and
/// first slot of the first full-length epoch. `None` if no power of two is
/// left to round the length up to.
///
/// Warm-up epochs double from 32 slots until one would reach the epoch
/// length rounded up to a power of two (`EpochSchedule::custom`,
/// `solana-epoch-schedule` `src/lib.rs:111-133`).
fn warmup_end(slots_per_epoch: u64) -> Option<(u64, u64)> {
    let rounded = slots_per_epoch.checked_next_power_of_two()?;
    let epoch = rounded
        .trailing_zeros()
        .checked_sub(MINIMUM_SLOTS_PER_EPOCH.trailing_zeros())?;
    let slot = rounded.checked_sub(MINIMUM_SLOTS_PER_EPOCH)?;
    Some((u64::from(epoch), slot))
}

/// A block the client has checked a finality certificate for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FinalizedBlock {
    /// The block.
    pub block: BlockRef,
    /// How it was finalized.
    pub finality: Finality,
}

/// A transaction proven to be in a finalized block.
///
/// **This says the transaction is in a finalized block, in a part validators
/// executed. It does not say it succeeded, or that it did anything at all.**
///
/// * A transaction whose program returned an error still lands in the block
///   and pays its fee.
/// * A transaction that could not load its accounts lands, pays its fee and
///   runs nothing.
/// * Where the cluster has activated `relax_fee_payer_constraint`
///   (SIMD-0290), a transaction whose fee payer cannot pay may land as a
///   no-op: no fee, nothing run. Honest leaders leave these out, but a block
///   that carries one is valid.
///
/// Nothing a block commits to records the difference in a form a small proof
/// can open. Build on what inclusion alone gives: these bytes, signed by
/// their signers, were ordered into this block. See the crate docs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedTransaction {
    /// The transaction.
    pub transaction: Transaction,
    /// The block it is in.
    pub block: BlockRef,
    /// That block's parent.
    pub parent: BlockRef,
    /// Index of the first shred of its component.
    pub component_start: u32,
    /// Its place within the component.
    pub position: TxPosition,
    /// The block the finality certificate was for: `block` or a descendant.
    pub finalized_by: FinalizedBlock,
    /// The block's footer, if the proof opened it.
    pub footer: Option<Footer>,
}

impl VerifiedTransaction {
    /// The leader's clock for the block, in nanoseconds since the Unix epoch,
    /// if the proof opened the footer.
    pub fn block_time_nanos(&self) -> Option<u64> {
        self.footer.as_ref().map(|f| f.producer_time_nanos)
    }

    /// Whether the transaction carries a Memo instruction whose data is
    /// exactly `data`. The basis for anchoring: see `examples/anchor.rs`.
    pub fn has_memo(&self, data: &[u8]) -> bool {
        self.transaction.memos().any(|memo| memo == data)
    }
}

/// Verifies finality certificates and transaction proofs.
///
/// A client is nothing but its trust: the cluster parameters and the
/// validator sets it has been told to believe. It keeps no chain state and
/// makes no network calls. Proofs can come from anyone.
#[derive(Debug, Clone)]
pub struct ThinClient {
    params: ClusterParams,
    trusted: BTreeMap<u64, ValidatorSet>,
    limits: Limits,
}

impl ThinClient {
    /// A client that trusts nothing yet.
    pub fn new(params: ClusterParams) -> Self {
        Self {
            params,
            trusted: BTreeMap::new(),
            limits: Limits::default(),
        }
    }

    /// The cluster parameters.
    pub fn params(&self) -> &ClusterParams {
        &self.params
    }

    /// Replaces the size limits applied to incoming proofs.
    ///
    /// They hold for every proof this client checks, whether it arrives as
    /// bytes or already decoded.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// The size limits applied to incoming proofs. Pass these to
    /// [`TxProof::from_bytes`] when decoding a proof for this client.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Trusts `set` as the validators of `epoch`, provided it hashes to
    /// `pinned_hash`.
    ///
    /// The hash is the trust root. The set itself can be fetched from anywhere
    /// (it is about 56 bytes per validator); the hash has to come from
    /// somewhere you believe.
    ///
    /// Building a [`ValidatorSet`] checks every key, before this can compare
    /// anything. To load fetched bytes, call
    /// [`trust_validator_set_bytes`](Self::trust_validator_set_bytes), which
    /// compares first.
    ///
    /// An epoch keeps the first set pinned for it. Pinning the same set again
    /// does nothing; a different one is refused with
    /// [`Error::EpochAlreadyPinned`]. To change an epoch's set on purpose,
    /// [`forget_validator_set`](Self::forget_validator_set) first.
    pub fn trust_validator_set(
        &mut self,
        epoch: u64,
        set: ValidatorSet,
        pinned_hash: &Hash,
    ) -> Result<()> {
        if &set.hash() != pinned_hash {
            return Err(Error::ValidatorSetHashMismatch);
        }
        if self.already_pinned(epoch, pinned_hash)? {
            return Ok(());
        }
        self.trusted.insert(epoch, set);
        Ok(())
    }

    /// Whether `epoch` already has the set with this hash. An epoch that has
    /// a different one is an error: the trust root is not something a later
    /// call gets to swap.
    fn already_pinned(&self, epoch: u64, hash: &Hash) -> Result<bool> {
        match self.trusted.get(&epoch) {
            None => Ok(false),
            Some(pinned) if &pinned.hash() == hash => Ok(true),
            Some(_) => Err(Error::EpochAlreadyPinned(epoch)),
        }
    }

    /// Trusts the validator set encoded in `set_bytes` (the output of
    /// [`ValidatorSet::to_bytes`]) as the validators of `epoch`, provided it
    /// hashes to `pinned_hash`.
    ///
    /// This is the entry point for a set that came from somewhere you do not
    /// trust. The pinned hash is compared with a hash over the bytes first,
    /// and the keys are decompressed and subgroup-checked only if it matches,
    /// so bytes that are not the pinned set cost one SHA-256 over at most
    /// 112 KB.
    pub fn trust_validator_set_bytes(
        &mut self,
        epoch: u64,
        set_bytes: &[u8],
        pinned_hash: &Hash,
    ) -> Result<()> {
        if set_bytes.len() > validator_set::MAX_ENCODED_SIZE {
            return Err(Error::LimitExceeded("validator count"));
        }
        if &validator_set::encoding_hash(set_bytes) != pinned_hash {
            return Err(Error::ValidatorSetHashMismatch);
        }
        if self.already_pinned(epoch, pinned_hash)? {
            return Ok(());
        }
        let set = ValidatorSet::from_bytes(set_bytes)?;
        // Compares the pin again, with the hash of what was decoded. It
        // cannot differ while the encoding is canonical; if that ever broke,
        // this is where a set other than the pinned one would be stopped.
        self.trust_validator_set(epoch, set, pinned_hash)
    }

    /// The trusted set for `epoch`, if one was pinned.
    pub fn validator_set(&self, epoch: u64) -> Option<&ValidatorSet> {
        self.trusted.get(&epoch)
    }

    /// The epochs a set is pinned for, in ascending order.
    pub fn pinned_epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.trusted.keys().copied()
    }

    /// Drops the set pinned for `epoch` and returns it. Certificates for that
    /// epoch are [`Error::UnknownEpoch`] from then on, and the epoch can be
    /// pinned again.
    pub fn forget_validator_set(&mut self, epoch: u64) -> Option<ValidatorSet> {
        self.trusted.remove(&epoch)
    }

    /// Drops everything held for epochs before `epoch` and returns how many
    /// pinned sets went. A client that follows the chain for a long time
    /// calls this as epochs pass, so that what it trusts does not grow
    /// without bound and old keys stop being able to finalize old slots.
    pub fn forget_epochs_before(&mut self, epoch: u64) -> usize {
        let kept = self.trusted.split_off(&epoch);
        let dropped = self.trusted.len();
        self.trusted = kept;
        dropped
    }

    /// Checks a finality certificate against the validator set pinned for the
    /// epoch of its slot. With no set pinned for that epoch the answer is
    /// [`Error::UnknownEpoch`].
    pub fn verify_finality(&self, cert: &FinalityCert) -> Result<FinalizedBlock> {
        let block = cert.block();
        let epoch = self.params.epoch_of(block.slot)?;
        let version = self.params.shred_version;
        let notar_msg = notarize_payload(&block, version);
        let final_msg = finalize_payload(block.slot, version);

        // (aggregate, message, base threshold) for each half of the certificate.
        let (parts, finality) = match cert {
            FinalityCert::Fast { notar, .. } => (
                vec![(notar, &notar_msg[..], FAST_FINALIZE_BPS)],
                Finality::Fast,
            ),
            FinalityCert::Slow {
                finalize, notar, ..
            } => (
                vec![
                    (notar, &notar_msg[..], SLOW_FINALIZE_BPS),
                    (finalize, &final_msg[..], SLOW_FINALIZE_BPS),
                ],
                Finality::Slow,
            ),
        };

        if let Some(set) = self.trusted.get(&epoch) {
            for (aggregate, message, bps) in parts {
                let signed = set.signed_stake(aggregate, message)?;
                check_stake(signed, set.total_stake(), bps)?;
            }
            return Ok(FinalizedBlock { block, finality });
        }

        Err(Error::UnknownEpoch(epoch))
    }

    /// Checks a transaction proof from its encoded form.
    pub fn verify_transaction_bytes(&self, proof: &[u8]) -> Result<VerifiedTransaction> {
        self.verify_transaction(&TxProof::from_bytes(proof, &self.limits)?)
    }

    /// Checks a transaction proof.
    ///
    /// On success the returned transaction is in a block that the pinned
    /// validators finalized. Compare its [`signature`](Transaction::signature)
    /// or contents with what you expected: the proof shows *a* transaction is
    /// final, and it is the caller who knows which one they care about.
    /// [`verify_signature`](Self::verify_signature) does that comparison.
    pub fn verify_transaction(&self, proof: &TxProof) -> Result<VerifiedTransaction> {
        // 0. The client's limits, before any work. A proof decoded by the
        //    caller was held to whatever limits the caller decoded it with,
        //    which need not be this client's.
        self.limits.check(proof)?;

        // 1. Some block is final.
        let finalized_by = self.verify_finality(&proof.finality)?;

        // 2. Walk back to the block the transaction is in.
        let mut block = finalized_by.block;
        for link in &proof.ancestry {
            link.verify(&block)?;
            block = link.parent;
        }

        // 3. Open that block's shreds.
        let shreds = proof.block.verify(&block, self.params.shred_version)?;

        // 4. The block must have run from its first shred. The header in
        //    shred 0 names the parent the block started on; the tree names
        //    the parent it ended on. If they differ, the parent was switched
        //    part way and the verifier cannot show the whole block ran, so it
        //    refuses the block.
        //
        //    The header is read from shred 0 alone, never from the whole
        //    first component: the rule that an UpdateParent may not name the
        //    header's own parent only holds when the header is wholly in
        //    shred 0. The verifier therefore requires it there and treats a
        //    header that is not as no header at all.
        const NO_HEADER: Error = Error::InvalidComponent("block does not start with a header");
        match block::parse_marker(&shreds.first_shred_data()?) {
            Ok(Marker::Header { parent }) if parent == shreds.parent => {}
            Ok(Marker::Header { .. }) => return Err(Error::UpdateParentBlock),
            _ => return Err(NO_HEADER),
        }
        //    A parent id of all zeros cannot be told from an unset one, so
        //    the verifier cannot establish the parent and refuses to prove
        //    anything. Only a block built directly on a cluster's first block
        //    has such a parent.
        if shreds.parent.id == [0u8; 32] {
            return Err(Error::ZeroParentId);
        }
        //    And the shreds themselves must agree with that parent.
        shreds.check_parent_offset(block.slot)?;

        // 5. Parse the transaction's component from its true start.
        if proof.component_start == 0 {
            return Err(Error::InvalidComponent("not an entry batch"));
        }
        let component = shreds.component(proof.component_start)?;
        let transaction = block::transaction_at(&component, proof.position)?;

        // 6. Optionally, the footer.
        let footer = match proof.footer_start {
            None => None,
            Some(start) => match block::parse_marker(&shreds.component(start)?)? {
                Marker::Footer(footer) => Some(*footer),
                _ => return Err(Error::InvalidComponent("not a footer")),
            },
        };

        Ok(VerifiedTransaction {
            transaction,
            block,
            parent: shreds.parent,
            component_start: proof.component_start,
            position: proof.position,
            finalized_by,
            footer,
        })
    }

    /// Checks a proof and that it is for the transaction with this signature.
    pub fn verify_signature(
        &self,
        proof: &TxProof,
        signature: &[u8; 64],
    ) -> Result<VerifiedTransaction> {
        let verified = self.verify_transaction(proof)?;
        if verified.transaction.signature() != Some(signature) {
            return Err(Error::SignatureNotFound);
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_epochs_are_432_000_slots_from_slot_zero() {
        let mainnet = ClusterParams::mainnet(50093);
        assert_eq!(mainnet.validate(), Ok(()));
        assert_eq!(mainnet.epoch_of(0), Ok(0));
        assert_eq!(mainnet.epoch_of(431_999), Ok(0));
        assert_eq!(mainnet.epoch_of(432_000), Ok(1));
        assert_eq!(mainnet.epoch_of(473_100_911), Ok(1095));
        assert_eq!(mainnet.epoch_of(u64::MAX), Ok(u64::MAX / 432_000));
        assert_eq!(ClusterParams::without_warmup(50093, 432_000), Ok(mainnet));
    }

    /// Testnet began with warm-up epochs of 32, 64, 128, ... slots. Its
    /// first full-length epoch is 14, starting at slot 524,256.
    #[test]
    fn epochs_follow_a_warm_up_schedule() {
        let testnet = ClusterParams::with_warmup(1, 432_000).unwrap();
        assert_eq!(
            (testnet.first_normal_epoch, testnet.first_normal_slot),
            (14, 524_256)
        );
        assert_eq!(testnet.validate(), Ok(()));
        assert_eq!(testnet.epoch_of(524_256), Ok(14));
        assert_eq!(testnet.epoch_of(524_256 + 431_999), Ok(14));
        assert_eq!(testnet.epoch_of(524_256 + 432_000), Ok(15));
        assert_eq!(testnet.epoch_of(524_256 + 10 * 432_000 + 1), Ok(24));
        assert_eq!(
            testnet.epoch_of(u64::MAX),
            Ok(14 + (u64::MAX - 524_256) / 432_000)
        );
        // The warm-up epochs themselves are not covered.
        assert_eq!(testnet.epoch_of(524_255), Err(Error::SlotBeforeSchedule));
        assert_eq!(testnet.epoch_of(0), Err(Error::SlotBeforeSchedule));

        // Epoch lengths that are and are not powers of two, and the shortest.
        let end = |slots| {
            let params = ClusterParams::with_warmup(1, slots).unwrap();
            (params.first_normal_epoch, params.first_normal_slot)
        };
        assert_eq!(end(32), (0, 0));
        assert_eq!(end(33), (1, 32));
        assert_eq!(end(64), (1, 32));
        assert_eq!(end(8_192), (8, 8_160));
    }

    #[test]
    fn parameters_no_cluster_can_have_are_refused() {
        let mainnet = ClusterParams::mainnet(1);
        let testnet = ClusterParams::with_warmup(1, 432_000).unwrap();
        let slots = Error::InvalidClusterParams("slots per epoch");
        let warmup = Error::InvalidClusterParams("warm-up schedule");

        // An epoch count that would overflow: a debug build used to panic
        // here, and a release build wrapped around to epoch 4.
        let overflowing = ClusterParams {
            slots_per_epoch: 1,
            first_normal_epoch: u64::MAX,
            ..mainnet
        };
        assert_eq!(overflowing.epoch_of(5), Err(slots.clone()));
        let overflowing = ClusterParams {
            first_normal_epoch: u64::MAX,
            ..testnet
        };
        assert_eq!(overflowing.epoch_of(524_256 + 432_000), Err(warmup.clone()));

        // Epochs shorter than a cluster's minimum of 32 slots.
        for (slots_per_epoch, verdict) in [(0, Err(slots.clone())), (31, Err(slots)), (32, Ok(0))] {
            let params = ClusterParams {
                slots_per_epoch,
                ..mainnet
            };
            assert_eq!(params.epoch_of(7), verdict);
            assert_eq!(
                ClusterParams::without_warmup(1, slots_per_epoch).map(|p| p.slots_per_epoch),
                verdict.clone().map(|_| slots_per_epoch)
            );
            assert_eq!(
                ClusterParams::with_warmup(1, slots_per_epoch).map(|p| p.slots_per_epoch),
                verdict.map(|_| slots_per_epoch)
            );
        }
        // No power of two is left to round the epoch length up to.
        assert_eq!(ClusterParams::with_warmup(1, u64::MAX), Err(warmup.clone()));
        assert!(ClusterParams::without_warmup(1, u64::MAX).is_ok());

        // A warm-up end that is not the one this epoch length gives.
        for (first_normal_epoch, first_normal_slot) in [
            (14, 0),
            (0, 524_256),
            (13, 524_256),
            (15, 524_256),
            (14, 524_255),
            (14, 524_257),
            (1, 32),
        ] {
            let params = ClusterParams {
                first_normal_epoch,
                first_normal_slot,
                ..mainnet
            };
            assert_eq!(params.validate(), Err(warmup.clone()));
            assert_eq!(params.epoch_of(600_000), Err(warmup.clone()));
        }

        // The client reports it rather than pick an epoch.
        let client = ThinClient::new(ClusterParams {
            first_normal_epoch: 3,
            ..mainnet
        });
        let cert = FinalityCert::Fast {
            block: BlockRef {
                slot: 5,
                id: [0; 32],
            },
            notar: crate::certificate::Aggregate {
                signature: [0; 96],
                bitmap: vec![],
            },
        };
        assert_eq!(client.verify_finality(&cert), Err(warmup));
    }
}
