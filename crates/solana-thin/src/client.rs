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
#[cfg(feature = "unsound-stale-set")]
use crate::validator_set::CandidateSet;
use crate::validator_set::ValidatorSet;
use std::collections::BTreeMap;

/// Facts about the cluster that are not in any proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterParams {
    /// The cluster's shred version. It is part of every signed vote and of
    /// every shred, and it changes when a cluster is restarted.
    pub shred_version: u16,
    /// Slots per epoch once the warm-up epochs are over.
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

    /// The epoch a slot falls in.
    pub fn epoch_of(&self, slot: u64) -> Result<u64> {
        if slot < self.first_normal_slot || self.slots_per_epoch == 0 {
            return Err(Error::SlotBeforeSchedule);
        }
        Ok(self.first_normal_epoch + (slot - self.first_normal_slot) / self.slots_per_epoch)
    }
}

/// Opt-in rule for checking certificates from an epoch whose validator set has
/// not been pinned yet, using the newest pinned set from an earlier epoch.
///
/// The client counts only signers it already trusts, at the stake it already
/// knows for them, and demands more of it: each threshold is raised by
/// `drift_bps_per_epoch` for every epoch between the pinned set and the
/// certificate. The reasoning: if the true stake distribution has moved by at
/// most that much (as a share of total stake) since the pinned epoch, then
/// signers holding `threshold + drift` of the old stake hold at least
/// `threshold` of the new.
///
/// This is an assumption about the world, not a proof, and the protocol does
/// not enforce it. Solana caps how fast stake can activate and deactivate at
/// 9% of the total per epoch, which is where 900 comes from. But stake that is
/// already active can join the ranked set in a single epoch without
/// activating (its validator registers a BLS key, or tops up its admission
/// balance), and that is not capped at all. If more than about a tenth of
/// stake arrives that way, a certificate this accepts as final may be short
/// of the real threshold. `docs/DESIGN.md` has the arithmetic.
///
/// Treat it as a grace window for showing something rather than nothing. Do
/// not move value on it, keep `max_epochs` at one, and pin a fresh set as
/// soon as you can get one.
#[cfg(feature = "unsound-stale-set")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalePolicy {
    /// How many epochs past a pinned set this may be used.
    pub max_epochs: u64,
    /// Extra stake demanded per epoch of distance, in basis points.
    pub drift_bps_per_epoch: u32,
}

/// A block the client has checked a finality certificate for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    #[cfg(feature = "unsound-stale-set")]
    candidates: BTreeMap<u64, CandidateSet>,
    #[cfg(feature = "unsound-stale-set")]
    stale: Option<StalePolicy>,
    limits: Limits,
}

impl ThinClient {
    /// A client that trusts nothing yet.
    pub fn new(params: ClusterParams) -> Self {
        Self {
            params,
            trusted: BTreeMap::new(),
            #[cfg(feature = "unsound-stale-set")]
            candidates: BTreeMap::new(),
            #[cfg(feature = "unsound-stale-set")]
            stale: None,
            limits: Limits::default(),
        }
    }

    /// The cluster parameters.
    pub fn params(&self) -> &ClusterParams {
        &self.params
    }

    /// Replaces the size limits applied to incoming proofs.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Trusts `set` as the validators of `epoch`, provided it hashes to
    /// `pinned_hash`.
    ///
    /// The hash is the trust root. The set itself can be fetched from anywhere
    /// (it is about 56 bytes per validator); the hash has to come from
    /// somewhere you believe.
    pub fn trust_validator_set(
        &mut self,
        epoch: u64,
        set: ValidatorSet,
        pinned_hash: &Hash,
    ) -> Result<()> {
        if &set.hash() != pinned_hash {
            return Err(Error::ValidatorSetHashMismatch);
        }
        self.trusted.insert(epoch, set);
        Ok(())
    }

    /// The trusted set for `epoch`, if one was pinned.
    pub fn validator_set(&self, epoch: u64) -> Option<&ValidatorSet> {
        self.trusted.get(&epoch)
    }

    /// Turns on stale-set verification. Off by default, and unsound.
    #[cfg(feature = "unsound-stale-set")]
    pub fn set_stale_policy(&mut self, policy: Option<StalePolicy>) {
        self.stale = policy;
    }

    /// Supplies an untrusted key list for `epoch`, used only under a
    /// [`StalePolicy`].
    #[cfg(feature = "unsound-stale-set")]
    pub fn add_candidate_set(&mut self, epoch: u64, candidates: CandidateSet) {
        self.candidates.insert(epoch, candidates);
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

        #[cfg(not(feature = "unsound-stale-set"))]
        {
            let _ = (parts, finality);
            Err(Error::UnknownEpoch(epoch))
        }
        #[cfg(feature = "unsound-stale-set")]
        self.verify_finality_stale(epoch, block, finality, parts)
    }

    /// No pinned set for the certificate's epoch: fall back to an older one,
    /// if the caller opted in.
    #[cfg(feature = "unsound-stale-set")]
    fn verify_finality_stale(
        &self,
        epoch: u64,
        block: BlockRef,
        finality: Finality,
        parts: Vec<(&crate::certificate::Aggregate, &[u8], u32)>,
    ) -> Result<FinalizedBlock> {
        let policy = self.stale.ok_or(Error::UnknownEpoch(epoch))?;
        let (trusted_epoch, trusted) = self
            .trusted
            .range(..epoch)
            .next_back()
            .ok_or(Error::UnknownEpoch(epoch))?;
        let distance = epoch - trusted_epoch;
        if distance > policy.max_epochs {
            return Err(Error::TooStale);
        }
        let candidates = self
            .candidates
            .get(&epoch)
            .ok_or(Error::UnknownEpoch(epoch))?;
        let margin = u64::from(policy.drift_bps_per_epoch).saturating_mul(distance);
        for (aggregate, message, bps) in parts {
            let required = u64::from(bps).saturating_add(margin);
            if required > 10_000 {
                return Err(Error::TooStale);
            }
            let signed = candidates.signed_trusted_stake(trusted, aggregate, message)?;
            check_stake(signed, trusted.total_stake(), required as u32)?;
        }
        Ok(FinalizedBlock { block, finality })
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
        // 1. Some block is final.
        let finalized_by = self.verify_finality(&proof.finality)?;

        // 2. Walk back to the block the transaction is in.
        if proof.ancestry.len() > self.limits.max_ancestry {
            return Err(Error::LimitExceeded("ancestry length"));
        }
        let mut block = finalized_by.block;
        for link in &proof.ancestry {
            link.verify(&block)?;
            block = link.parent;
        }

        // 3. Open that block's shreds.
        let shreds = proof.block.verify(&block, self.params.shred_version)?;

        // 4. The block must have run from its first shred. The header in
        //    shred 0 names the parent the leader started on; the tree names
        //    the parent the block ended on. If they differ the leader switched
        //    parent part way, and everything before the switch was discarded
        //    without being executed.
        //
        //    The header is read from shred 0 alone, never from the whole
        //    first component. A validator rejects an UpdateParent that names
        //    the header's own parent, but only when it found a header in
        //    shred 0 by itself. A leader that lets the header run on into
        //    shred 1 escapes that rule: it can switch to the *same* parent
        //    and abandon a prefix while the header still equals the tree.
        const NO_HEADER: Error = Error::InvalidComponent("block does not start with a header");
        match block::parse_marker(&shreds.first_shred_data()?) {
            Ok(Marker::Header { parent }) if parent == shreds.parent => {}
            Ok(Marker::Header { .. }) => return Err(Error::UpdateParentBlock),
            _ => return Err(NO_HEADER),
        }

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
        if verified.transaction.signature() != signature {
            return Err(Error::SignatureNotFound);
        }
        Ok(verified)
    }
}
