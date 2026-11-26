//! From a signature and a slot hint to a proof that verifies.
//!
//! 1. **Certify.** Read the footers of the slots after the hinted one, by
//!    slot, until one carries a finality certificate for the hinted slot or
//!    a later one. Verify it. From here on the block is known by its id.
//! 2. **Descend.** If the certificate is for a later block, follow parent
//!    links down from it, each held to the id above. The slot is in the
//!    finalized chain only if a link lands on it.
//! 3. **Fetch** the block by its id, every shred held to that id.
//! 4. **Prove and verify.** Open the shreds that hold the transaction and
//!    check the result with the verifier before anything leaves.
//!
//! The hint is the only input that is not checked, and all a wrong one can
//! do is send this to a block the transaction is not in.

use crate::anchor::Anchor;
use crate::fetch::{FetchStats, Fetcher};
use crate::peers::PeerBook;
use crate::refusal::Refusal;
use crate::store::Store;
use crate::trust::Trust;
use solana_thin::prover::BlockData;
use solana_thin::{BlockRef, Error, FinalityCert, TxProof};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

/// Consecutive slots one leader produces.
const LEADER_TURN: u32 = 4;

/// How far to look for a certificate, and how long a chain to accept.
#[derive(Debug, Clone)]
pub struct ProverConfig {
    /// How many slots after the hinted one to read footers of. A block's
    /// certificate is usually in the next block and can be five slots on
    /// when a leader's turn was skipped.
    pub certificate_window: u64,
    /// Times to go over that window. At the tip the next blocks may not
    /// exist yet.
    pub certificate_passes: u32,
    /// Wait between passes.
    pub pass_wait: Duration,
    /// Most parent links between a certified block and the block proven.
    pub max_ancestry: usize,
    /// Indexed blocks kept in memory.
    pub cached_blocks: usize,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            certificate_window: 12,
            certificate_passes: 2,
            pass_wait: Duration::from_millis(800),
            max_ancestry: 32,
            cached_blocks: 4,
        }
    }
}

/// A block known to be final, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certified {
    /// The block.
    pub block: BlockRef,
    /// The certificate and the parent links from it down to the block.
    pub anchor: Anchor,
    /// The slot whose footer carried the certificate, or `None` if it was
    /// already held.
    pub found_in: Option<u64>,
}

/// A block that is now held, and what getting it took.
#[derive(Debug, Clone)]
pub struct HeldBlock {
    /// The block.
    pub block: BlockRef,
    /// Why it is final.
    pub anchor: Anchor,
    /// The slot whose footer carried the certificate, if it was looked for
    /// just now.
    pub found_in: Option<u64>,
    /// What the fetch cost, or `None` if the block was already held.
    pub fetch: Option<FetchStats>,
    /// Data shreds in the block.
    pub shreds: u32,
    /// Signatures of its transactions, in order.
    pub signatures: Vec<[u8; 64]>,
}

/// The outcome of proving every transaction of a block.
#[derive(Debug, Clone, Default)]
pub struct Proven {
    /// Encoded size of each proof that was built and verified.
    pub proof_sizes: Vec<usize>,
    /// Each transaction that was not proven, and why.
    pub failures: Vec<([u8; 64], Refusal)>,
}

struct Indexed {
    data: BlockData,
    anchor: Anchor,
}

/// An indexed block, and what was done just now to get it.
struct Ensured {
    indexed: Arc<Indexed>,
    found_in: Option<u64>,
    fetch: Option<FetchStats>,
}

impl Ensured {
    fn held(indexed: Arc<Indexed>) -> Self {
        Self {
            indexed,
            found_in: None,
            fetch: None,
        }
    }
}

/// The whole pipeline, on one thread.
pub struct Prover {
    trust: Arc<Trust>,
    store: Arc<Store>,
    fetcher: Fetcher,
    config: ProverConfig,
    cache: VecDeque<(u64, Arc<Indexed>)>,
}

/// The proof kept for `signature`, if there is one and it verifies now.
///
/// The store is a directory anyone with access can write to, so what comes
/// out of it gets the same check as a proof fresh from the builder.
pub fn held_proof(store: &Store, trust: &Trust, signature: &[u8; 64]) -> Option<Vec<u8>> {
    let bytes = store.proof(signature)?;
    let client = trust.client();
    let proof = TxProof::from_bytes(&bytes, client.limits()).ok()?;
    client.verify_signature(&proof, signature).ok()?;
    Some(bytes)
}

/// The certificate kept for the block of `slot`, if there is one and it
/// verifies now.
pub fn held_certificate(store: &Store, trust: &Trust, slot: u64) -> Option<FinalityCert> {
    let certificate = store.certificate(slot)?;
    trust.client().verify_finality(&certificate).ok()?;
    Some(certificate)
}

impl Prover {
    /// A prover that verifies with `trust`, keeps what it builds in
    /// `store`, and fetches with `fetcher`.
    pub fn new(
        trust: Arc<Trust>,
        store: Arc<Store>,
        fetcher: Fetcher,
        config: ProverConfig,
    ) -> Self {
        Self {
            trust,
            store,
            fetcher,
            config,
            cache: VecDeque::new(),
        }
    }

    /// What this prover verifies with.
    pub fn trust(&self) -> Arc<Trust> {
        Arc::clone(&self.trust)
    }

    /// Where this prover keeps what it builds.
    pub fn store(&self) -> Arc<Store> {
        Arc::clone(&self.store)
    }

    /// The fetcher, for its counters and peers.
    pub fn fetcher(&self) -> &Fetcher {
        &self.fetcher
    }

    /// Replaces the peers with a newer list.
    pub fn set_peers(&mut self, peers: PeerBook) {
        self.fetcher.set_peers(peers);
    }

    /// Finds a verified certificate that makes the block of `slot` final.
    ///
    /// Reads footers by slot, which proves nothing by itself: a certificate
    /// counts only once the verifier has accepted it against the pinned
    /// set. One that is refused is skipped, and the search goes on.
    pub fn certify(&mut self, slot: u64) -> Result<Certified, Refusal> {
        let trust = Arc::clone(&self.trust);
        let client = trust.client();
        if let Some(certificate) = held_certificate(&self.store, &trust, slot) {
            return Ok(Certified {
                block: certificate.block(),
                anchor: Anchor {
                    certificate,
                    links: Vec::new(),
                },
                found_in: None,
            });
        }
        let last = slot.saturating_add(self.config.certificate_window);
        let mut read = BTreeSet::new();
        let mut rejected = Vec::new();
        let mut lacking = None;
        for pass in 0..self.config.certificate_passes.max(1) {
            if pass > 0 {
                std::thread::sleep(self.config.pass_wait);
            }
            let mut missing_run = 0;
            for carrier in slot.saturating_add(1)..=last {
                if read.contains(&carrier) {
                    missing_run = 0;
                    continue;
                }
                // Going over the window again is for blocks that did not
                // exist yet. They appear in order, so past a whole leader
                // turn of slots still missing there is nothing newer.
                if pass > 0 && missing_run > LEADER_TURN {
                    break;
                }
                let Some(footer) = self.fetcher.footer(carrier)? else {
                    missing_run += 1;
                    continue;
                };
                missing_run = 0;
                read.insert(carrier);
                let Some(certificate) = footer.finality else {
                    continue;
                };
                let certified = certificate.block();
                match client.verify_finality(&certificate) {
                    Ok(_) => {
                        // Kept for whoever asks about that block next. A
                        // full disk is no reason to fail this request.
                        let _ = self.store.put_certificate(&certificate);
                        if certified.slot >= slot {
                            return self.descend(slot, certificate, carrier);
                        }
                    }
                    // Around an epoch boundary the next blocks may still
                    // carry certificates for the epoch before.
                    Err(Error::UnknownEpoch(epoch)) => {
                        lacking.get_or_insert((epoch, certified.slot));
                    }
                    Err(error) => rejected.push((carrier, error)),
                }
            }
            // Every footer in the window has been read: another pass
            // would find the same.
            if read.len() as u64 >= self.config.certificate_window {
                break;
            }
        }
        match lacking {
            Some((epoch, slot)) => Err(Refusal::EpochNotPinned {
                epoch,
                slot,
                pinned: trust.epochs(),
            }),
            None => Err(Refusal::NoCertificate {
                slot,
                searched_to: last,
                rejected,
            }),
        }
    }

    /// Follows parent links from a certified block down to `slot`.
    fn descend(
        &mut self,
        slot: u64,
        certificate: FinalityCert,
        found_in: u64,
    ) -> Result<Certified, Refusal> {
        let certified = certificate.block();
        let mut block = certified;
        let mut links = Vec::new();
        while block.slot > slot {
            if links.len() >= self.config.max_ancestry {
                return Err(Refusal::AncestryTooLong {
                    slot,
                    certified,
                    limit: self.config.max_ancestry,
                });
            }
            let link = self.fetcher.parent(&block)?;
            if link.parent.slot < slot {
                return Err(Refusal::NotFinalized {
                    slot,
                    certified,
                    between: (block.slot, link.parent.slot),
                });
            }
            block = link.parent;
            links.push(link);
        }
        Ok(Certified {
            block,
            anchor: Anchor { certificate, links },
            found_in: Some(found_in),
        })
    }

    /// Whether `anchor` makes `block` final: the certificate verifies and
    /// every link is the parent leaf of the block above it.
    fn anchors(&self, anchor: &Anchor, block: &BlockRef) -> bool {
        let mut child = anchor.certificate.block();
        self.trust
            .client()
            .verify_finality(&anchor.certificate)
            .is_ok()
            && anchor.links.iter().all(|link| {
                let held = link.verify(&child).is_ok();
                child = link.parent;
                held
            })
            && child == *block
    }

    fn index(block: &BlockRef, shreds: &[Vec<u8>]) -> Result<BlockData, Refusal> {
        let data = BlockData::from_shreds(shreds).map_err(|error| Refusal::Unprovable {
            block: *block,
            error,
        })?;
        if data.block() != *block {
            return Err(Refusal::Mismatch {
                block: *block,
                computed: data.block(),
            });
        }
        Ok(data)
    }

    fn remember(&mut self, slot: u64, indexed: Indexed) -> Arc<Indexed> {
        let indexed = Arc::new(indexed);
        self.cache.push_back((slot, Arc::clone(&indexed)));
        while self.cache.len() > self.config.cached_blocks.max(1) {
            self.cache.pop_front();
        }
        indexed
    }

    /// Makes sure the finalized block of `slot` is held and indexed.
    fn ensure(&mut self, slot: u64) -> Result<Ensured, Refusal> {
        if let Some((_, indexed)) = self.cache.iter().find(|(held, _)| *held == slot) {
            return Ok(Ensured::held(Arc::clone(indexed)));
        }
        if let Some(stored) = self.store.block(slot) {
            // A file is only a claim. It is taken if its anchor verifies
            // and its shreds hash to the block the anchor names.
            let indexed = Self::index(&stored.block, &stored.shreds)
                .ok()
                .filter(|_| self.anchors(&stored.anchor, &stored.block));
            match indexed {
                Some(data) => {
                    let indexed = Indexed {
                        data,
                        anchor: stored.anchor,
                    };
                    return Ok(Ensured::held(self.remember(slot, indexed)));
                }
                None => self.store.drop_block(slot),
            }
        }
        let certified = self.certify(slot)?;
        let fetched = self.fetcher.block(&certified.block)?;
        let data = Self::index(&certified.block, &fetched.shreds)?;
        self.store
            .put_block(&certified.block, &certified.anchor, &fetched.shreds)
            .map_err(|e| Refusal::Store(e.to_string()))?;
        let indexed = Indexed {
            data,
            anchor: certified.anchor,
        };
        Ok(Ensured {
            indexed: self.remember(slot, indexed),
            found_in: certified.found_in,
            fetch: Some(fetched.stats),
        })
    }

    /// Fetches the finalized block of `slot` by its certified id and keeps
    /// it, unless it is held already.
    pub fn fetch(&mut self, slot: u64) -> Result<HeldBlock, Refusal> {
        let Ensured {
            indexed,
            found_in,
            fetch,
        } = self.ensure(slot)?;
        Ok(HeldBlock {
            block: indexed.data.block(),
            anchor: indexed.anchor.clone(),
            found_in,
            fetch,
            shreds: indexed.data.shred_count(),
            signatures: indexed.data.signatures(),
        })
    }

    /// Builds the proof for `signature` from a held block and checks it
    /// with the verifier.
    fn build(&self, indexed: &Indexed, signature: &[u8; 64]) -> Result<Vec<u8>, Refusal> {
        let block = indexed.data.block();
        let (opened, component_start, position, footer_start) = indexed
            .data
            .prove_transaction(signature, true)
            .map_err(|error| match error {
                Error::SignatureNotFound => Refusal::NotInBlock { slot: block.slot },
                error => Refusal::Unprovable { block, error },
            })?;
        let proof = TxProof {
            finality: indexed.anchor.certificate.clone(),
            ancestry: indexed.anchor.links.clone(),
            block: opened,
            component_start,
            position,
            footer_start,
        };
        let rejected = |error| Refusal::ProofRejected { block, error };
        let bytes = proof.to_bytes().map_err(rejected)?;
        // From the bytes, as a client gets them, and with the client's own
        // limits: nothing leaves that a client holding this set refuses.
        let client = self.trust.client();
        let decoded = TxProof::from_bytes(&bytes, client.limits()).map_err(rejected)?;
        let verified = client
            .verify_signature(&decoded, signature)
            .map_err(rejected)?;
        if verified.block != block {
            return Err(rejected(Error::BlockIdMismatch));
        }
        Ok(bytes)
    }

    /// The proof that the transaction with `signature` is in the finalized
    /// block of `slot`: built, verified and kept.
    ///
    /// `slot` is a hint and is not trusted. If the transaction is not in
    /// that slot's finalized block the answer is [`Refusal::NotInBlock`].
    pub fn prove(&mut self, signature: &[u8; 64], slot: u64) -> Result<Vec<u8>, Refusal> {
        if let Some(bytes) = held_proof(&self.store, &self.trust, signature) {
            return Ok(bytes);
        }
        let indexed = self.ensure(slot)?.indexed;
        let bytes = self.build(&indexed, signature)?;
        self.store
            .put_proof(signature, &bytes)
            .map_err(|e| Refusal::Store(e.to_string()))?;
        Ok(bytes)
    }

    /// Proves and verifies every transaction of the block of `slot`,
    /// keeping none of the proofs. For measuring.
    pub fn prove_all(&mut self, slot: u64) -> Result<Proven, Refusal> {
        let indexed = self.ensure(slot)?.indexed;
        let mut proven = Proven::default();
        for signature in indexed.data.signatures() {
            match self.build(&indexed, &signature) {
                Ok(bytes) => proven.proof_sizes.push(bytes.len()),
                Err(refusal) => proven.failures.push((signature, refusal)),
            }
        }
        Ok(proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_thin::testkit::{legacy_transaction, simple_block, BlockBuilder};

    #[test]
    fn shreds_that_assemble_to_another_block_are_a_mismatch() {
        let parent = BlockRef {
            slot: 9,
            id: [9; 32],
        };
        let payloads = BlockBuilder::new(10, parent, 1)
            .header()
            .component(&solana_thin::testkit::entry_batch(&[vec![
                legacy_transaction(1, &[b"x"]),
            ]]))
            .build();
        let computed = BlockData::from_shreds(&payloads).unwrap().block();
        assert!(Prover::index(&computed, &payloads).is_ok());

        let other = simple_block(10, parent, 1, &[], None).block();
        assert_eq!(
            Prover::index(&other, &payloads).unwrap_err(),
            Refusal::Mismatch {
                block: other,
                computed
            }
        );
        // And shreds that assemble to nothing are unprovable, not a match.
        assert!(matches!(
            Prover::index(&computed, &payloads[..31]),
            Err(Refusal::Unprovable { .. })
        ));
    }
}
