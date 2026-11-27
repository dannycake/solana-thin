//! The proof a thin client is handed, and the checks that tie it to a block id.
//!
//! A [`TxProof`] answers one question: *is this transaction in a finalized
//! block?* It has three parts, checked in this order:
//!
//! 1. A [`FinalityCert`] for some block `F`.
//! 2. An ancestry chain of [`ParentLink`]s from `F` back to the block `B` that
//!    holds the transaction (empty when `B` is `F`). Finality of a block
//!    finalizes all of its ancestors.
//! 3. A [`BlockProof`] opening the shreds of `B` that hold the transaction,
//!    plus the few extra shreds needed to show where the transaction's
//!    component starts and that none of the block was abandoned.

use crate::block::TxPosition;
use crate::certificate::{Aggregate, BlockRef, FinalityCert};
use crate::error::{Error, Result};
use crate::merkle::{self, Hash, Node, DATA_SHREDS_PER_FEC_SET};
use crate::shred::DataShred;
use crate::wire::{Reader, Sink, Writer};
use std::collections::BTreeMap;

const MAGIC: &[u8; 3] = b"STP";
const VERSION: u8 = 1;

/// The most FEC sets a block can have: 32,768 data shreds in sets of 32.
///
/// A consensus rule, not a tunable. Validators refuse a parent leaf that
/// claims more (`MAX_FEC_SETS_PER_SLOT`, checked in Agave's
/// `core/src/repair/serve_repair.rs`), so no finalized block does.
pub const MAX_FEC_SETS_PER_SLOT: u32 = 1024;

/// Upper bounds a verifier enforces before it does any work.
///
/// [`TxProof::from_bytes`] applies the ones it is given to the bytes, and a
/// [`ThinClient`](crate::ThinClient) applies its own to every proof it
/// checks.
///
/// Start from [`Limits::default`] and change what you need:
///
/// ```
/// let limits = solana_thin::Limits::default()
///     .with_max_proof_bytes(256 << 10)
///     .with_max_ancestry(64);
/// assert_eq!(limits.max_proof_bytes, 262_144);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest encoded proof, in bytes. 8 MiB by default.
    pub max_proof_bytes: usize,
    /// Longest ancestry chain. 4,096 links by default.
    pub max_ancestry: usize,
}

impl Limits {
    /// These limits with another cap on the encoded proof, in bytes.
    pub const fn with_max_proof_bytes(mut self, max_proof_bytes: usize) -> Self {
        self.max_proof_bytes = max_proof_bytes;
        self
    }

    /// These limits with another cap on the ancestry chain, in links.
    pub const fn with_max_ancestry(mut self, max_ancestry: usize) -> Self {
        self.max_ancestry = max_ancestry;
        self
    }

    /// Holds a decoded proof to these limits, in the order
    /// [`TxProof::from_bytes`] applies them to its bytes: size, then
    /// ancestry. The size is the proof's encoded size, so a proof that
    /// cannot be encoded at all is refused too.
    pub(crate) fn check(&self, proof: &TxProof) -> Result<()> {
        if proof.encoded_len()? > self.max_proof_bytes {
            return Err(Error::LimitExceeded("proof size"));
        }
        if proof.ancestry.len() > self.max_ancestry {
            return Err(Error::LimitExceeded("ancestry length"));
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_proof_bytes: 8 << 20,
            max_ancestry: 4096,
        }
    }
}

/// The last leaf of a block's tree: its parent, and how many FEC sets it has.
///
/// The leaf is `sha256(parent_slot ‖ parent_id ‖ fec_set_count)` and sits at
/// index `fec_set_count`, after the FEC set roots. Binding the count into the
/// leaf is what lets a verifier trust the tree's size, and with it every
/// other leaf index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentLink {
    /// The parent block.
    pub parent: BlockRef,
    /// Number of FEC sets in the child block.
    pub fec_set_count: u32,
    /// Merkle path from the parent leaf to the child's block id.
    pub path: Vec<Node>,
}

impl ParentLink {
    /// Checks that `child` commits to this parent and FEC set count.
    pub fn verify(&self, child: &BlockRef) -> Result<()> {
        if self.parent.slot >= child.slot {
            return Err(Error::InvalidParent);
        }
        if self.fec_set_count == 0 || self.fec_set_count > MAX_FEC_SETS_PER_SLOT {
            return Err(Error::LimitExceeded("FEC set count"));
        }
        let leaf = merkle::sha256(&[
            &self.parent.slot.to_le_bytes(),
            &self.parent.id,
            &self.fec_set_count.to_le_bytes(),
        ]);
        let count = self.fec_set_count as usize;
        let root = merkle::root_from_path(count, count + 1, leaf, &self.path)?;
        if root != child.id {
            return Err(Error::BlockIdMismatch);
        }
        Ok(())
    }
}

/// A contiguous run of data shreds from one FEC set, with what is needed to
/// hash them up to the block id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecSetProof {
    /// Which FEC set of the block, counting from zero.
    pub set: u32,
    /// Position within the set of the first shred in `shreds` (0 to 31).
    pub first: u8,
    /// The shreds, consecutive from `first`.
    pub shreds: Vec<DataShred>,
    /// The 32 bytes every shred of this set carries in its "chained root"
    /// field. They are part of what is hashed, so the proof must supply
    /// them, but nothing checks them: since Alpenglow, validators no longer
    /// require them to be the previous set's root. Treat them as bytes the
    /// leader chose.
    pub chained_root: Hash,
    /// Subtree hashes covering the set's other data shreds.
    pub siblings: Vec<Node>,
    /// Root of the subtree over the set's 32 coding shreds.
    pub coding_root: Node,
    /// Merkle path from the FEC set root to the block id.
    pub path: Vec<Node>,
}

/// Openings of some of a block's data shreds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockProof {
    /// The block's parent leaf.
    pub parent: ParentLink,
    /// The opened shreds, grouped by FEC set.
    pub sets: Vec<FecSetProof>,
}

/// Shreds of one block that have been tied to its id.
pub(crate) struct VerifiedShreds<'a> {
    pub(crate) parent: BlockRef,
    shreds: BTreeMap<u32, &'a DataShred>,
}

impl BlockProof {
    /// Ties every shred in the proof to `block`.
    ///
    /// For each shred this rebuilds the bytes a validator hashed, using the
    /// slot from `block`, the index from where the proof places the shred, and
    /// the caller's `shred_version`. A shred therefore only verifies at the
    /// one position it really occupies.
    pub(crate) fn verify<'a>(
        &'a self,
        block: &BlockRef,
        shred_version: u16,
    ) -> Result<VerifiedShreds<'a>> {
        self.parent.verify(block)?;
        let fec_set_count = self.parent.fec_set_count;
        let tree_leaves = fec_set_count as usize + 1;
        let mut shreds = BTreeMap::new();
        let mut seen_sets = std::collections::BTreeSet::new();
        for set in &self.sets {
            if set.set >= fec_set_count {
                return Err(Error::InvalidShred("FEC set outside the block"));
            }
            if !seen_sets.insert(set.set) {
                return Err(Error::DuplicateShred);
            }
            let first = usize::from(set.first);
            if set.shreds.is_empty() || first + set.shreds.len() > DATA_SHREDS_PER_FEC_SET {
                return Err(Error::InvalidShred("run outside its FEC set"));
            }
            let fec_set_index = set
                .set
                .checked_mul(DATA_SHREDS_PER_FEC_SET as u32)
                .ok_or(Error::InvalidShred("FEC set outside the block"))?;
            let mut leaves = Vec::with_capacity(set.shreds.len());
            for (offset, shred) in set.shreds.iter().enumerate() {
                let index = fec_set_index + (first + offset) as u32;
                leaves.push(shred.leaf_hash(
                    block.slot,
                    index,
                    shred_version,
                    fec_set_index,
                    &set.chained_root,
                )?);
                shreds.insert(index, shred);
            }
            let data_root = merkle::data_range_root(first, &leaves, &set.siblings)?;
            let fec_root = merkle::join(&data_root, &set.coding_root);
            let root = merkle::root_from_path(set.set as usize, tree_leaves, fec_root, &set.path)?;
            if root != block.id {
                return Err(Error::BlockIdMismatch);
            }
        }
        Ok(VerifiedShreds {
            parent: self.parent.parent,
            shreds,
        })
    }
}

impl<'a> VerifiedShreds<'a> {
    fn get(&self, index: u32) -> Result<&'a DataShred> {
        self.shreds
            .get(&index)
            .copied()
            .ok_or(Error::MissingShred(index))
    }

    /// The data of shred 0 alone, where a validator looks for the block
    /// header.
    ///
    /// Agave's blockstore records the header's parent only if the header
    /// parses from shred 0's own bytes (`ParentInfo::maybe_parse_block_header`
    /// in `ledger/src/blockstore.rs`). A header that runs on into shred 1 is
    /// a header to anyone who reads the whole component, and no header at all
    /// to the blockstore. The verifier has to see what the blockstore sees.
    pub(crate) fn first_shred_data(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.get(0)?.append_data(&mut data)?;
        Ok(data)
    }

    /// Checks that every opened shred names parent slot `parent_slot`.
    ///
    /// Each data shred carries how many slots back its parent is. A
    /// validator kills a slot whose header names a different parent slot
    /// than its shreds do, and never completes one whose shreds disagree
    /// with each other, so a finalized block's shreds all name one slot.
    fn offsets_name(&self, slot: u64, parent_slot: u64) -> Result<()> {
        let expected = slot.checked_sub(parent_slot);
        for shred in self.shreds.values() {
            if Some(u64::from(shred.parent_offset)) != expected {
                return Err(Error::InvalidShred(
                    "parent offset does not name the block's parent",
                ));
            }
        }
        Ok(())
    }

    /// Checks that every opened shred names the parent the block's tree
    /// commits to. For a block that did not switch parent, that parent slot
    /// is the distance every shred's offset records.
    pub(crate) fn check_parent_offset(&self, slot: u64) -> Result<()> {
        self.offsets_name(slot, self.parent.slot)
    }

    /// Checks that every opened shred names the header's parent `header_parent`.
    ///
    /// A block that switched parent keeps the shred headers it was first shred
    /// with: every shred still records the distance to the *header's* parent,
    /// not to the parent an `UpdateParent` marker moved replay onto. (Confirmed
    /// against Agave: the shred parent offset is one slot-wide value, checked
    /// equal to the block header's parent and `>=` the marker's.)
    #[cfg(feature = "fast-leader-handover")]
    pub(crate) fn check_parent_offset_switched(
        &self,
        slot: u64,
        header_parent: &BlockRef,
    ) -> Result<()> {
        self.offsets_name(slot, header_parent.slot)
    }

    /// The one opened `UpdateParent` marker: its component start `u` (a FEC-set
    /// boundary) and the parent it names. An error if the opened shreds show
    /// no such marker, or more than one.
    ///
    /// Only the opened shreds are scanned; `component` already enforces that a
    /// start is a FEC-set boundary whose previous shred is `DATA_COMPLETE`.
    /// "At most one marker in the whole block" is relied on from finality, as
    /// with other rules a certificate already enforces: a block Agave marked
    /// dead for a second marker (`MultipleUpdateParents`) has no certificate to
    /// reach this check.
    #[cfg(feature = "fast-leader-handover")]
    pub(crate) fn single_opened_update_parent(&self) -> Result<(u32, BlockRef)> {
        use crate::block::Marker;
        let per_set = DATA_SHREDS_PER_FEC_SET as u32;
        let mut found: Option<(u32, BlockRef)> = None;
        for &index in self.shreds.keys() {
            if index % per_set != 0 {
                continue;
            }
            // Skip a boundary whose previous shred is not opened and
            // `DATA_COMPLETE`; `component` would refuse it anyway.
            if index > 0
                && !self
                    .get(index - 1)
                    .map(|s| s.data_complete())
                    .unwrap_or(false)
            {
                continue;
            }
            let data = self.component(index)?;
            if let Ok(Marker::UpdateParent { parent }) = crate::block::parse_marker(&data) {
                if found.is_some() {
                    return Err(Error::UpdateParentBlock);
                }
                found = Some((index, parent));
            }
        }
        found.ok_or(Error::UpdateParentBlock)
    }

    /// The bytes of the component that starts at shred `start`, as far as the
    /// proof supplies them.
    ///
    /// A component starts at shred 0 or right after a shred flagged
    /// `DATA_COMPLETE`, and runs through the next shred so flagged. The
    /// preceding shred must be in the proof so the start cannot be faked: a
    /// parse that begins in the middle of a component reads attacker-chosen
    /// bytes as if they were structure.
    pub(crate) fn component(&self, start: u32) -> Result<Vec<u8>> {
        // A component ends only on the last data shred of a FEC set, so one
        // starts only on the first of a set. The flag check below implies
        // this; saying it outright costs nothing.
        if start % DATA_SHREDS_PER_FEC_SET as u32 != 0 {
            return Err(Error::NotComponentStart);
        }
        if start > 0 && !self.get(start - 1)?.data_complete() {
            return Err(Error::NotComponentStart);
        }
        let mut data = Vec::new();
        let mut index = start;
        loop {
            let Some(shred) = self.shreds.get(&index) else {
                if index == start {
                    return Err(Error::MissingShred(start));
                }
                break;
            };
            shred.append_data(&mut data)?;
            if shred.data_complete() {
                break;
            }
            index = index.checked_add(1).ok_or(Error::InvalidShred("index"))?;
        }
        Ok(data)
    }
}

/// Everything needed to believe one transaction is in a finalized block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxProof {
    /// Certificate for a block at or after the transaction's block.
    pub finality: FinalityCert,
    /// Parent links from the certified block back to the transaction's block,
    /// newest first. Empty when the certificate is for the transaction's block.
    pub ancestry: Vec<ParentLink>,
    /// Opened shreds of the transaction's block.
    pub block: BlockProof,
    /// Index of the first shred of the component holding the transaction.
    pub component_start: u32,
    /// Where the transaction sits in that component.
    pub position: TxPosition,
    /// Index of the first shred of the block's footer, if the proof opens it.
    pub footer_start: Option<u32>,
}

impl TxProof {
    /// Serializes the proof.
    ///
    /// Fails with [`Error::TooLargeToEncode`] if a list or byte string is
    /// longer than its count field can say, rather than write a count that
    /// would decode to a different proof. A proof that
    /// [`from_bytes`](Self::from_bytes) returned always encodes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        self.encode(&mut w)?;
        Ok(w.buf)
    }

    /// The number of bytes [`to_bytes`](Self::to_bytes) would produce,
    /// without producing them. Fails where `to_bytes` fails.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut w = Writer { buf: 0usize };
        self.encode(&mut w)?;
        Ok(w.buf)
    }

    fn encode<S: Sink>(&self, w: &mut Writer<S>) -> Result<()> {
        w.bytes(MAGIC);
        w.u8(VERSION);
        write_finality(w, &self.finality)?;
        w.count_u16(self.ancestry.len(), "ancestry length")?;
        for link in &self.ancestry {
            write_link(w, link)?;
        }
        write_link(w, &self.block.parent)?;
        w.count_u16(self.block.sets.len(), "FEC set count")?;
        for set in &self.block.sets {
            w.u32(set.set);
            w.u8(set.first);
            w.count_u8(set.shreds.len(), "shred count")?;
            w.bytes(&set.chained_root);
            for shred in &set.shreds {
                w.u8(shred.variant);
                w.u16(shred.parent_offset);
                w.u8(shred.flags);
                w.u16(shred.size);
                w.count_u16(shred.body.len(), "shred body")?;
                w.bytes(&shred.body);
            }
            write_nodes(w, &set.siblings)?;
            w.bytes(&set.coding_root);
            write_nodes(w, &set.path)?;
        }
        w.u32(self.component_start);
        w.u32(self.position.entry);
        w.u32(self.position.transaction);
        match self.footer_start {
            None => w.u8(0),
            Some(start) => {
                w.u8(1);
                w.u32(start);
            }
        }
        Ok(())
    }

    /// Parses a proof. Rejects unknown versions, lengths the input cannot
    /// back, and any bytes left over.
    pub fn from_bytes(bytes: &[u8], limits: &Limits) -> Result<Self> {
        if bytes.len() > limits.max_proof_bytes {
            return Err(Error::LimitExceeded("proof size"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(3)? != MAGIC {
            return Err(Error::Malformed("magic"));
        }
        let version = r.u8()?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let finality = read_finality(&mut r)?;
        let links = usize::from(r.u16()?);
        if links > limits.max_ancestry {
            return Err(Error::LimitExceeded("ancestry length"));
        }
        let links = r.bounded_count(links, 45)?;
        let mut ancestry = Vec::with_capacity(links);
        for _ in 0..links {
            ancestry.push(read_link(&mut r)?);
        }
        let parent = read_link(&mut r)?;
        let set_count = usize::from(r.u16()?);
        let set_count = r.bounded_count(set_count, 60)?;
        let mut sets = Vec::with_capacity(set_count);
        for _ in 0..set_count {
            let set = r.u32()?;
            let first = r.u8()?;
            let shred_count = usize::from(r.u8()?);
            if shred_count > DATA_SHREDS_PER_FEC_SET {
                return Err(Error::Malformed("shred count"));
            }
            let chained_root = r.array()?;
            let mut shreds = Vec::with_capacity(shred_count);
            for _ in 0..shred_count {
                let variant = r.u8()?;
                let parent_offset = r.u16()?;
                let flags = r.u8()?;
                let size = r.u16()?;
                let body_len = usize::from(r.u16()?);
                let body = r.bytes(body_len)?.to_vec();
                if body.last() == Some(&0) {
                    // One encoding per shred: trailing zeros are implied.
                    return Err(Error::Malformed("shred body padding"));
                }
                shreds.push(DataShred {
                    variant,
                    parent_offset,
                    flags,
                    size,
                    body,
                });
            }
            let siblings = read_nodes(&mut r)?;
            let coding_root = r.array()?;
            let path = read_nodes(&mut r)?;
            sets.push(FecSetProof {
                set,
                first,
                shreds,
                chained_root,
                siblings,
                coding_root,
                path,
            });
        }
        let component_start = r.u32()?;
        let position = TxPosition {
            entry: r.u32()?,
            transaction: r.u32()?,
        };
        let footer_start = match r.u8()? {
            0 => None,
            1 => Some(r.u32()?),
            _ => return Err(Error::Malformed("footer tag")),
        };
        r.finish()?;
        Ok(Self {
            finality,
            ancestry,
            block: BlockProof { parent, sets },
            component_start,
            position,
            footer_start,
        })
    }
}

impl FinalityCert {
    /// The certificate alone, in the layout it has at the front of a proof:
    /// a kind (0 fast, 1 slow), the slot, the block id, then each aggregate
    /// as its 96-byte signature, a `u16` length and the signer bitmap.
    ///
    /// For passing a certificate around on its own, as a prover does when
    /// asked which certificate finalized a slot. The bytes are no more
    /// trusted than any other: check the result with
    /// [`ThinClient::verify_finality`](crate::ThinClient::verify_finality).
    /// Fails only for a bitmap longer than a `u16` can count.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        write_finality(&mut w, self)?;
        Ok(w.buf)
    }

    /// Reads [`to_bytes`](Self::to_bytes) back, refusing anything but
    /// exactly one certificate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let finality = read_finality(&mut r)?;
        r.finish()?;
        Ok(finality)
    }
}

fn write_finality<S: Sink>(w: &mut Writer<S>, finality: &FinalityCert) -> Result<()> {
    match finality {
        FinalityCert::Fast { block, notar } => {
            w.u8(0);
            write_block(w, block);
            write_aggregate(w, notar)
        }
        FinalityCert::Slow {
            block,
            finalize,
            notar,
        } => {
            w.u8(1);
            write_block(w, block);
            write_aggregate(w, finalize)?;
            write_aggregate(w, notar)
        }
    }
}

fn read_finality(r: &mut Reader<'_>) -> Result<FinalityCert> {
    Ok(match r.u8()? {
        0 => FinalityCert::Fast {
            block: read_block(r)?,
            notar: read_aggregate(r)?,
        },
        1 => FinalityCert::Slow {
            block: read_block(r)?,
            finalize: read_aggregate(r)?,
            notar: read_aggregate(r)?,
        },
        _ => return Err(Error::Malformed("certificate kind")),
    })
}

fn write_block<S: Sink>(w: &mut Writer<S>, block: &BlockRef) {
    w.u64(block.slot);
    w.bytes(&block.id);
}

fn read_block(r: &mut Reader<'_>) -> Result<BlockRef> {
    Ok(BlockRef {
        slot: r.u64()?,
        id: r.array()?,
    })
}

fn write_aggregate<S: Sink>(w: &mut Writer<S>, aggregate: &Aggregate) -> Result<()> {
    w.bytes(&aggregate.signature);
    w.count_u16(aggregate.bitmap.len(), "signer bitmap")?;
    w.bytes(&aggregate.bitmap);
    Ok(())
}

fn read_aggregate(r: &mut Reader<'_>) -> Result<Aggregate> {
    let signature = r.array()?;
    let len = usize::from(r.u16()?);
    Ok(Aggregate {
        signature,
        bitmap: r.bytes(len)?.to_vec(),
    })
}

fn write_nodes<S: Sink>(w: &mut Writer<S>, nodes: &[Node]) -> Result<()> {
    w.count_u8(nodes.len(), "Merkle path")?;
    for node in nodes {
        w.bytes(node);
    }
    Ok(())
}

fn read_nodes(r: &mut Reader<'_>) -> Result<Vec<Node>> {
    let count = usize::from(r.u8()?);
    let count = r.bounded_count(count, 20)?;
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        nodes.push(r.array()?);
    }
    Ok(nodes)
}

fn write_link<S: Sink>(w: &mut Writer<S>, link: &ParentLink) -> Result<()> {
    write_block(w, &link.parent);
    w.u32(link.fec_set_count);
    write_nodes(w, &link.path)
}

fn read_link(r: &mut Reader<'_>) -> Result<ParentLink> {
    Ok(ParentLink {
        parent: read_block(r)?,
        fec_set_count: r.u32()?,
        path: read_nodes(r)?,
    })
}
