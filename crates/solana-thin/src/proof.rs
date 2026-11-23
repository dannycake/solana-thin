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
use crate::wire::{Reader, Writer};
use std::collections::BTreeMap;

const MAGIC: &[u8; 3] = b"STP";
const VERSION: u8 = 1;

/// Upper bounds a verifier enforces before it does any work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest encoded proof, in bytes.
    pub max_proof_bytes: usize,
    /// Longest ancestry chain.
    pub max_ancestry: usize,
    /// Most FEC sets a block may claim. A slot's shred index is a `u32`, and a
    /// set holds 32 data shreds.
    pub max_fec_sets: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_proof_bytes: 8 << 20,
            max_ancestry: 4096,
            max_fec_sets: 1 << 15,
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
    pub fn verify(&self, child: &BlockRef, limits: &Limits) -> Result<()> {
        if self.parent.slot >= child.slot {
            return Err(Error::InvalidParent);
        }
        if self.fec_set_count == 0 || self.fec_set_count > limits.max_fec_sets {
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
    /// Root of the previous FEC set, which every shred of this set carries.
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
        limits: &Limits,
    ) -> Result<VerifiedShreds<'a>> {
        self.parent.verify(block, limits)?;
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
            let fec_set_index = set.set * DATA_SHREDS_PER_FEC_SET as u32;
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

    /// The bytes of the component that starts at shred `start`, as far as the
    /// proof supplies them.
    ///
    /// A component starts at shred 0 or right after a shred flagged
    /// `DATA_COMPLETE`, and runs through the next shred so flagged. The
    /// preceding shred must be in the proof so the start cannot be faked: a
    /// parse that begins in the middle of a component reads attacker-chosen
    /// bytes as if they were structure.
    pub(crate) fn component(&self, start: u32) -> Result<Vec<u8>> {
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(MAGIC);
        w.u8(VERSION);
        match &self.finality {
            FinalityCert::Fast { block, notar } => {
                w.u8(0);
                write_block(&mut w, block);
                write_aggregate(&mut w, notar);
            }
            FinalityCert::Slow {
                block,
                finalize,
                notar,
            } => {
                w.u8(1);
                write_block(&mut w, block);
                write_aggregate(&mut w, finalize);
                write_aggregate(&mut w, notar);
            }
        }
        w.u16(self.ancestry.len() as u16);
        for link in &self.ancestry {
            write_link(&mut w, link);
        }
        write_link(&mut w, &self.block.parent);
        w.u16(self.block.sets.len() as u16);
        for set in &self.block.sets {
            w.u32(set.set);
            w.u8(set.first);
            w.u8(set.shreds.len() as u8);
            w.bytes(&set.chained_root);
            for shred in &set.shreds {
                w.u8(shred.variant);
                w.u16(shred.parent_offset);
                w.u8(shred.flags);
                w.u16(shred.size);
                w.u16(shred.body.len() as u16);
                w.bytes(&shred.body);
            }
            write_nodes(&mut w, &set.siblings);
            w.bytes(&set.coding_root);
            write_nodes(&mut w, &set.path);
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
        w.buf
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
        let finality = match r.u8()? {
            0 => FinalityCert::Fast {
                block: read_block(&mut r)?,
                notar: read_aggregate(&mut r)?,
            },
            1 => FinalityCert::Slow {
                block: read_block(&mut r)?,
                finalize: read_aggregate(&mut r)?,
                notar: read_aggregate(&mut r)?,
            },
            _ => return Err(Error::Malformed("certificate kind")),
        };
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

fn write_block(w: &mut Writer, block: &BlockRef) {
    w.u64(block.slot);
    w.bytes(&block.id);
}

fn read_block(r: &mut Reader<'_>) -> Result<BlockRef> {
    Ok(BlockRef {
        slot: r.u64()?,
        id: r.array()?,
    })
}

fn write_aggregate(w: &mut Writer, aggregate: &Aggregate) {
    w.bytes(&aggregate.signature);
    w.u16(aggregate.bitmap.len() as u16);
    w.bytes(&aggregate.bitmap);
}

fn read_aggregate(r: &mut Reader<'_>) -> Result<Aggregate> {
    let signature = r.array()?;
    let len = usize::from(r.u16()?);
    Ok(Aggregate {
        signature,
        bitmap: r.bytes(len)?.to_vec(),
    })
}

fn write_nodes(w: &mut Writer, nodes: &[Node]) {
    w.u8(nodes.len() as u8);
    for node in nodes {
        w.bytes(node);
    }
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

fn write_link(w: &mut Writer, link: &ParentLink) {
    write_block(w, &link.parent);
    w.u32(link.fec_set_count);
    write_nodes(w, &link.path);
}

fn read_link(r: &mut Reader<'_>) -> Result<ParentLink> {
    Ok(ParentLink {
        parent: read_block(r)?,
        fec_set_count: r.u32()?,
        path: read_nodes(r)?,
    })
}
