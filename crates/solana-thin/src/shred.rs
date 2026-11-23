//! Data shreds: the 1,203-byte frames a Solana block is cut into.
//!
//! Layout of a data shred as validators send it (Agave,
//! `shred/wire-format/src/constants.rs`):
//!
//! ```text
//!  0        64       83      88                   1051      1083       1203
//!  | signature | common | data |       body         | chained  | Merkle   |
//!  |           | header | hdr  | (zero padded)      | root     | proof    |
//!               '------------- hashed into the leaf ----------'
//! ```
//!
//! A "resigned" shred carries a second signature at the very end and has a
//! body 64 bytes shorter; everything else is the same.
//!
//! A proof does not carry whole shreds. The slot, index, shred version and FEC
//! set index are all known from context, the padding is zeros, and the chained
//! root is shared by a whole FEC set, so a [`DataShred`] keeps only the three
//! header fields that vary plus the body with trailing zeros removed. The
//! verifier rebuilds the exact bytes that were hashed.

use crate::error::{Error, Result};
use crate::merkle::{self, Hash, Node};

/// Bytes in a data shred on the wire.
pub const DATA_SHRED_SIZE: usize = 1203;
const SIGNATURE_SIZE: usize = 64;
/// Signature, common header and data header.
pub const DATA_HEADERS_SIZE: usize = 88;
const MERKLE_PROOF_ENTRIES: usize = 6;
const MERKLE_PROOF_SIZE: usize = MERKLE_PROOF_ENTRIES * 20;
const CHAINED_ROOT_SIZE: usize = 32;

/// Variant byte of an ordinary Merkle data shred.
pub const VARIANT_DATA: u8 = 0x96;
/// Variant byte of a data shred that also carries a retransmitter signature.
pub const VARIANT_DATA_RESIGNED: u8 = 0xb6;

/// Set on the last shred of a block component.
pub const FLAG_DATA_COMPLETE: u8 = 0b0100_0000;

/// Body bytes a data shred of this variant can hold, or `None` if the variant
/// is not a Merkle data shred with the fixed 32+32 erasure layout.
pub fn body_capacity(variant: u8) -> Option<usize> {
    let trailer = CHAINED_ROOT_SIZE + MERKLE_PROOF_SIZE;
    match variant {
        VARIANT_DATA => Some(DATA_SHRED_SIZE - DATA_HEADERS_SIZE - trailer),
        VARIANT_DATA_RESIGNED => {
            Some(DATA_SHRED_SIZE - DATA_HEADERS_SIZE - trailer - SIGNATURE_SIZE)
        }
        _ => None,
    }
}

/// The parts of a data shred that a proof has to carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataShred {
    /// The shred variant byte.
    pub variant: u8,
    /// Slots back to the parent, as the leader wrote it.
    pub parent_offset: u16,
    /// Completion markers and the reference tick.
    pub flags: u8,
    /// Headers plus meaningful body bytes; the rest of the body is padding.
    pub size: u16,
    /// The body with trailing zero bytes removed.
    pub body: Vec<u8>,
}

impl DataShred {
    /// Number of meaningful body bytes, after checking that `size` is one a
    /// validator would accept.
    pub fn data_len(&self) -> Result<usize> {
        let capacity = body_capacity(self.variant).ok_or(Error::InvalidShred("variant"))?;
        let size = usize::from(self.size);
        if size < DATA_HEADERS_SIZE || size > DATA_HEADERS_SIZE + capacity {
            return Err(Error::InvalidShred("size"));
        }
        if self.body.len() > capacity {
            return Err(Error::InvalidShred("body longer than capacity"));
        }
        Ok(size - DATA_HEADERS_SIZE)
    }

    /// Appends the meaningful body bytes to `out`.
    pub fn append_data(&self, out: &mut Vec<u8>) -> Result<()> {
        let len = self.data_len()?;
        let have = self.body.len().min(len);
        out.extend_from_slice(&self.body[..have]);
        out.resize(out.len() + (len - have), 0);
        Ok(())
    }

    /// Whether this shred ends a block component.
    pub fn data_complete(&self) -> bool {
        self.flags & FLAG_DATA_COMPLETE != 0
    }

    /// Rebuilds the bytes a validator hashed for this shred: everything from
    /// the variant byte to the end of the chained root.
    ///
    /// The position (`slot`, `index`, `fec_set_index`) and `shred_version` are
    /// supplied by the verifier from where the proof *claims* the shred sits.
    /// Because they are part of the hashed bytes, a shred moved to another
    /// slot, index or cluster produces a different leaf and the proof fails.
    pub fn leaf_bytes(
        &self,
        slot: u64,
        index: u32,
        shred_version: u16,
        fec_set_index: u32,
        chained_root: &Hash,
    ) -> Result<Vec<u8>> {
        let capacity = body_capacity(self.variant).ok_or(Error::InvalidShred("variant"))?;
        self.data_len()?;
        let mut leaf = Vec::with_capacity(24 + capacity + CHAINED_ROOT_SIZE);
        leaf.push(self.variant);
        leaf.extend_from_slice(&slot.to_le_bytes());
        leaf.extend_from_slice(&index.to_le_bytes());
        leaf.extend_from_slice(&shred_version.to_le_bytes());
        leaf.extend_from_slice(&fec_set_index.to_le_bytes());
        leaf.extend_from_slice(&self.parent_offset.to_le_bytes());
        leaf.push(self.flags);
        leaf.extend_from_slice(&self.size.to_le_bytes());
        leaf.extend_from_slice(&self.body);
        leaf.resize(24 + capacity, 0);
        leaf.extend_from_slice(chained_root);
        Ok(leaf)
    }

    /// The Merkle leaf hash of this shred at the given position.
    pub fn leaf_hash(
        &self,
        slot: u64,
        index: u32,
        shred_version: u16,
        fec_set_index: u32,
        chained_root: &Hash,
    ) -> Result<Hash> {
        Ok(merkle::shred_leaf(&self.leaf_bytes(
            slot,
            index,
            shred_version,
            fec_set_index,
            chained_root,
        )?))
    }
}

/// A data shred exactly as a node stores it, parsed for the prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDataShred {
    /// Slot the shred belongs to.
    pub slot: u64,
    /// Index of the shred within the slot.
    pub index: u32,
    /// Shred version of the cluster.
    pub shred_version: u16,
    /// Index of the first data shred of this shred's FEC set.
    pub fec_set_index: u32,
    /// Root of the previous FEC set, as chained by the leader.
    pub chained_root: Hash,
    /// The shred's own path to its FEC set root.
    pub proof: [Node; MERKLE_PROOF_ENTRIES],
    /// The fields a proof carries.
    pub shred: DataShred,
}

impl RawDataShred {
    /// Parses a full data shred payload.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < DATA_SHRED_SIZE {
            return Err(Error::InvalidShred("payload too short"));
        }
        let payload = &payload[..DATA_SHRED_SIZE];
        let variant = payload[64];
        let capacity = body_capacity(variant).ok_or(Error::InvalidShred("variant"))?;
        let slot = u64::from_le_bytes(payload[65..73].try_into().unwrap());
        let index = u32::from_le_bytes(payload[73..77].try_into().unwrap());
        let shred_version = u16::from_le_bytes(payload[77..79].try_into().unwrap());
        let fec_set_index = u32::from_le_bytes(payload[79..83].try_into().unwrap());
        let parent_offset = u16::from_le_bytes(payload[83..85].try_into().unwrap());
        let flags = payload[85];
        let size = u16::from_le_bytes(payload[86..88].try_into().unwrap());
        let body_end = DATA_HEADERS_SIZE + capacity;
        let body = &payload[DATA_HEADERS_SIZE..body_end];
        let trimmed = body.len() - body.iter().rev().take_while(|b| **b == 0).count();
        let mut chained_root = [0u8; 32];
        chained_root.copy_from_slice(&payload[body_end..body_end + CHAINED_ROOT_SIZE]);
        let mut proof = [[0u8; 20]; MERKLE_PROOF_ENTRIES];
        let proof_start = body_end + CHAINED_ROOT_SIZE;
        for (i, entry) in proof.iter_mut().enumerate() {
            entry.copy_from_slice(&payload[proof_start + 20 * i..proof_start + 20 * (i + 1)]);
        }
        let shred = DataShred {
            variant,
            parent_offset,
            flags,
            size,
            body: body[..trimmed].to_vec(),
        };
        shred.data_len()?;
        Ok(Self {
            slot,
            index,
            shred_version,
            fec_set_index,
            chained_root,
            proof,
            shred,
        })
    }

    /// The leaf hash of this shred at the position its own header states.
    pub fn leaf_hash(&self) -> Result<Hash> {
        self.shred.leaf_hash(
            self.slot,
            self.index,
            self.shred_version,
            self.fec_set_index,
            &self.chained_root,
        )
    }

    /// Root of this shred's FEC set, computed from its embedded path.
    pub fn fec_set_root(&self) -> Result<Hash> {
        let position = self
            .index
            .checked_sub(self.fec_set_index)
            .filter(|p| (*p as usize) < merkle::DATA_SHREDS_PER_FEC_SET)
            .ok_or(Error::InvalidShred("index outside its FEC set"))?;
        merkle::root_from_path(position as usize, 64, self.leaf_hash()?, &self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacities_match_agave_constants() {
        assert_eq!(body_capacity(VARIANT_DATA), Some(963));
        assert_eq!(body_capacity(VARIANT_DATA_RESIGNED), Some(899));
        // Coding shreds and legacy variants are not data shreds.
        assert_eq!(body_capacity(0x66), None);
        assert_eq!(body_capacity(0x76), None);
        assert_eq!(body_capacity(0xa5), None);
    }

    #[test]
    fn size_bounds_follow_the_validator() {
        let mut shred = DataShred {
            variant: VARIANT_DATA,
            parent_offset: 1,
            flags: 0,
            size: 87,
            body: vec![],
        };
        assert!(shred.data_len().is_err());
        shred.size = 88;
        assert_eq!(shred.data_len().unwrap(), 0);
        shred.size = 88 + 963;
        assert_eq!(shred.data_len().unwrap(), 963);
        shred.size = 88 + 964;
        assert!(shred.data_len().is_err());
        shred.variant = VARIANT_DATA_RESIGNED;
        shred.size = 88 + 900;
        assert!(shred.data_len().is_err());
    }

    #[test]
    fn data_is_zero_extended_to_size() {
        let shred = DataShred {
            variant: VARIANT_DATA,
            parent_offset: 1,
            flags: 0,
            size: 88 + 5,
            body: vec![9, 8],
        };
        let mut out = vec![1];
        shred.append_data(&mut out).unwrap();
        assert_eq!(out, [1, 9, 8, 0, 0, 0]);
    }

    #[test]
    fn position_is_part_of_the_leaf() {
        let shred = DataShred {
            variant: VARIANT_DATA,
            parent_offset: 1,
            flags: FLAG_DATA_COMPLETE,
            size: 88 + 3,
            body: vec![1, 2, 3],
        };
        let base = shred.leaf_hash(10, 32, 7, 32, &[0; 32]).unwrap();
        assert_ne!(base, shred.leaf_hash(11, 32, 7, 32, &[0; 32]).unwrap());
        assert_ne!(base, shred.leaf_hash(10, 33, 7, 32, &[0; 32]).unwrap());
        assert_ne!(base, shred.leaf_hash(10, 32, 8, 32, &[0; 32]).unwrap());
        assert_ne!(base, shred.leaf_hash(10, 32, 7, 0, &[0; 32]).unwrap());
        assert_ne!(base, shred.leaf_hash(10, 32, 7, 32, &[1; 32]).unwrap());
    }
}
