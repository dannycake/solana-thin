//! Finality certificates: what validators sign, and how the signers are named.
//!
//! Alpenglow validators vote with BLS signatures that never touch the ledger.
//! Enough matching votes are folded into one aggregate signature plus a bitmap
//! of who signed. There are two ways a block becomes final:
//!
//! * **Fast**: at least 80% of stake signed a *notarize* vote for the block.
//! * **Slow**: at least 60% signed a notarize vote for the block, and at least
//!   60% signed a *finalize* vote for its slot.
//!
//! The two traps for a light client are both about what a signature covers:
//!
//! 1. A fast certificate is the same notarize aggregate as a plain notarization
//!    certificate, only with more signers. Sixty percent on a notarize vote is
//!    **not** finality. The threshold check is the whole difference.
//! 2. A finalize vote names a *slot*, not a block. On its own it says "whatever
//!    was notarized in this slot is final". It must be paired with a notarize
//!    aggregate for the exact block, at 60% or more, or it proves nothing about
//!    any particular block.

use crate::error::{Error, Result};
use crate::merkle::Hash;

/// A block: the slot it was produced in and its double-Merkle id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockRef {
    /// Slot number.
    pub slot: u64,
    /// The block id that validators vote on.
    pub id: Hash,
}

/// An aggregate BLS signature and the bitmap of validator ranks that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aggregate {
    /// Compressed G2 point.
    pub signature: [u8; 96],
    /// Signer ranks in Agave's `solana-signer-store` encoding.
    pub bitmap: Vec<u8>,
}

/// Proof that a block is final. Same content as the certificate a leader
/// embeds in a block footer, so a prover can lift one straight off the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityCert {
    /// One aggregate of notarize votes carrying at least 80% of stake.
    Fast {
        /// The finalized block.
        block: BlockRef,
        /// Notarize votes for `block`.
        notar: Aggregate,
    },
    /// A finalize aggregate for the slot plus a notarize aggregate for the
    /// block, each carrying at least 60% of stake.
    Slow {
        /// The finalized block.
        block: BlockRef,
        /// Finalize votes for `block.slot`.
        finalize: Aggregate,
        /// Notarize votes for `block`.
        notar: Aggregate,
    },
}

impl FinalityCert {
    /// The block this certificate finalizes.
    pub fn block(&self) -> BlockRef {
        match self {
            FinalityCert::Fast { block, .. } | FinalityCert::Slow { block, .. } => *block,
        }
    }
}

/// How a block reached finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
    /// 80% or more of stake notarized the block in one round.
    Fast,
    /// 60% notarized the block and 60% then voted to finalize its slot.
    Slow,
}

/// Stake share a fast certificate needs, in basis points.
pub const FAST_FINALIZE_BPS: u32 = 8_000;
/// Stake share each half of a slow certificate needs, in basis points.
pub const SLOW_FINALIZE_BPS: u32 = 6_000;

/// The bytes a validator signs to notarize `block` on the cluster identified
/// by `shred_version`.
///
/// The shred version is in the signed bytes, so a certificate from a test
/// cluster, or from before a cluster restart, does not verify on mainnet.
pub fn notarize_payload(block: &BlockRef, shred_version: u16) -> [u8; 43] {
    let mut out = [0u8; 43];
    out[0] = 1;
    out[1..9].copy_from_slice(&block.slot.to_le_bytes());
    out[9..41].copy_from_slice(&block.id);
    out[41..43].copy_from_slice(&shred_version.to_le_bytes());
    out
}

/// The bytes a validator signs to finalize `slot`.
pub fn finalize_payload(slot: u64, shred_version: u16) -> [u8; 11] {
    let mut out = [0u8; 11];
    out[0] = 2;
    out[1..9].copy_from_slice(&slot.to_le_bytes());
    out[9..11].copy_from_slice(&shred_version.to_le_bytes());
    out
}

/// Decodes a signer bitmap into ascending validator ranks.
///
/// Only the single-vector ("base 2") form is accepted: a version byte of 0, a
/// little-endian bit count, then the bits, least significant first. Validators
/// reject the two-vector form for finalization certificates and so do we.
/// `validators` is the size of the set the ranks index into.
pub fn decode_bitmap(bitmap: &[u8], validators: usize) -> Result<Vec<usize>> {
    if bitmap.len() < 3 || bitmap[0] != 0 {
        return Err(Error::InvalidBitmap);
    }
    let bits = usize::from(u16::from_le_bytes([bitmap[1], bitmap[2]]));
    if bits > validators {
        return Err(Error::RankOutOfRange);
    }
    let data = &bitmap[3..];
    if data.len() != bits.div_ceil(8) {
        return Err(Error::InvalidBitmap);
    }
    let mut ranks = Vec::new();
    for rank in 0..bits {
        if data[rank / 8] >> (rank % 8) & 1 == 1 {
            ranks.push(rank);
        }
    }
    Ok(ranks)
}

/// Encodes ascending ranks as a single-vector bitmap, the way Agave does: the
/// bit count is one past the highest signer.
pub fn encode_bitmap(ranks: &[usize]) -> Vec<u8> {
    let bits = ranks.iter().max().map_or(0, |max| max + 1);
    let mut out = vec![0u8; 3 + bits.div_ceil(8)];
    out[1..3].copy_from_slice(&(bits as u16).to_le_bytes());
    for rank in ranks {
        out[3 + rank / 8] |= 1 << (rank % 8);
    }
    out
}

/// Whether `signed` out of `total` reaches `required_bps` basis points.
/// Uses the same "at least" comparison as Agave, in exact integer arithmetic.
pub(crate) fn check_stake(signed: u64, total: u64, required_bps: u32) -> Result<()> {
    if u128::from(signed) * 10_000 >= u128::from(total) * u128::from(required_bps) {
        Ok(())
    } else {
        Err(Error::InsufficientStake {
            signed,
            total,
            required_bps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_match_agave_layout() {
        let block = BlockRef {
            slot: 0x0102030405060708,
            id: [0xab; 32],
        };
        let p = notarize_payload(&block, 0xc3ad);
        assert_eq!(p[0], 1);
        assert_eq!(&p[1..9], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&p[9..41], &[0xab; 32]);
        assert_eq!(&p[41..], &[0xad, 0xc3]);
        let f = finalize_payload(block.slot, 0xc3ad);
        assert_eq!(f[0], 2);
        assert_eq!(&f[9..], &[0xad, 0xc3]);
    }

    #[test]
    fn bitmap_round_trips() {
        for ranks in [vec![0], vec![7], vec![8], vec![0, 3, 9, 16, 671]] {
            let encoded = encode_bitmap(&ranks);
            assert_eq!(decode_bitmap(&encoded, 672).unwrap(), ranks);
        }
        assert_eq!(
            decode_bitmap(&encode_bitmap(&[]), 10).unwrap(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn bitmap_rejects_what_validators_reject() {
        // Too short, unknown version, two-vector form.
        assert_eq!(decode_bitmap(&[0, 1], 8), Err(Error::InvalidBitmap));
        assert_eq!(
            decode_bitmap(&[2, 8, 0, 0xff], 8),
            Err(Error::InvalidBitmap)
        );
        assert_eq!(
            decode_bitmap(&[1, 5, 0, 0x01], 8),
            Err(Error::InvalidBitmap)
        );
        // More bits than validators.
        assert_eq!(
            decode_bitmap(&[0, 9, 0, 0xff, 0x01], 8),
            Err(Error::RankOutOfRange)
        );
        // Byte length that does not match the bit count.
        assert_eq!(decode_bitmap(&[0, 8, 0], 8), Err(Error::InvalidBitmap));
        assert_eq!(
            decode_bitmap(&[0, 8, 0, 0xff, 0x00], 8),
            Err(Error::InvalidBitmap)
        );
    }

    #[test]
    fn bits_past_the_count_are_ignored_like_the_validator_does() {
        // Five bits declared; the three high bits of the byte are noise.
        assert_eq!(
            decode_bitmap(&[0, 5, 0, 0b1110_0101], 8).unwrap(),
            vec![0, 2]
        );
    }

    #[test]
    fn thresholds_are_inclusive_and_exact() {
        assert!(check_stake(80, 100, FAST_FINALIZE_BPS).is_ok());
        assert!(check_stake(79, 100, FAST_FINALIZE_BPS).is_err());
        assert!(check_stake(60, 100, SLOW_FINALIZE_BPS).is_ok());
        // One lamport short of 60% of a stake total where floats would round up.
        let total = 100_000_000_000_000_000u64;
        assert!(check_stake(total / 10 * 6, total, SLOW_FINALIZE_BPS).is_ok());
        assert!(check_stake(total / 10 * 6 - 1, total, SLOW_FINALIZE_BPS).is_err());
        assert!(check_stake(u64::MAX, u64::MAX, 10_000).is_ok());
    }
}
