//! A model of what the reference harness means by "this shred parses".
//!
//! The fixtures' `shred_results[i]` is, in Agave's harness
//! (`conformance/src/shred.rs`, `execute_shred_parse`, step 1):
//!
//! ```text
//! Shred::new_from_serialized_shred(bytes).ok()
//!     .is_some_and(|s| s.chained_merkle_root().is_ok())
//! ```
//!
//! That is a parse plus `sanitize`, for data *and* coding shreds, with any
//! Merkle proof size. It is not the fetch-stage filter and it checks no
//! signature. This module re-states those rules so that a disagreement with
//! the light client can be named by the rule that caused it. The model is
//! itself checked: `main` counts every shred where it and the fixture differ.
//!
//! Rules are from Agave `ledger/src/shred.rs`, `shred/merkle.rs`,
//! `shred/shred_data.rs`, `shred/shred_code.rs` and `shred/traits.rs`.

/// Data and coding payload sizes (`ShredData::SIZE_OF_PAYLOAD`,
/// `ShredCode::SIZE_OF_PAYLOAD`).
const DATA_PAYLOAD: usize = 1203;
const CODE_PAYLOAD: usize = 1228;
const DATA_HEADERS: usize = 88;
const CODE_HEADERS: usize = 89;
/// `MAX_DATA_SHREDS_PER_SLOT` and `MAX_CODE_SHREDS_PER_SLOT`.
const MAX_SHREDS_PER_SLOT: u32 = 32_768;

/// What kind of shred the variant byte announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `0x9_` or `0xb_`.
    Data { proof_size: u8, resigned: bool },
    /// `0x6_` or `0x7_`.
    Code { proof_size: u8, resigned: bool },
}

/// `ShredVariant::try_from(u8)`.
pub fn kind(variant: u8) -> Option<Kind> {
    let proof_size = variant & 0x0f;
    match variant {
        // The two legacy type bytes are refused outright.
        0x5a | 0xa5 => None,
        _ => match variant & 0xf0 {
            0x60 => Some(Kind::Code {
                proof_size,
                resigned: false,
            }),
            0x70 => Some(Kind::Code {
                proof_size,
                resigned: true,
            }),
            0x90 => Some(Kind::Data {
                proof_size,
                resigned: false,
            }),
            0xb0 => Some(Kind::Data {
                proof_size,
                resigned: true,
            }),
            _ => None,
        },
    }
}

/// Whether the reference parses `payload` as a chained Merkle shred, and if
/// not, the first rule that refuses it.
pub fn parses(payload: &[u8]) -> Result<Kind, &'static str> {
    let Some(&variant) = payload.get(64) else {
        return Err("payload ends before the variant byte");
    };
    let kind = kind(variant).ok_or("variant byte is not a Merkle shred")?;
    let u16_at = |at: usize| u16::from_le_bytes([payload[at], payload[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes(payload[at..at + 4].try_into().unwrap());
    match kind {
        Kind::Data {
            proof_size,
            resigned,
        } => {
            // ShredData::from_payload
            if payload.len() < DATA_PAYLOAD {
                return Err("data shred shorter than 1203 bytes");
            }
            let slot = u64::from_le_bytes(payload[65..73].try_into().unwrap());
            let (index, fec_set_index) = (u32_at(73), u32_at(79));
            let (parent_offset, flags, size) = (u16_at(83), payload[85], usize::from(u16_at(86)));
            // shred_data::sanitize, in its order
            if index >= MAX_SHREDS_PER_SLOT {
                return Err("data shred index >= 32768");
            }
            if flags & 0x80 != 0 && flags & 0x40 == 0 {
                return Err("LAST_SHRED_IN_SLOT without DATA_COMPLETE");
            }
            let capacity = DATA_PAYLOAD
                - DATA_HEADERS
                - 32
                - 20 * usize::from(proof_size)
                - if resigned { 64 } else { 0 };
            if !(DATA_HEADERS..=DATA_HEADERS + capacity).contains(&size) {
                return Err("data size outside the body");
            }
            if parent_offset == 0 && slot != 0 {
                return Err("parent offset 0 in a slot other than 0");
            }
            if u64::from(parent_offset) > slot {
                return Err("parent offset larger than the slot");
            }
            if index < fec_set_index {
                return Err("index below its FEC set index");
            }
        }
        Kind::Code { .. } => {
            // ShredCode::from_payload reads the headers first, then the length.
            if payload.len() < CODE_HEADERS {
                return Err("coding shred ends inside its headers");
            }
            if payload.len() < CODE_PAYLOAD {
                return Err("coding shred shorter than 1228 bytes");
            }
            let (index, fec_set_index) = (u32_at(73), u32_at(79));
            let (num_data, num_coding, position) = (u16_at(83), u16_at(85), u16_at(87));
            // shred_code::sanitize and erasure_shard_index
            if index >= MAX_SHREDS_PER_SLOT {
                return Err("coding shred index >= 32768");
            }
            if num_coding > 256 {
                return Err("more than 256 coding shreds");
            }
            let last_data = num_data
                .checked_sub(1)
                .and_then(|n| fec_set_index.checked_add(u32::from(n)));
            if last_data.is_none_or(|i| i >= MAX_SHREDS_PER_SLOT) {
                return Err("coding header: data shreds overrun the slot");
            }
            let last_coding = index
                .checked_sub(u32::from(position))
                .zip(num_coding.checked_sub(1))
                .and_then(|(first, n)| first.checked_add(u32::from(n)));
            if last_coding.is_none_or(|i| i >= MAX_SHREDS_PER_SLOT) {
                return Err("coding header: coding shreds overrun the slot");
            }
            if position >= num_coding {
                return Err("coding position outside its set");
            }
        }
    }
    Ok(kind)
}
