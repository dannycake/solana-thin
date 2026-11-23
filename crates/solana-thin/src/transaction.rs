//! Reading transactions off the wire.
//!
//! The verifier has to walk every transaction that precedes the one being
//! proven, because transactions are not length-prefixed: the only way to know
//! where one ends is to parse it. This module parses all three encodings a
//! validator accepts (legacy, v0 and v1) and nothing else.
//!
//! A parser here does not have to reject everything a validator rejects. The
//! bytes it walks sit in a block that a supermajority already replayed, so
//! they are valid transactions. It has to do one thing exactly: for every
//! valid transaction, consume the same number of bytes a validator would.

use crate::error::{Error, Result};
use crate::wire::Reader;

/// SPL Memo version 3, `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`.
pub const MEMO_PROGRAM_ID: [u8; 32] = [
    5, 74, 83, 90, 153, 41, 33, 6, 77, 36, 232, 113, 96, 218, 56, 124, 124, 53, 181, 221, 188, 146,
    187, 129, 228, 31, 168, 64, 65, 5, 68, 141,
];
/// SPL Memo version 4, `Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH`. The
/// `solana` CLI of Agave 4.4 writes `--with-memo` to this one.
pub const MEMO_V4_PROGRAM_ID: [u8; 32] = [
    5, 74, 83, 82, 40, 84, 205, 209, 3, 204, 46, 70, 49, 163, 245, 23, 146, 172, 114, 124, 241,
    229, 10, 188, 151, 130, 138, 197, 153, 79, 60, 194,
];
/// The first Memo program, `Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo`.
pub const MEMO_V1_PROGRAM_ID: [u8; 32] = [
    5, 74, 83, 80, 248, 93, 200, 130, 214, 20, 165, 86, 114, 120, 138, 41, 109, 223, 30, 171, 171,
    208, 166, 6, 120, 136, 73, 50, 244, 238, 246, 160,
];

/// Every Memo program a validator ships: versions 1, 3 and 4.
pub const MEMO_PROGRAM_IDS: [[u8; 32]; 3] =
    [MEMO_PROGRAM_ID, MEMO_V1_PROGRAM_ID, MEMO_V4_PROGRAM_ID];

/// Which message encoding a transaction uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageVersion {
    /// The original format, with no version byte.
    Legacy,
    /// Version 0: legacy plus address lookup tables.
    V0,
    /// Version 1: fixed-width instruction headers, signatures after the message.
    V1,
}

/// One instruction of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Index of the program in the transaction's account keys.
    pub program_id_index: u8,
    /// Indexes of the accounts the instruction touches.
    pub accounts: Vec<u8>,
    /// The instruction's data.
    pub data: Vec<u8>,
}

/// A transaction as it appears inside a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The message encoding.
    pub version: MessageVersion,
    /// Ed25519 signatures. The first is the transaction id.
    pub signatures: Vec<[u8; 64]>,
    /// Account keys listed in the message itself. Keys loaded from address
    /// lookup tables are not here: resolving them needs account state.
    pub account_keys: Vec<[u8; 32]>,
    /// The recent blockhash (or durable nonce) the transaction commits to.
    pub recent_blockhash: [u8; 32],
    /// The instructions.
    pub instructions: Vec<Instruction>,
    /// The exact bytes the signatures cover.
    pub message: Vec<u8>,
}

impl Transaction {
    /// Parses a transaction that occupies all of `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let tx = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(tx)
    }

    /// The transaction id: its first signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signatures[0]
    }

    /// The account that paid the fee.
    pub fn fee_payer(&self) -> &[u8; 32] {
        &self.account_keys[0]
    }

    /// The program an instruction calls, if its key is listed in the message
    /// rather than loaded from a lookup table.
    pub fn program_id(&self, instruction: &Instruction) -> Option<&[u8; 32]> {
        self.account_keys
            .get(usize::from(instruction.program_id_index))
    }

    /// Data of every instruction addressed to a Memo program, in order.
    pub fn memos(&self) -> impl Iterator<Item = &[u8]> {
        self.instructions.iter().filter_map(move |ix| {
            let program = self.program_id(ix)?;
            MEMO_PROGRAM_IDS
                .contains(program)
                .then_some(ix.data.as_slice())
        })
    }

    /// Reads one transaction, leaving the reader just past it.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let first = reader.u8()?;
        if first & 0x80 == 0 {
            // Legacy or v0: `first` is the one-byte signature count.
            let count = reader.bounded_count(usize::from(first), 64)?;
            let signatures = read_signatures(reader, count)?;
            let start = reader.position();
            let mut probe = reader.clone();
            let prefix = probe.u8()?;
            let version = if prefix & 0x80 == 0 {
                MessageVersion::Legacy
            } else if prefix == 0x80 {
                reader.u8()?;
                MessageVersion::V0
            } else {
                return Err(Error::UnsupportedTransaction);
            };
            let header = reader.array::<3>()?;
            let key_count = usize::from(reader.short_u16()?);
            let key_count = reader.bounded_count(key_count, 32)?;
            let mut account_keys = Vec::with_capacity(key_count);
            for _ in 0..key_count {
                account_keys.push(reader.array::<32>()?);
            }
            let recent_blockhash = reader.array::<32>()?;
            let ix_count = usize::from(reader.short_u16()?);
            let ix_count = reader.bounded_count(ix_count, 3)?;
            let mut instructions = Vec::with_capacity(ix_count);
            for _ in 0..ix_count {
                let program_id_index = reader.u8()?;
                let accounts_len = usize::from(reader.short_u16()?);
                let accounts = reader.bytes(accounts_len)?.to_vec();
                let data_len = usize::from(reader.short_u16()?);
                let data = reader.bytes(data_len)?.to_vec();
                instructions.push(Instruction {
                    program_id_index,
                    accounts,
                    data,
                });
            }
            if version == MessageVersion::V0 {
                let lookups = usize::from(reader.short_u16()?);
                let lookups = reader.bounded_count(lookups, 34)?;
                for _ in 0..lookups {
                    reader.bytes(32)?;
                    let writable = usize::from(reader.short_u16()?);
                    reader.bytes(writable)?;
                    let readonly = usize::from(reader.short_u16()?);
                    reader.bytes(readonly)?;
                }
            }
            let message = reader.span(start).to_vec();
            finish(
                version,
                signatures,
                header[0],
                account_keys,
                recent_blockhash,
                instructions,
                message,
            )
        } else if first == 0x81 {
            // v1: the message comes first, then one signature per required signer.
            let start = reader.position() - 1;
            let header = reader.array::<3>()?;
            let mask = reader.u32()?;
            let fee_bits = mask & 0b11;
            if mask & !0b1_1111 != 0 || (fee_bits != 0 && fee_bits != 0b11) {
                return Err(Error::UnsupportedTransaction);
            }
            let recent_blockhash = reader.array::<32>()?;
            let ix_count = usize::from(reader.u8()?);
            let key_count = usize::from(reader.u8()?);
            let key_count = reader.bounded_count(key_count, 32)?;
            let mut account_keys = Vec::with_capacity(key_count);
            for _ in 0..key_count {
                account_keys.push(reader.array::<32>()?);
            }
            let mut config_len = 0;
            if fee_bits == 0b11 {
                config_len += 8;
            }
            config_len += 4 * (mask >> 2 & 0b111).count_ones() as usize;
            reader.bytes(config_len)?;
            let ix_count = reader.bounded_count(ix_count, 4)?;
            let mut headers = Vec::with_capacity(ix_count);
            for _ in 0..ix_count {
                let program_id_index = reader.u8()?;
                let accounts_len = usize::from(reader.u8()?);
                let data_len = usize::from(reader.u16()?);
                headers.push((program_id_index, accounts_len, data_len));
            }
            let mut instructions = Vec::with_capacity(ix_count);
            for (program_id_index, accounts_len, data_len) in headers {
                let accounts = reader.bytes(accounts_len)?.to_vec();
                let data = reader.bytes(data_len)?.to_vec();
                instructions.push(Instruction {
                    program_id_index,
                    accounts,
                    data,
                });
            }
            let message = reader.span(start).to_vec();
            let count = reader.bounded_count(usize::from(header[0]), 64)?;
            let signatures = read_signatures(reader, count)?;
            finish(
                MessageVersion::V1,
                signatures,
                header[0],
                account_keys,
                recent_blockhash,
                instructions,
                message,
            )
        } else {
            Err(Error::UnsupportedTransaction)
        }
    }
}

fn read_signatures(reader: &mut Reader<'_>, count: usize) -> Result<Vec<[u8; 64]>> {
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(reader.array::<64>()?);
    }
    Ok(signatures)
}

fn finish(
    version: MessageVersion,
    signatures: Vec<[u8; 64]>,
    required_signatures: u8,
    account_keys: Vec<[u8; 32]>,
    recent_blockhash: [u8; 32],
    instructions: Vec<Instruction>,
    message: Vec<u8>,
) -> Result<Transaction> {
    // A transaction without a fee payer signature never reaches a block. This
    // also makes `signature()` and `fee_payer()` total.
    if signatures.is_empty()
        || account_keys.is_empty()
        || usize::from(required_signatures) != signatures.len()
        || signatures.len() > account_keys.len()
    {
        return Err(Error::UnsupportedTransaction);
    }
    Ok(Transaction {
        version,
        signatures,
        account_keys,
        recent_blockhash,
        instructions,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{legacy_transaction, v0_transaction, v1_transaction};

    #[test]
    fn all_three_encodings_round_trip() {
        for (bytes, version) in [
            (legacy_transaction(1, &[b"hello"]), MessageVersion::Legacy),
            (v0_transaction(2, &[b"a", b"bc"]), MessageVersion::V0),
            (v1_transaction(3, &[b"xyz"]), MessageVersion::V1),
        ] {
            let tx = Transaction::parse(&bytes).unwrap();
            assert_eq!(tx.version, version);
            assert_eq!(tx.signatures.len(), 1);
            assert!(tx.memos().count() >= 1);
            // One byte short or long is never a transaction.
            assert!(Transaction::parse(&bytes[..bytes.len() - 1]).is_err());
            let mut long = bytes.clone();
            long.push(0);
            assert_eq!(Transaction::parse(&long), Err(Error::TrailingBytes));
        }
    }

    #[test]
    fn every_memo_program_is_recognised_and_nothing_else() {
        let bytes = legacy_transaction(4, &[b"anchor"]);
        let at = bytes
            .windows(32)
            .position(|w| w == MEMO_PROGRAM_ID)
            .unwrap();
        for program in MEMO_PROGRAM_IDS {
            let mut tx = bytes.clone();
            tx[at..at + 32].copy_from_slice(&program);
            let tx = Transaction::parse(&tx).unwrap();
            assert_eq!(tx.memos().collect::<Vec<_>>(), [b"anchor"]);
        }
        let mut other = bytes.clone();
        other[at + 31] ^= 1;
        assert_eq!(Transaction::parse(&other).unwrap().memos().count(), 0);
    }

    #[test]
    fn signatures_cover_the_message_bytes() {
        let bytes = legacy_transaction(9, &[b"memo"]);
        let tx = Transaction::parse(&bytes).unwrap();
        // Legacy: one count byte, then signatures, then the message.
        assert_eq!(tx.message, bytes[1 + 64..]);
        let bytes = v1_transaction(9, &[b"memo"]);
        let tx = Transaction::parse(&bytes).unwrap();
        // v1: the message, then signatures.
        assert_eq!(tx.message, bytes[..bytes.len() - 64]);
    }

    #[test]
    fn unknown_versions_and_masks_are_refused() {
        let mut bytes = v0_transaction(1, &[b"x"]);
        bytes[1 + 64] = 0x82;
        assert_eq!(
            Transaction::parse(&bytes),
            Err(Error::UnsupportedTransaction)
        );
        // A v1 message is not allowed behind a legacy-style signature list.
        bytes[1 + 64] = 0x81;
        assert_eq!(
            Transaction::parse(&bytes),
            Err(Error::UnsupportedTransaction)
        );
        let mut bytes = v1_transaction(1, &[b"x"]);
        bytes[4] = 0b10_0000;
        assert_eq!(
            Transaction::parse(&bytes),
            Err(Error::UnsupportedTransaction)
        );
        bytes[4] = 0b01;
        assert_eq!(
            Transaction::parse(&bytes),
            Err(Error::UnsupportedTransaction)
        );
        assert_eq!(
            Transaction::parse(&[0x85]),
            Err(Error::UnsupportedTransaction)
        );
    }

    #[test]
    fn huge_counts_do_not_allocate() {
        // 127 signatures claimed, none present.
        assert_eq!(Transaction::parse(&[0x7f]), Err(Error::Truncated));
    }
}
