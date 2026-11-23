//! Block components: what the bytes inside shreds mean.
//!
//! The data shreds of a slot, concatenated, hold a sequence of *components*.
//! A component is either a batch of entries (which hold the transactions) or a
//! marker. Agave (`entry/src/block_component.rs`) lays them out as:
//!
//! ```text
//! entry batch:  count:u64 (> 0) | entry | entry | ...
//!        entry: num_hashes:u64 | hash:32 | tx_count:u64 | tx | tx | ...
//! marker:       0:u64 | version:u16 = 1 | kind:u8 | len:u16 | body
//! ```
//!
//! A valid block is `header, entries..., footer, final tick`. The header names
//! the parent. The footer carries the bank hash, the leader's clock, and
//! usually a finality certificate for an earlier block.

use crate::certificate::{Aggregate, BlockRef, FinalityCert};
use crate::error::{Error, Result};
use crate::merkle::Hash;
use crate::transaction::Transaction;
use crate::wire::Reader;

const MARKER_FOOTER: u8 = 0;
const MARKER_HEADER: u8 = 1;
const MARKER_UPDATE_PARENT: u8 = 2;
const MARKER_GENESIS_CERTIFICATE: u8 = 3;

/// Longest signer bitmap a footer certificate may carry: three header bytes
/// plus one bit per validator.
const MAX_BITMAP_LEN: usize = 3 + crate::validator_set::MAX_VALIDATORS.div_ceil(8);

/// The footer a leader appends to its block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// Hash of the bank after executing the block.
    pub bank_hash: Hash,
    /// The leader's clock when it produced the block, in nanoseconds since the
    /// Unix epoch. Validators reject blocks whose clock is out of bounds
    /// relative to the parent, so this is a checked value, not a free claim.
    pub producer_time_nanos: u64,
    /// Free-form client identification written by the leader.
    pub user_agent: Vec<u8>,
    /// A finality certificate for an earlier block, as embedded by the leader.
    /// It is returned unverified: pass it to the client like any other.
    pub finality: Option<FinalityCert>,
}

/// A marker component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Marker {
    /// First component of every block: names the parent.
    Header {
        /// The block this one builds on.
        parent: BlockRef,
    },
    /// The leader abandoned its first parent part way through the block.
    UpdateParent {
        /// The parent the rest of the block builds on instead.
        parent: BlockRef,
    },
    /// The footer.
    Footer(Footer),
    /// The one-off certificate that started Alpenglow.
    GenesisCertificate,
}

/// Parses a marker from the start of a component's bytes.
///
/// `data` may run past the end of the marker (it usually ends in padding from
/// a later shred of the same FEC set that the proof also had to include).
pub fn parse_marker(data: &[u8]) -> Result<Marker> {
    let mut r = Reader::new(data);
    if r.u64()? != 0 {
        return Err(Error::InvalidComponent("not a marker"));
    }
    if r.u16()? != 1 {
        return Err(Error::InvalidComponent("marker version"));
    }
    let kind = r.u8()?;
    let len = usize::from(r.u16()?);
    let mut body = Reader::new(r.bytes(len)?);
    match kind {
        MARKER_HEADER | MARKER_UPDATE_PARENT => {
            if body.u8()? != 1 {
                return Err(Error::InvalidComponent("parent marker version"));
            }
            let parent = BlockRef {
                slot: body.u64()?,
                id: body.array()?,
            };
            body.finish()
                .map_err(|_| Error::InvalidComponent("parent marker length"))?;
            Ok(if kind == MARKER_HEADER {
                Marker::Header { parent }
            } else {
                Marker::UpdateParent { parent }
            })
        }
        MARKER_FOOTER => {
            if body.u8()? != 1 {
                return Err(Error::InvalidComponent("footer version"));
            }
            let bank_hash = body.array()?;
            let producer_time_nanos = body.u64()?;
            let agent_len = usize::from(body.u8()?);
            let user_agent = body.bytes(agent_len)?.to_vec();
            let finality = match body.u8()? {
                0 => None,
                1 => Some(read_finality(&mut body)?),
                _ => return Err(Error::InvalidComponent("footer option tag")),
            };
            // Reward certificates follow. They pay validators and say nothing
            // a light client relies on, so they are left unread.
            Ok(Marker::Footer(Footer {
                bank_hash,
                producer_time_nanos,
                user_agent,
                finality,
            }))
        }
        MARKER_GENESIS_CERTIFICATE => Ok(Marker::GenesisCertificate),
        _ => Err(Error::InvalidComponent("marker kind")),
    }
}

fn read_aggregate(r: &mut Reader<'_>) -> Result<Aggregate> {
    let signature = r.array()?;
    let len = usize::from(r.u16()?);
    if len > MAX_BITMAP_LEN {
        return Err(Error::LimitExceeded("signer bitmap"));
    }
    Ok(Aggregate {
        signature,
        bitmap: r.bytes(len)?.to_vec(),
    })
}

/// Reads Agave's `BlockFinalizationCert`: slot, block id, the final aggregate
/// and an optional notarize aggregate. With the notarize aggregate present it
/// is a slow finalization; without, the single aggregate is a fast one.
fn read_finality(r: &mut Reader<'_>) -> Result<FinalityCert> {
    let block = BlockRef {
        slot: r.u64()?,
        id: r.array()?,
    };
    let first = read_aggregate(r)?;
    match r.u8()? {
        0 => Ok(FinalityCert::Fast {
            block,
            notar: first,
        }),
        1 => Ok(FinalityCert::Slow {
            block,
            finalize: first,
            notar: read_aggregate(r)?,
        }),
        _ => Err(Error::InvalidComponent("footer option tag")),
    }
}

/// Where a transaction sits inside an entry batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxPosition {
    /// Index of the entry within the batch.
    pub entry: u32,
    /// Index of the transaction within the entry.
    pub transaction: u32,
}

/// Walks an entry batch from its first byte and returns the transaction at
/// `position`.
///
/// This is the step that makes inclusion mean something. Transactions are not
/// length-prefixed, so the only honest way to say "these bytes are a
/// transaction of this block" is to start where the validator starts and
/// parse everything in front. Bytes that merely *look* like a transaction,
/// sitting inside another transaction's instruction data, are never reached
/// as a transaction by this walk.
pub fn transaction_at(data: &[u8], position: TxPosition) -> Result<Transaction> {
    let mut r = Reader::new(data);
    let entries = r.u64()?;
    if entries == 0 {
        return Err(Error::InvalidComponent("not an entry batch"));
    }
    if u64::from(position.entry) >= entries {
        return Err(Error::TransactionNotFound);
    }
    for entry in 0..=position.entry {
        r.bytes(8 + 32)?;
        let count = r.u64()?;
        let wanted = entry == position.entry;
        if wanted && u64::from(position.transaction) >= count {
            return Err(Error::TransactionNotFound);
        }
        let stop = if wanted {
            u64::from(position.transaction)
        } else {
            count
        };
        for _ in 0..stop {
            Transaction::read(&mut r)?;
        }
        if wanted {
            return Transaction::read(&mut r);
        }
    }
    Err(Error::TransactionNotFound)
}

/// Every transaction of a complete entry batch with its position. Used by the
/// prover to find a signature.
pub fn transactions(data: &[u8]) -> Result<Vec<(TxPosition, Transaction)>> {
    let mut r = Reader::new(data);
    let entries = r.u64()?;
    if entries == 0 {
        return Err(Error::InvalidComponent("not an entry batch"));
    }
    let mut out = Vec::new();
    for entry in 0..entries {
        r.bytes(8 + 32)?;
        let count = r.u64()?;
        for transaction in 0..count {
            let position = TxPosition {
                entry: u32::try_from(entry).map_err(|_| Error::LimitExceeded("entry count"))?,
                transaction: u32::try_from(transaction)
                    .map_err(|_| Error::LimitExceeded("transaction count"))?,
            };
            out.push((position, Transaction::read(&mut r)?));
        }
    }
    Ok(out)
}

/// Whether component bytes start an entry batch rather than a marker.
pub fn is_entry_batch(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] != [0u8; 8]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, legacy_transaction};

    #[test]
    fn header_and_update_parent_round_trip() {
        let parent = BlockRef {
            slot: 41,
            id: [3; 32],
        };
        assert_eq!(
            parse_marker(&testkit::header_component(&parent)).unwrap(),
            Marker::Header { parent }
        );
        assert_eq!(
            parse_marker(&testkit::update_parent_component(&parent)).unwrap(),
            Marker::UpdateParent { parent }
        );
        // Trailing padding is fine; a short marker is not.
        let mut padded = testkit::header_component(&parent);
        padded.extend_from_slice(&[0; 100]);
        assert!(parse_marker(&padded).is_ok());
        let short = testkit::header_component(&parent);
        assert_eq!(parse_marker(&short[..short.len() - 1]), Err(Error::Truncated));
    }

    #[test]
    fn entry_batch_is_not_a_marker_and_vice_versa() {
        let batch = testkit::entry_batch(&[vec![legacy_transaction(1, &[b"m"])]]);
        assert!(parse_marker(&batch).is_err());
        assert!(is_entry_batch(&batch));
        let header = testkit::header_component(&BlockRef { slot: 1, id: [0; 32] });
        assert!(!is_entry_batch(&header));
        let pos = TxPosition { entry: 0, transaction: 0 };
        assert!(transaction_at(&header, pos).is_err());
    }

    #[test]
    fn transaction_at_finds_exactly_the_indexed_one() {
        let txs: Vec<Vec<u8>> = (0..7).map(|i| legacy_transaction(i, &[b"memo"])).collect();
        let batch = testkit::entry_batch(&[
            vec![txs[0].clone(), txs[1].clone()],
            vec![],
            vec![txs[2].clone(), txs[3].clone(), txs[4].clone()],
            vec![txs[5].clone(), txs[6].clone()],
        ]);
        let all = transactions(&batch).unwrap();
        assert_eq!(all.len(), 7);
        for (i, (position, tx)) in all.iter().enumerate() {
            assert_eq!(tx, &Transaction::parse(&txs[i]).unwrap());
            assert_eq!(&transaction_at(&batch, *position).unwrap(), tx);
        }
        for (entry, transaction) in [(0, 2), (1, 0), (3, 2), (4, 0), (u32::MAX, 0)] {
            assert_eq!(
                transaction_at(&batch, TxPosition { entry, transaction }),
                Err(Error::TransactionNotFound)
            );
        }
    }

    #[test]
    fn footer_carries_time_and_certificate() {
        let block = BlockRef { slot: 9, id: [5; 32] };
        let agg = |b: u8| Aggregate {
            signature: [b; 96],
            bitmap: vec![0, 8, 0, 0xff],
        };
        let fast = FinalityCert::Fast { block, notar: agg(1) };
        let slow = FinalityCert::Slow {
            block,
            finalize: agg(2),
            notar: agg(3),
        };
        for cert in [None, Some(fast), Some(slow)] {
            let bytes = testkit::footer_component([8; 32], 1_700_000_000_000_000_000, b"agave/4.4", cert.as_ref());
            let Marker::Footer(footer) = parse_marker(&bytes).unwrap() else {
                panic!("not a footer");
            };
            assert_eq!(footer.bank_hash, [8; 32]);
            assert_eq!(footer.producer_time_nanos, 1_700_000_000_000_000_000);
            assert_eq!(footer.user_agent, b"agave/4.4");
            assert_eq!(footer.finality, cert);
        }
    }
}
