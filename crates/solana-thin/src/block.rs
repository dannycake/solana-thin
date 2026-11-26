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

/// Longest signer bitmap a footer is read with: three header bytes plus a
/// bit for each of the 65,535 signers the bitmap's own count can name.
///
/// This is the format's bound, not the admission limit of 2,000. A footer
/// has to be read to its end whatever its certificates hold, and a validator
/// applies no smaller bound here. A bitmap that names more ranks than the
/// pinned set has is refused later, when a certificate is checked.
const MAX_BITMAP_LEN: usize = 3 + (u16::MAX as usize).div_ceil(8);

/// The footer a leader appends to its block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Footer {
    /// Hash of the bank after executing the block.
    pub bank_hash: Hash,
    /// The leader's clock when it produced the block, in nanoseconds since the
    /// Unix epoch.
    ///
    /// Validators check it only against the parent block: later than the
    /// parent's, and no more than twice the elapsed slot time ahead of it.
    /// Nothing compares it with real time. One leader cannot move it far, but
    /// a run of colluding leaders can push it forward at up to twice the real
    /// rate. Use it as "not earlier than the parent's clock", and compare
    /// with a clock of your own before relying on it as wall time.
    pub producer_time_nanos: u64,
    /// Free-form client identification written by the leader.
    pub user_agent: Vec<u8>,
    /// A finality certificate, as embedded by the leader. It is returned
    /// unverified: pass it to the client like any other.
    ///
    /// It says nothing about this block. Validators check its signatures and
    /// stake and nothing else: the block it certifies need not be this
    /// block's parent, an ancestor, or even an earlier slot. In practice it is
    /// the leader's latest finalized block. Ancestry is shown by
    /// [`ParentLink`](crate::ParentLink)s, never by a footer.
    pub finality: Option<FinalityCert>,
}

/// A marker component.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    Footer(Box<Footer>),
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
            // Reward certificates. They pay validators and say nothing a
            // light client relies on, but they are read to the end, so that a
            // footer is accepted only where a validator's exact-length parse
            // accepts it.
            if option_tag(&mut body)? {
                body.u64()?;
                body.bytes(96)?;
                reward_bitmap(&mut body)?;
            }
            if option_tag(&mut body)? {
                body.u64()?;
                body.bytes(32)?;
                body.bytes(96)?;
                reward_bitmap(&mut body)?;
            }
            body.finish()
                .map_err(|_| Error::InvalidComponent("footer length"))?;
            Ok(Marker::Footer(Box::new(Footer {
                bank_hash,
                producer_time_nanos,
                user_agent,
                finality,
            })))
        }
        MARKER_GENESIS_CERTIFICATE => Ok(Marker::GenesisCertificate),
        _ => Err(Error::InvalidComponent("marker kind")),
    }
}

fn option_tag(r: &mut Reader<'_>) -> Result<bool> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::InvalidComponent("footer option tag")),
    }
}

/// Skips a reward certificate's signer bitmap, whose length is a compact
/// integer where a finality certificate's is a `u16`.
fn reward_bitmap(r: &mut Reader<'_>) -> Result<()> {
    let len = usize::from(r.short_u16()?);
    if len > MAX_BITMAP_LEN {
        return Err(Error::LimitExceeded("signer bitmap"));
    }
    r.bytes(len)?;
    Ok(())
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

/// A cursor over an entry batch.
///
/// This is the one place that knows how entries are laid out. The verifier,
/// the prover and the test tools all walk a batch with it, so that what a
/// tool enumerates is exactly what the verifier would read.
pub(crate) struct Batch<'a> {
    reader: Reader<'a>,
    entries: u64,
    next_entry: u64,
}

impl<'a> Batch<'a> {
    /// Starts a walk. Fails on a marker, whose entry count is zero.
    pub(crate) fn new(data: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(data);
        let entries = reader.u64()?;
        if entries == 0 {
            return Err(Error::InvalidComponent("not an entry batch"));
        }
        Ok(Self {
            reader,
            entries,
            next_entry: 0,
        })
    }

    /// How many entries the batch says it has.
    pub(crate) fn entries(&self) -> u64 {
        self.entries
    }

    /// Reads the next entry's header. Returns the entry's index and how many
    /// transactions it holds, or `None` after the last entry. The caller must
    /// read exactly that many transactions before calling again.
    pub(crate) fn next_entry(&mut self) -> Result<Option<(u64, u64)>> {
        if self.next_entry == self.entries {
            return Ok(None);
        }
        self.reader.bytes(8 + 32)?;
        let count = self.reader.u64()?;
        let index = self.next_entry;
        self.next_entry += 1;
        Ok(Some((index, count)))
    }

    /// Reads one transaction.
    pub(crate) fn transaction(&mut self) -> Result<Transaction> {
        Transaction::read(&mut self.reader)
    }

    /// Offset of the next unread byte.
    pub(crate) fn offset(&self) -> usize {
        self.reader.position()
    }
}

/// Walks an entry batch from its first byte to the transaction at `position`,
/// and returns it with the offset just past its last byte.
///
/// This is the step that makes inclusion mean something. Transactions are not
/// length-prefixed, so the only honest way to say "these bytes are a
/// transaction of this block" is to start where the validator starts and
/// parse everything in front. Bytes that merely *look* like a transaction,
/// sitting inside another transaction's instruction data, are never reached
/// as a transaction by this walk.
pub(crate) fn walk_to(data: &[u8], position: TxPosition) -> Result<(Transaction, usize)> {
    let mut batch = Batch::new(data)?;
    if u64::from(position.entry) >= batch.entries() {
        return Err(Error::TransactionNotFound);
    }
    while let Some((entry, count)) = batch.next_entry()? {
        if entry < u64::from(position.entry) {
            for _ in 0..count {
                batch.transaction()?;
            }
            continue;
        }
        if u64::from(position.transaction) >= count {
            return Err(Error::TransactionNotFound);
        }
        for _ in 0..position.transaction {
            batch.transaction()?;
        }
        let transaction = batch.transaction()?;
        return Ok((transaction, batch.offset()));
    }
    Err(Error::TransactionNotFound)
}

/// Walks an entry batch from its first byte and returns the transaction at
/// `position`. See [`reachable`] for what a walk can reach at all.
pub fn transaction_at(data: &[u8], position: TxPosition) -> Result<Transaction> {
    walk_to(data, position).map(|(transaction, _)| transaction)
}

/// Every transaction of a complete entry batch with its position. Used by the
/// prover to find a signature. Fails if any part of the batch does not parse.
pub fn transactions(data: &[u8]) -> Result<Vec<(TxPosition, Transaction)>> {
    let mut batch = Batch::new(data)?;
    let mut out = Vec::new();
    while let Some((entry, count)) = batch.next_entry()? {
        for transaction in 0..count {
            let position = TxPosition {
                entry: u32::try_from(entry).map_err(|_| Error::LimitExceeded("entry count"))?,
                transaction: u32::try_from(transaction)
                    .map_err(|_| Error::LimitExceeded("transaction count"))?,
            };
            out.push((position, batch.transaction()?));
        }
    }
    Ok(out)
}

/// Every transaction a walk of `data` reaches, with the offset just past
/// each, stopping without error at the first thing that does not parse.
///
/// Where [`transactions`] answers "what does this whole batch hold",
/// this answers "what could a verifier be led to read here". It is for tools
/// that enumerate every claim a proof could make about some bytes: it uses
/// the same cursor as the verifier, so it reaches a position exactly when
/// [`transaction_at`] does.
pub fn reachable(data: &[u8]) -> Vec<(TxPosition, Transaction, usize)> {
    let mut out = Vec::new();
    let Ok(mut batch) = Batch::new(data) else {
        return out;
    };
    while let Ok(Some((entry, count))) = batch.next_entry() {
        for transaction in 0..count {
            let (Ok(entry), Ok(transaction)) = (u32::try_from(entry), u32::try_from(transaction))
            else {
                return out;
            };
            let Ok(parsed) = batch.transaction() else {
                return out;
            };
            out.push((TxPosition { entry, transaction }, parsed, batch.offset()));
        }
    }
    out
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
        assert_eq!(
            parse_marker(&short[..short.len() - 1]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn entry_batch_is_not_a_marker_and_vice_versa() {
        let batch = testkit::entry_batch(&[vec![legacy_transaction(1, &[b"m"])]]);
        assert!(parse_marker(&batch).is_err());
        assert!(is_entry_batch(&batch));
        let header = testkit::header_component(&BlockRef {
            slot: 1,
            id: [0; 32],
        });
        assert!(!is_entry_batch(&header));
        let pos = TxPosition {
            entry: 0,
            transaction: 0,
        };
        assert!(transaction_at(&header, pos).is_err());
    }

    #[test]
    fn reachable_reaches_exactly_what_transaction_at_does() {
        let txs: Vec<Vec<u8>> = (0..5).map(|i| legacy_transaction(i, &[b"m"])).collect();
        let batch = testkit::entry_batch(&[
            vec![txs[0].clone(), txs[1].clone()],
            vec![],
            vec![txs[2].clone(), txs[3].clone(), txs[4].clone()],
        ]);
        // Cut the batch at every length: whatever a walk reaches is what
        // `transaction_at` returns, and nothing past it is returned at all.
        for len in 0..=batch.len() {
            let data = &batch[..len];
            let reached = reachable(data);
            for (position, tx, end) in &reached {
                assert_eq!(&transaction_at(data, *position).unwrap(), tx);
                assert!(*end <= len);
            }
            for (position, _) in transactions(&batch).unwrap() {
                let found = reached.iter().any(|(p, _, _)| *p == position);
                assert_eq!(transaction_at(data, position).is_ok(), found);
            }
        }
        assert_eq!(reachable(&batch).len(), 5);
        assert!(reachable(&testkit::header_component(&BlockRef {
            slot: 1,
            id: [0; 32]
        }))
        .is_empty());
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

    /// Rebuilds a testkit footer with different bytes after the finality
    /// certificate, fixing the marker's length prefix.
    fn footer_with_tail(tail: &[u8]) -> Vec<u8> {
        let mut bytes = testkit::footer_component([8; 32], 1, b"agent", None);
        // Drop the two "no reward certificate" tags and append the new tail.
        bytes.truncate(bytes.len() - 2);
        bytes.extend_from_slice(tail);
        let len = (bytes.len() - 13) as u16;
        bytes[11..13].copy_from_slice(&len.to_le_bytes());
        bytes
    }

    #[test]
    fn footer_is_read_to_its_end_like_a_validator_reads_it() {
        // Both reward certificates present: slot, [block id,] signature, and
        // a bitmap behind a compact length.
        let mut tail = vec![1];
        tail.extend_from_slice(&7u64.to_le_bytes());
        tail.extend_from_slice(&[0xaa; 96]);
        tail.extend_from_slice(&[4, 0, 8, 0, 0xff]);
        tail.push(1);
        tail.extend_from_slice(&7u64.to_le_bytes());
        tail.extend_from_slice(&[0xbb; 32]);
        tail.extend_from_slice(&[0xcc; 96]);
        tail.extend_from_slice(&[4, 0, 8, 0, 0x0f]);
        assert!(matches!(
            parse_marker(&footer_with_tail(&tail)).unwrap(),
            Marker::Footer(_)
        ));

        // Neither present, the common case.
        assert!(parse_marker(&footer_with_tail(&[0, 0])).is_ok());

        // A validator rejects a footer whose length prefix covers more than
        // the footer, or less. So must the verifier.
        assert_eq!(
            parse_marker(&footer_with_tail(&[0, 0, 0])),
            Err(Error::InvalidComponent("footer length"))
        );
        assert_eq!(parse_marker(&footer_with_tail(&[0])), Err(Error::Truncated));
        // A certificate cut short inside the declared length.
        assert_eq!(
            parse_marker(&footer_with_tail(&tail[..tail.len() - 1])),
            Err(Error::Truncated)
        );
        // An option tag that is neither 0 nor 1.
        assert_eq!(
            parse_marker(&footer_with_tail(&[2, 0])),
            Err(Error::InvalidComponent("footer option tag"))
        );
    }

    /// A signer bitmap is three header bytes and at most a bit for each
    /// signer its count can name. A footer bitmap of exactly that length is
    /// read; one byte longer is refused, in the finality certificate and in
    /// either reward certificate.
    #[test]
    fn a_footer_bitmap_is_as_long_as_the_format_allows_and_no_longer() {
        assert_eq!(MAX_BITMAP_LEN, 3 + 8_192);
        let refused = Err(Error::LimitExceeded("signer bitmap"));
        let block = BlockRef {
            slot: 9,
            id: [5; 32],
        };
        let aggregate = |len: usize| Aggregate {
            signature: [7; 96],
            bitmap: vec![0xa5; len],
        };
        let footer = |cert: &FinalityCert| {
            parse_marker(&testkit::footer_component([8; 32], 1, b"", Some(cert)))
        };
        let small = aggregate(4);

        // The only aggregate of a fast certificate, and each of a slow one.
        for len in [MAX_BITMAP_LEN, MAX_BITMAP_LEN + 1] {
            let fast = FinalityCert::Fast {
                block,
                notar: aggregate(len),
            };
            let finalize = FinalityCert::Slow {
                block,
                finalize: aggregate(len),
                notar: small.clone(),
            };
            let notar = FinalityCert::Slow {
                block,
                finalize: small.clone(),
                notar: aggregate(len),
            };
            for cert in [fast, finalize, notar] {
                let parsed = footer(&cert);
                if len > MAX_BITMAP_LEN {
                    assert_eq!(parsed, refused);
                } else {
                    let Ok(Marker::Footer(parsed)) = parsed else {
                        panic!("a footer with a {len}-byte bitmap: {parsed:?}");
                    };
                    assert_eq!(parsed.finality, Some(cert));
                }
            }
        }

        // The skip reward certificate, then the notarization one.
        let reward = |with_block_id: bool, len: usize| {
            let mut out = vec![1];
            out.extend_from_slice(&7u64.to_le_bytes());
            if with_block_id {
                out.extend_from_slice(&[0xbb; 32]);
            }
            out.extend_from_slice(&[0xaa; 96]);
            crate::wire::write_short_u16(&mut out, len as u16);
            out.extend_from_slice(&vec![0xa5; len]);
            out
        };
        for len in [MAX_BITMAP_LEN, MAX_BITMAP_LEN + 1] {
            let mut skip = reward(false, len);
            skip.push(0);
            let mut notar = vec![0];
            notar.extend_from_slice(&reward(true, len));
            for tail in [skip, notar] {
                let parsed = parse_marker(&footer_with_tail(&tail));
                if len > MAX_BITMAP_LEN {
                    assert_eq!(parsed, refused);
                } else {
                    assert!(matches!(parsed, Ok(Marker::Footer(_))), "{parsed:?}");
                }
            }
        }
    }

    /// The marker that carried Alpenglow's first certificate is a marker,
    /// not an unknown kind. Nothing is read from it.
    #[test]
    fn a_genesis_certificate_marker_is_recognized() {
        let mut bytes = 0u64.to_le_bytes().to_vec();
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(MARKER_GENESIS_CERTIFICATE);
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        assert_eq!(parse_marker(&bytes), Ok(Marker::GenesisCertificate));
        // Its declared length must still be there.
        assert_eq!(
            parse_marker(&bytes[..bytes.len() - 1]),
            Err(Error::Truncated)
        );
        bytes[10] = MARKER_GENESIS_CERTIFICATE + 1;
        assert_eq!(
            parse_marker(&bytes),
            Err(Error::InvalidComponent("marker kind"))
        );
    }

    #[test]
    fn footer_carries_time_and_certificate() {
        let block = BlockRef {
            slot: 9,
            id: [5; 32],
        };
        let agg = |b: u8| Aggregate {
            signature: [b; 96],
            bitmap: vec![0, 8, 0, 0xff],
        };
        let fast = FinalityCert::Fast {
            block,
            notar: agg(1),
        };
        let slow = FinalityCert::Slow {
            block,
            finalize: agg(2),
            notar: agg(3),
        };
        for cert in [None, Some(fast), Some(slow)] {
            let bytes = testkit::footer_component(
                [8; 32],
                1_700_000_000_000_000_000,
                b"agave/4.4",
                cert.as_ref(),
            );
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
