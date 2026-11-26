//! Every reason the prover gives for not producing a block or a proof.

use solana_thin::{BlockRef, Error};
use std::fmt;

/// Why a block was not fetched or a proof was not built.
///
/// None of these says the transaction is not final. They say this prover
/// could not show that it is, now, from the peers it has.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The RPC node listed no validator this prover can ask.
    NoPeers,
    /// Many requests in a row went unanswered by every peer. The prover has
    /// stopped asking for a while instead of pressing on.
    PeersSilent {
        /// Requests sent since a peer last sent anything.
        unanswered: u64,
    },
    /// A certificate was found for a block in an epoch whose validator set
    /// is not pinned, so it could not be checked.
    EpochNotPinned {
        /// The epoch whose set is missing.
        epoch: u64,
        /// The slot of the block the certificate is for.
        slot: u64,
        /// The epochs that are pinned.
        pinned: Vec<u64>,
    },
    /// No certificate that verifies was found for the slot or a descendant.
    NoCertificate {
        /// The slot that was to be certified.
        slot: u64,
        /// The last slot whose footer was looked for.
        searched_to: u64,
        /// Certificates that were found and refused: the slot whose footer
        /// carried each, and why.
        rejected: Vec<(u64, Error)>,
    },
    /// The chain of parents from a certified block passes over the slot:
    /// the cluster skipped it, or finalized another fork.
    NotFinalized {
        /// The slot asked about.
        slot: u64,
        /// The certified block the walk started from.
        certified: BlockRef,
        /// The nearest ancestors on either side of the slot.
        between: (u64, u64),
    },
    /// The nearest certified block is more parent links away than a proof
    /// may carry.
    AncestryTooLong {
        /// The slot asked about.
        slot: u64,
        /// The certified block the walk started from.
        certified: BlockRef,
        /// The longest chain allowed.
        limit: usize,
    },
    /// No peer answered for this block: none holds it any more, or none
    /// answers this client.
    NoHolder {
        /// The certified block.
        block: BlockRef,
        /// How many peers were asked.
        asked: usize,
    },
    /// Peers hold the block and did not send all of it.
    Incomplete {
        /// The certified block.
        block: BlockRef,
        /// What was being collected: `"FEC set roots"` or `"shreds"`.
        what: &'static str,
        /// How many arrived and passed their check.
        have: usize,
        /// How many the block has.
        total: usize,
        /// Answers that failed their check against the block id.
        rejected: u64,
    },
    /// Every shred checked out against the certified id, and the block is
    /// one nothing can be proven in: its leader switched parent, its parent
    /// id is all zeros, or it breaks a rule validators hold blocks to.
    Unprovable {
        /// The certified block.
        block: BlockRef,
        /// What the indexer said.
        error: Error,
    },
    /// Every shred checked out against the certified id, and the block
    /// assembled from them has another id or parent. This should be
    /// impossible; it is reported and nothing is kept.
    Mismatch {
        /// The certified block.
        block: BlockRef,
        /// What the shreds hash to.
        computed: BlockRef,
    },
    /// The block at the hinted slot is held and the transaction is not in
    /// it. The hint was wrong, or the transaction never landed.
    NotInBlock {
        /// The slot the hint named.
        slot: u64,
    },
    /// A proof was built and the verifier refused it. This should be
    /// impossible; the proof is not returned.
    ProofRejected {
        /// The block the transaction is in.
        block: BlockRef,
        /// What the verifier said.
        error: Error,
    },
    /// The store directory could not be read or written.
    Store(String),
}

impl Refusal {
    /// Whether asking again later could go better without anything else
    /// changing: the peers were busy or quiet, not wrong.
    pub fn is_temporary(&self) -> bool {
        matches!(
            self,
            Refusal::PeersSilent { .. } | Refusal::Incomplete { .. } | Refusal::Store(_)
        )
    }
}

fn short(id: &[u8; 32]) -> String {
    hex::encode(&id[..8])
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NoPeers => write!(f, "the RPC node listed no validator that can be asked"),
            Refusal::PeersSilent { unanswered } => write!(
                f,
                "{unanswered} requests in a row went unanswered by every peer; not asking for a while"
            ),
            Refusal::EpochNotPinned {
                epoch,
                slot,
                pinned,
            } => {
                let pinned: Vec<String> = pinned.iter().map(u64::to_string).collect();
                write!(
                    f,
                    "no validator set is pinned for epoch {epoch}, which the certificate for slot \
                     {slot} needs (pinned: {}); pass that epoch's set file",
                    if pinned.is_empty() {
                        "none".to_string()
                    } else {
                        pinned.join(", ")
                    }
                )
            }
            Refusal::NoCertificate {
                slot,
                searched_to,
                rejected,
            } => {
                write!(
                    f,
                    "no finality certificate for slot {slot} or a descendant in the footers up \
                     to slot {searched_to}"
                )?;
                for (found_in, error) in rejected {
                    write!(f, "; the one in slot {found_in} was refused: {error}")?;
                }
                Ok(())
            }
            Refusal::NotFinalized {
                slot,
                certified,
                between,
            } => write!(
                f,
                "slot {slot} is not in the finalized chain: the ancestors of certified block \
                 {} ({}) go from slot {} to slot {}",
                certified.slot,
                short(&certified.id),
                between.1,
                between.0
            ),
            Refusal::AncestryTooLong {
                slot,
                certified,
                limit,
            } => write!(
                f,
                "slot {slot} is more than {limit} blocks before the nearest certified block, {}",
                certified.slot
            ),
            Refusal::NoHolder { block, asked } => write!(
                f,
                "none of {asked} peers answered for block {} ({}): pruned, or they are not \
                 serving this client",
                block.slot,
                short(&block.id)
            ),
            Refusal::Incomplete {
                block,
                what,
                have,
                total,
                rejected,
            } => write!(
                f,
                "only {have} of {total} {what} of block {} ({}) arrived; {rejected} answers \
                 failed their check",
                block.slot,
                short(&block.id)
            ),
            Refusal::Unprovable { block, error } => write!(
                f,
                "nothing can be proven in block {} ({}): {error}",
                block.slot,
                short(&block.id)
            ),
            Refusal::Mismatch { block, computed } => write!(
                f,
                "the shreds fetched for block {} ({}) assemble to block {} ({})",
                block.slot,
                short(&block.id),
                computed.slot,
                short(&computed.id)
            ),
            Refusal::NotInBlock { slot } => {
                write!(f, "the transaction is not in the block of slot {slot}")
            }
            Refusal::ProofRejected { block, error } => write!(
                f,
                "the verifier refused the proof built from block {} ({}): {error}",
                block.slot,
                short(&block.id)
            ),
            Refusal::Store(why) => write!(f, "the store: {why}"),
        }
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_says_what_it_is_about() {
        let block = BlockRef {
            slot: 77,
            id: [0xab; 32],
        };
        let other = BlockRef {
            slot: 78,
            id: [0xcd; 32],
        };
        let cases: Vec<(Refusal, &[&str])> = vec![
            (Refusal::NoPeers, &["no validator"]),
            (Refusal::PeersSilent { unanswered: 400 }, &["400 requests"]),
            (
                Refusal::EpochNotPinned {
                    epoch: 1096,
                    slot: 5,
                    pinned: vec![1097, 1098],
                },
                &["epoch 1096", "slot 5", "pinned: 1097, 1098"],
            ),
            (
                Refusal::EpochNotPinned {
                    epoch: 3,
                    slot: 5,
                    pinned: vec![],
                },
                &["pinned: none"],
            ),
            (
                Refusal::NoCertificate {
                    slot: 77,
                    searched_to: 89,
                    rejected: vec![(80, Error::SignatureMismatch)],
                },
                &["slot 77", "slot 89", "slot 80 was refused"],
            ),
            (
                Refusal::NotFinalized {
                    slot: 77,
                    certified: other,
                    between: (78, 76),
                },
                &[
                    "slot 77 is not in the finalized chain",
                    "slot 76 to slot 78",
                ],
            ),
            (
                Refusal::AncestryTooLong {
                    slot: 7,
                    certified: block,
                    limit: 32,
                },
                &["more than 32 blocks", "77"],
            ),
            (
                Refusal::NoHolder { block, asked: 24 },
                &["none of 24 peers", "block 77 (abababababababab)"],
            ),
            (
                Refusal::Incomplete {
                    block,
                    what: "shreds",
                    have: 3,
                    total: 64,
                    rejected: 2,
                },
                &["3 of 64 shreds", "2 answers failed"],
            ),
            (
                Refusal::Unprovable {
                    block,
                    error: Error::UpdateParentBlock,
                },
                &["nothing can be proven in block 77"],
            ),
            (
                Refusal::Mismatch {
                    block,
                    computed: other,
                },
                &["block 77", "block 78 (cdcdcdcdcdcdcdcd)"],
            ),
            (
                Refusal::NotInBlock { slot: 77 },
                &["not in the block of slot 77"],
            ),
            (
                Refusal::ProofRejected {
                    block,
                    error: Error::InvalidMerkleProof,
                },
                &["the verifier refused the proof", "block 77"],
            ),
            (
                Refusal::Store("disk full".into()),
                &["the store: disk full"],
            ),
        ];
        for (refusal, needles) in cases {
            let said = refusal.to_string();
            for needle in needles {
                assert!(said.contains(needle), "{said:?} lacks {needle:?}");
            }
        }
        assert!(Refusal::PeersSilent { unanswered: 1 }.is_temporary());
        assert!(!Refusal::NotInBlock { slot: 1 }.is_temporary());
        assert!(!Refusal::NoHolder { block, asked: 1 }.is_temporary());
    }
}
