//! The cases: a named seed corpus, Agave's own table of component sequences,
//! and the mutator families `--random` draws from.
//!
//! Mutators come in two kinds, because most random damage to a block makes
//! Agave reject it, and soundness says nothing about a block nobody votes
//! for. *Layout* mutators re-cut the same component bytes into shreds
//! differently. *Content* mutators change the components and settle the
//! footer's bank hash again, so the block can still vote. Each family states
//! whether it is supposed to vote ([`Floor`]); a run in which a family that
//! should vote never did has not tested soundness for it, and fails.

use {
    crate::harness::{
        Case, Edit, End, Expect, FLAG_LAST_IN_SLOT, Item, Layout, MID_WINDOW_SLOT, PARENT_SLOT,
        Par, Recipe, Rng, SIDE_SLOT, Trailer, Tx, World, window_slot,
    },
    solana_hash::Hash,
    solana_thin::shred::FLAG_DATA_COMPLETE,
    std::collections::{BTreeMap, BTreeSet},
};

const MAIN: Par = Par::Bank(PARENT_SLOT);
const SIDE: Par = Par::Bank(SIDE_SLOT);
const GENESIS: Par = Par::Bank(0);

/// Whether a family's cases are supposed to get Agave's vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Floor {
    /// At least one case must vote, with or without fast leader handover.
    Votes,
    /// At least one case must vote when fast leader handover is active, and
    /// none may when it is not.
    VotesWithHandover,
    /// No case may vote: the family exists to show Agave refuses the shape.
    Never,
    /// Nothing is required.
    Any,
}

/// A mutator family.
#[derive(Debug, Clone, Copy)]
pub struct Family {
    /// Name, `layout/..` or `content/..`.
    pub name: &'static str,
    /// Whether it is supposed to vote.
    pub floor: Floor,
    /// Why.
    pub why: &'static str,
}

/// Every family `--random` draws from, in the order it cycles through them.
pub const FAMILIES: &[Family] = &[
    Family {
        name: "content/honest",
        floor: Floor::Votes,
        why: "a well-formed block with a settled bank hash is what a validator votes for",
    },
    Family {
        name: "layout/split",
        floor: Floor::Votes,
        why: "a component after the header may be cut anywhere: deshredding concatenates the \
              data of its shreds, so the bytes replay parses are unchanged",
    },
    Family {
        name: "layout/short",
        floor: Floor::Votes,
        why: "shreds may carry any size up to capacity, zero included; the remainder moves into \
              later shreds of the same component",
    },
    Family {
        name: "layout/padding",
        floor: Floor::Votes,
        why: "bytes past `size` are covered by the Merkle leaf but are not data; no check reads \
              them",
    },
    Family {
        name: "layout/split-header",
        floor: Floor::Any,
        why: "on a parent with an id the blockstore finds no header in shred 0 and replay \
              defers; on genesis the id is not compared and the block votes",
    },
    Family {
        name: "layout/complete-midset",
        floor: Floor::Never,
        why: "the filter discards DATA_COMPLETE anywhere but the last shred of a FEC set, so \
              the slot never fills",
    },
    Family {
        name: "layout/complete-missing",
        floor: Floor::Any,
        why: "two components run together; a batch swallowed whole as trailing bytes can leave \
              a block that votes for less",
    },
    Family {
        name: "layout/complete-extra",
        floor: Floor::Any,
        why: "a component is cut in two at a FEC boundary; the second half rarely parses",
    },
    Family {
        name: "layout/resigned",
        floor: Floor::Votes,
        why: "the filter, sigverify and the blockstore admit the resigned data variant (0xb6) \
              like the plain one; only the body is 64 bytes shorter",
    },
    Family {
        name: "layout/last-in-slot",
        floor: Floor::Never,
        why: "LAST_IN_SLOT early ends the slot before its footer or alpentick, misaligned is \
              discarded, missing never fills",
    },
    Family {
        name: "layout/shred-fields",
        floor: Floor::Any,
        why: "one shred with a random parent offset, size or flags; almost always discarded",
    },
    Family {
        name: "content/markers",
        floor: Floor::Never,
        why: "duplicated, reordered and missing markers are each refused by \
              BlockComponentProcessor",
    },
    Family {
        name: "content/update-parent-ancestor",
        floor: Floor::VotesWithHandover,
        why: "the legitimate fast leader handover: header on one parent, UpdateParent to an \
              older ancestor at a FEC boundary, replay from the marker",
    },
    Family {
        name: "content/update-parent-same",
        floor: Floor::Never,
        why: "an UpdateParent naming the header's own parent is refused at insert \
              (UpdateParentMatchesBlockHeader)",
    },
    Family {
        name: "content/update-parent-split-header",
        floor: Floor::VotesWithHandover,
        why: "with the header cut across shreds 0 and 1 the blockstore records no header \
              parent, so an UpdateParent to the same parent is not compared with it and the \
              block votes from the marker (the split-header bug's shape)",
    },
    Family {
        name: "content/update-parent-zero-genesis",
        floor: Floor::VotesWithHandover,
        why: "ParentInfo::from_slot_meta treats a header whose parent id is all zeros as \
              absent; genesis is the one parent whose id replay does not compare, so header \
              and UpdateParent can both name (0, zeros) and the block votes from the marker \
              (finding C2)",
    },
    Family {
        name: "content/update-parent-duplicate-parent",
        floor: Floor::VotesWithHandover,
        why: "UpdateParent may keep the slot and change the id (a duplicate parent block); the \
              header's id is never checked once the marker replaces it",
    },
    Family {
        name: "content/update-parent-hidden",
        floor: Floor::Votes,
        why: "UpdateParent bytes after the last entry of a batch are trailing bytes of that \
              batch: no marker is seen, and the whole block is executed",
    },
    Family {
        name: "content/update-parent-broken",
        floor: Floor::Never,
        why: "two UpdateParents, one after the footer, one to a newer slot, one outside the \
              first slot of a leader window: each is refused",
    },
    Family {
        name: "content/decoy-footer",
        floor: Floor::VotesWithHandover,
        why: "a footer (and a tick) inside the abandoned prefix is never replayed, so it cannot \
              make the block invalid",
    },
    Family {
        name: "content/trailing",
        floor: Floor::Votes,
        why: "Agave's component parser stops at the end of the marker or of the last entry and \
              ignores what follows; the bytes are in no hash replay checks",
    },
    Family {
        name: "content/embedded-tx",
        floor: Floor::Votes,
        why: "instruction data is opaque to the block parser; a transaction is committed \
              whether or not its instruction succeeds",
    },
    Family {
        name: "content/count-lie",
        floor: Floor::Votes,
        why: "a count that covers less than the bytes present leaves trailing bytes, which are \
              ignored; the variants that claim more, or contradict the entry hash, are refused",
    },
    Family {
        name: "content/empty-entries",
        floor: Floor::Never,
        why: "an empty entry is a tick, and an Alpenglow block has exactly one, last",
    },
];

fn transfers(n: usize) -> Vec<Tx> {
    vec![Tx::Transfer; n]
}

fn batch(shape: &[usize]) -> Item {
    Item::Batch(shape.iter().map(|n| transfers(*n)).collect())
}

/// Header, the given batches, footer, alpentick.
fn honest(parent: Par, batches: &[&[usize]]) -> Vec<Item> {
    let mut items = vec![Item::Header(parent)];
    items.extend(batches.iter().map(|shape| batch(shape)));
    items.extend([Item::Footer, Item::Tick]);
    items
}

/// The block most corpus cases start from: 160 shreds, components at 0
/// (header), 32, 64 (batches), 96 (footer), 128 (alpentick).
fn base() -> Vec<Item> {
    honest(MAIN, &[&[2, 1], &[1]])
}

fn case(name: &str, family: &'static str, items: Vec<Item>, expect: Expect) -> Case {
    Case {
        name: name.to_string(),
        family,
        recipe: Recipe::new(0, items),
        expect,
        needs_handover: false,
        freeze: true,
    }
}

fn with_layout(mut case: Case, edit: impl FnOnce(&mut Layout)) -> Case {
    edit(&mut case.recipe.layout);
    case
}

fn handover(mut case: Case) -> Case {
    case.needs_handover = true;
    case
}

fn at_slot(mut case: Case, slot: u64) -> Case {
    case.recipe.slot = slot;
    case
}

fn voted(executed: usize, replay_start: u64, first_component: u32) -> Expect {
    Expect::VotedExecuting {
        executed,
        replay_start,
        first_component,
    }
}

/// A marker of a kind no version of Agave knows.
fn unknown_marker() -> Vec<u8> {
    let mut bytes = 0u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(9);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

/// The named cases. Every structurally distinct shape the generators can
/// produce has one here, next to the two known bugs and the premises.
pub fn corpus() -> Vec<Case> {
    use Expect::{DroppedShred, NotVoted, Report, Voted, VotedWithFailure};
    let b = |shape: &[usize]| batch(shape);
    let mut cases = Vec::new();

    // The two known bugs. Nothing below knows what the verifier does with
    // them; they are blocks Agave votes for.
    cases.push(handover(case(
        "known/c2-zero-parent-update-parent",
        "content/update-parent-zero-genesis",
        vec![
            Item::Header(GENESIS),
            b(&[2]),
            Item::Switch(GENESIS),
            b(&[1, 1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 64, 96),
    )));
    cases.push(handover(case(
        "known/c2-zero-parent-decoy-footer",
        "content/decoy-footer",
        vec![
            Item::Header(GENESIS),
            b(&[1]),
            Item::DecoyFooter,
            Item::Switch(GENESIS),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(1, 96, 128),
    )));
    cases.push(with_layout(
        handover(case(
            "known/split-header-update-parent-same",
            "content/update-parent-split-header",
            vec![
                Item::Header(MAIN),
                b(&[2]),
                Item::Switch(MAIN),
                b(&[1, 1]),
                Item::Footer,
                Item::Tick,
            ],
            voted(2, 64, 96),
        )),
        |layout| {
            layout.chunks.insert(0, vec![20]);
        },
    ));

    // Honest blocks.
    cases.push(case(
        "honest/two-batches",
        "content/honest",
        base(),
        voted(4, 0, 32),
    ));
    cases.push(case(
        "honest/one-transaction",
        "content/honest",
        honest(MAIN, &[&[1]]),
        voted(1, 0, 32),
    ));
    cases.push(case(
        "honest/no-transactions",
        "content/honest",
        honest(MAIN, &[]),
        voted(0, 0, 0),
    ));
    cases.push(case(
        "honest/on-genesis",
        "content/honest",
        honest(GENESIS, &[&[1, 1]]),
        voted(2, 0, 32),
    ));
    cases.push(at_slot(
        case(
            "honest/mid-window-slot",
            "content/honest",
            honest(MAIN, &[&[2]]),
            voted(2, 0, 32),
        ),
        MID_WINDOW_SLOT,
    ));

    // Premises: the facts "implied by finality" rests on, each asserted of
    // Agave alone.
    cases.push(case(
        "premise/replay-from-zero",
        "premise",
        base(),
        voted(4, 0, 32),
    ));
    cases.push(case(
        "premise/component-parse-kills/unknown-marker-kind",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Raw(unknown_marker()),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/component-parse-kills/entry-count-too-high",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::EntryCount(1),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/component-parse-kills/truncated-transaction",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1, 1]),
            Item::Truncate(10),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-batch-executed/second-batch",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 0, 32),
    ));
    cases.push(case(
        "premise/every-batch-executed/batch-after-footer",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            b(&[1]),
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-batch-executed/batch-after-final-tick",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Tick,
            b(&[1]),
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-batch-executed/second-tick-before-footer",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Tick,
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-batch-executed/second-tick-after-alpentick",
        "premise",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Tick,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-transaction-commits-or-kills/bad-signature",
        "premise",
        vec![
            Item::Header(MAIN),
            Item::Batch(vec![vec![Tx::Transfer, Tx::BadSignature]]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-transaction-commits-or-kills/unknown-blockhash",
        "premise",
        vec![
            Item::Header(MAIN),
            Item::Batch(vec![vec![Tx::Transfer, Tx::UnknownBlockhash]]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-transaction-commits-or-kills/duplicate",
        "premise",
        vec![
            Item::Header(MAIN),
            Item::Batch(vec![vec![Tx::Transfer]]),
            Item::Batch(vec![vec![Tx::Duplicate]]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "premise/every-transaction-commits-or-kills/instruction-failure",
        "premise",
        vec![
            Item::Header(MAIN),
            Item::Batch(vec![vec![Tx::Transfer, Tx::Failing]]),
            Item::Footer,
            Item::Tick,
        ],
        VotedWithFailure,
    ));
    let dropped = |name: &str, edit: Edit| {
        with_layout(
            case(
                &format!("premise/dropped-shreds-never-complete/{name}"),
                "premise",
                base(),
                DroppedShred(40),
            ),
            |layout| layout.edits.push(edit),
        )
    };
    cases.push(dropped(
        "data-complete-mid-set",
        Edit::OrFlags(40, FLAG_DATA_COMPLETE),
    ));
    cases.push(dropped(
        "last-in-slot-misaligned",
        Edit::OrFlags(40, FLAG_LAST_IN_SLOT),
    ));
    cases.push(dropped("flags-0x80-without-0x40", Edit::SetFlags(40, 0x80)));
    cases.push(dropped("parent-offset-zero", Edit::ParentOffset(40, 0)));
    cases.push(dropped("size-above-capacity", Edit::Size(40, 2000)));
    cases.push(dropped("size-below-headers", Edit::Size(40, 10)));

    // Layout shapes, all on the base block.
    let layout = |name: &str, family: &'static str, expect: Expect, edit: fn(&mut Layout)| {
        with_layout(
            case(&format!("layout/{name}"), family, base(), expect),
            edit,
        )
    };
    cases.push(layout(
        "split-header-on-main",
        "layout/split-header",
        NotVoted,
        |l| {
            l.chunks.insert(0, vec![20]);
        },
    ));
    cases.push(with_layout(
        case(
            "layout/split-header-on-genesis",
            "layout/split-header",
            honest(GENESIS, &[&[2, 1], &[1]]),
            Report,
        ),
        |l| {
            l.chunks.insert(0, vec![20]);
        },
    ));
    cases.push(layout(
        "header-in-second-shred",
        "layout/split-header",
        NotVoted,
        |l| {
            l.chunks.insert(0, vec![0]);
        },
    ));
    cases.push(layout("split-entry-count", "layout/split", Voted, |l| {
        l.chunks.insert(1, vec![3]);
    }));
    cases.push(layout("split-entry-header", "layout/split", Voted, |l| {
        l.chunks.insert(1, vec![8 + 20]);
    }));
    cases.push(layout("split-transaction", "layout/split", Voted, |l| {
        l.chunks.insert(1, vec![8 + 48 + 70]);
    }));
    cases.push(layout("split-footer", "layout/split", Voted, |l| {
        l.chunks.insert(3, vec![30]);
    }));
    cases.push(layout("split-alpentick", "layout/split", Voted, |l| {
        l.chunks.insert(4, vec![9]);
    }));
    cases.push(layout(
        "one-byte-shreds-across-two-sets",
        "layout/short",
        Voted,
        |l| {
            l.chunks.insert(1, vec![1; 40]);
        },
    ));
    cases.push(layout("short-sizes", "layout/short", Voted, |l| {
        l.chunks.insert(1, vec![50, 0, 7, 100, 0, 0, 1]);
        l.chunks.insert(3, vec![10, 10]);
    }));
    cases.push(layout("padding-nonzero", "layout/padding", Voted, |l| {
        l.edits.push(Edit::Padding(0, vec![0xaa; 40]));
        l.edits.push(Edit::Padding(33, vec![0xbb; 100]));
        l.edits.push(Edit::Padding(127, vec![0xcc; 7]));
    }));
    cases.push(layout(
        "complete-mid-set",
        "layout/complete-midset",
        NotVoted,
        |l| {
            l.ends.insert(1, End::MidSet);
        },
    ));
    cases.push(layout(
        "complete-missing-header-batch",
        "layout/complete-missing",
        Report,
        |l| {
            l.ends.insert(0, End::Missing);
        },
    ));
    cases.push(layout(
        "complete-missing-batch-batch",
        "layout/complete-missing",
        Report,
        |l| {
            l.ends.insert(1, End::Missing);
        },
    ));
    cases.push(layout(
        "complete-missing-batch-footer",
        "layout/complete-missing",
        Report,
        |l| {
            l.ends.insert(2, End::Missing);
        },
    ));
    cases.push(layout(
        "complete-missing-footer-alpentick",
        "layout/complete-missing",
        Report,
        |l| {
            l.ends.insert(3, End::Missing);
        },
    ));
    cases.push(layout(
        "complete-extra-inside-batch",
        "layout/complete-extra",
        Report,
        |l| {
            l.chunks.insert(1, vec![5; 40]);
            l.edits.push(Edit::OrFlags(63, FLAG_DATA_COMPLETE));
        },
    ));
    cases.push(layout("resigned-all", "layout/resigned", Report, |l| {
        l.resigned_sets = (0..5).collect();
    }));
    cases.push(layout("resigned-one-set", "layout/resigned", Report, |l| {
        l.resigned_sets = BTreeSet::from([1]);
    }));
    cases.push(layout(
        "last-in-slot-before-alpentick",
        "layout/last-in-slot",
        NotVoted,
        |l| {
            l.edits.push(Edit::OrFlags(127, FLAG_LAST_IN_SLOT));
        },
    ));
    cases.push(layout(
        "last-in-slot-missing",
        "layout/last-in-slot",
        NotVoted,
        |l| {
            l.edits.push(Edit::SetFlags(159, FLAG_DATA_COMPLETE));
        },
    ));
    cases.push(layout(
        "size-cuts-batch-short",
        "layout/shred-fields",
        NotVoted,
        |l| {
            l.edits.push(Edit::Size(32, 88 + 10));
        },
    ));
    cases.push(layout(
        "size-extends-header-with-zeros",
        "layout/shred-fields",
        Report,
        |l| {
            l.edits.push(Edit::Size(0, 88 + 200));
        },
    ));

    // Marker misuse.
    let marker = |name: &str, items: Vec<Item>| {
        case(
            &format!("markers/{name}"),
            "content/markers",
            items,
            NotVoted,
        )
    };
    cases.push(marker(
        "second-header",
        vec![
            Item::Header(MAIN),
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
    ));
    cases.push(marker(
        "header-after-entries",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
    ));
    cases.push(marker(
        "second-footer",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Footer,
            Item::Tick,
        ],
    ));
    cases.push(marker(
        "footer-before-entries",
        vec![Item::Header(MAIN), Item::Footer, b(&[1]), Item::Tick],
    ));
    cases.push(marker("no-header", vec![b(&[1]), Item::Footer, Item::Tick]));
    cases.push(marker(
        "no-footer",
        vec![Item::Header(MAIN), b(&[1]), Item::Tick],
    ));
    cases.push(marker(
        "no-alpentick",
        vec![Item::Header(MAIN), b(&[1]), Item::Footer],
    ));
    cases.push(marker(
        "header-wrong-id",
        honest(Par::Fake(PARENT_SLOT, 7), &[&[1]]),
    ));
    cases.push(marker(
        "header-zero-id-on-main",
        honest(Par::Fake(PARENT_SLOT, 0), &[&[1]]),
    ));
    cases.push(marker(
        "zero-entry-batch",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Raw(vec![0; 8]),
            Item::Footer,
            Item::Tick,
        ],
    ));

    // UpdateParent.
    let up = |name: &str, family: &'static str, items: Vec<Item>, expect: Expect| {
        case(&format!("update-parent/{name}"), family, items, expect)
    };
    let switched = |header: Par, prefix: Vec<Item>, to: Par, suffix: Vec<Item>| {
        let mut items = vec![Item::Header(header)];
        items.extend(prefix);
        items.push(Item::Switch(to));
        items.extend(suffix);
        items.extend([Item::Footer, Item::Tick]);
        items
    };
    cases.push(handover(up(
        "ancestor",
        "content/update-parent-ancestor",
        switched(SIDE, vec![b(&[2])], MAIN, vec![b(&[1, 1])]),
        voted(2, 64, 96),
    )));
    cases.push(handover(up(
        "ancestor-empty-prefix",
        "content/update-parent-ancestor",
        switched(SIDE, vec![], MAIN, vec![b(&[1])]),
        voted(1, 32, 64),
    )));
    cases.push(handover(up(
        "ancestor-empty-suffix",
        "content/update-parent-ancestor",
        switched(SIDE, vec![b(&[2])], MAIN, vec![]),
        voted(0, 64, 0),
    )));
    cases.push(handover(up(
        "to-genesis-from-main",
        "content/update-parent-ancestor",
        switched(MAIN, vec![b(&[1])], GENESIS, vec![b(&[1])]),
        voted(1, 64, 96),
    )));
    cases.push(up(
        "same-as-header",
        "content/update-parent-same",
        switched(MAIN, vec![b(&[1])], MAIN, vec![b(&[1])]),
        NotVoted,
    ));
    cases.push(handover(up(
        "duplicate-parent-block",
        "content/update-parent-duplicate-parent",
        switched(
            Par::Fake(PARENT_SLOT, 7),
            vec![b(&[1])],
            MAIN,
            vec![b(&[1])],
        ),
        voted(1, 64, 96),
    )));
    cases.push(handover(up(
        "zero-id-header-on-main",
        "content/update-parent-duplicate-parent",
        switched(
            Par::Fake(PARENT_SLOT, 0),
            vec![b(&[1])],
            MAIN,
            vec![b(&[1])],
        ),
        voted(1, 64, 96),
    )));
    cases.push(up(
        "zero-id-header-and-marker-on-main",
        "content/update-parent-same",
        switched(
            Par::Fake(PARENT_SLOT, 0),
            vec![b(&[1])],
            Par::Fake(PARENT_SLOT, 0),
            vec![b(&[1])],
        ),
        NotVoted,
    ));
    cases.push(with_layout(
        handover(up(
            "split-header-ancestor",
            "content/update-parent-split-header",
            switched(SIDE, vec![b(&[1])], MAIN, vec![b(&[1])]),
            voted(1, 64, 96),
        )),
        |l| {
            l.chunks.insert(0, vec![53]);
        },
    ));
    cases.push(up(
        "hidden-after-batch",
        "content/update-parent-hidden",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Trail(Trailer::UpdateParent(MAIN)),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 0, 32),
    ));
    cases.push(up(
        "hidden-ancestor-after-batch",
        "content/update-parent-hidden",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Trail(Trailer::UpdateParent(GENESIS)),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 0, 32),
    ));
    cases.push(with_layout(
        up(
            "marker-in-second-shred",
            "content/update-parent-broken",
            switched(SIDE, vec![b(&[1])], MAIN, vec![b(&[1])]),
            NotVoted,
        ),
        |l| {
            l.chunks.insert(2, vec![0]);
        },
    ));
    cases.push(up(
        "two-markers",
        "content/update-parent-broken",
        vec![
            Item::Header(SIDE),
            b(&[1]),
            Item::Switch(MAIN),
            b(&[1]),
            Item::Switch(GENESIS),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(up(
        "two-markers-same-parent",
        "content/update-parent-broken",
        vec![
            Item::Header(SIDE),
            b(&[1]),
            Item::Switch(MAIN),
            b(&[1]),
            Item::Switch(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(up(
        "after-footer",
        "content/update-parent-broken",
        vec![
            Item::Header(SIDE),
            b(&[1]),
            Item::Footer,
            Item::Switch(MAIN),
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(up(
        "to-newer-slot",
        "content/update-parent-broken",
        switched(MAIN, vec![b(&[1])], SIDE, vec![b(&[1])]),
        NotVoted,
    ));
    cases.push(at_slot(
        up(
            "mid-window-slot",
            "content/update-parent-broken",
            switched(SIDE, vec![b(&[1])], MAIN, vec![b(&[1])]),
            NotVoted,
        ),
        MID_WINDOW_SLOT,
    ));
    cases.push(handover(up(
        "decoy-footer-in-prefix",
        "content/decoy-footer",
        switched(SIDE, vec![b(&[1]), Item::DecoyFooter], MAIN, vec![b(&[1])]),
        voted(1, 96, 128),
    )));
    cases.push(handover(up(
        "footer-and-tick-in-prefix",
        "content/decoy-footer",
        switched(
            SIDE,
            vec![b(&[1]), Item::DecoyFooter, Item::Tick],
            MAIN,
            vec![b(&[1])],
        ),
        voted(1, 128, 160),
    )));

    // Trailing bytes.
    let trailing = |name: &str, items: Vec<Item>, expect: Expect| {
        case(
            &format!("trailing/{name}"),
            "content/trailing",
            items,
            expect,
        )
    };
    let junk = || Trailer::Bytes((1..=40).collect());
    cases.push(trailing(
        "zeros-after-header",
        vec![
            Item::Header(MAIN),
            Item::Trail(Trailer::Zeros(40)),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        Voted,
    ));
    cases.push(trailing(
        "bytes-after-header",
        vec![
            Item::Header(MAIN),
            Item::Trail(junk()),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        Voted,
    ));
    cases.push(trailing(
        "second-header-after-header",
        vec![
            Item::Header(MAIN),
            Item::Trail(Trailer::Header(SIDE)),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        Voted,
    ));
    cases.push(trailing(
        "bytes-after-footer",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Trail(junk()),
            Item::Tick,
        ],
        Voted,
    ));
    cases.push(handover(trailing(
        "bytes-after-update-parent",
        vec![
            Item::Header(SIDE),
            b(&[1]),
            Item::Switch(MAIN),
            Item::Trail(junk()),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        Voted,
    )));
    cases.push(trailing(
        "bytes-after-last-entry",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Trail(junk()),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 0, 32),
    ));
    cases.push(trailing(
        "transaction-after-last-entry",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Trail(Trailer::Transaction(Tx::Transfer)),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 0, 32),
    ));
    cases.push(trailing(
        "footer-after-last-entry",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Trail(Trailer::Footer),
            Item::Footer,
            Item::Tick,
        ],
        voted(1, 0, 32),
    ));
    cases.push(trailing(
        "bytes-after-alpentick",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::Footer,
            Item::Tick,
            Item::Trail(junk()),
        ],
        Voted,
    ));

    // Transaction-shaped bytes where no transaction is.
    cases.push(case(
        "embedded/transaction-in-instruction-data",
        "content/embedded-tx",
        vec![
            Item::Header(MAIN),
            Item::Batch(vec![vec![Tx::Embedding, Tx::Transfer]]),
            Item::Footer,
            Item::Tick,
        ],
        voted(2, 0, 32),
    ));

    // Counts that disagree with the bytes.
    let lie = |name: &str, items: Vec<Item>, expect: Expect| {
        case(
            &format!("count-lie/{name}"),
            "content/count-lie",
            items,
            expect,
        )
    };
    cases.push(lie(
        "uncounted-entry-after-batch",
        vec![
            Item::Header(MAIN),
            b(&[1, 1]),
            Item::Trail(Trailer::Entry(vec![Tx::Transfer, Tx::Transfer])),
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        voted(3, 0, 32),
    ));
    cases.push(lie(
        "entry-count-too-low",
        vec![
            Item::Header(MAIN),
            b(&[1, 1]),
            Item::EntryCount(-1),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(lie(
        "transaction-count-too-high",
        vec![
            Item::Header(MAIN),
            b(&[1]),
            Item::TxCount(1),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(lie(
        "transaction-count-too-low",
        vec![
            Item::Header(MAIN),
            b(&[2]),
            Item::TxCount(-1),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));

    // Empty entries.
    cases.push(case(
        "empty/empty-entry-in-batch",
        "content/empty-entries",
        vec![
            Item::Header(MAIN),
            Item::Batch(vec![transfers(1), vec![]]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));
    cases.push(case(
        "empty/tick-before-entries",
        "content/empty-entries",
        vec![
            Item::Header(MAIN),
            Item::Tick,
            b(&[1]),
            Item::Footer,
            Item::Tick,
        ],
        NotVoted,
    ));

    cases.extend(agave_table());
    for (seed, case) in cases.iter_mut().enumerate() {
        case.recipe.seed = 1000 + seed as u64;
    }
    cases
}

/// Agave's `test_processor_component_sequences`
/// (`runtime/src/block_component_processor.rs`), post-migration rows, as
/// blocks. The table drives `BlockComponentProcessor` directly; here each row
/// is a whole block, so only the verdict (votes or not) is comparable.
///
/// Letters: `h` header, `e` entry batch, `t` a tick that is not the last
/// component, `F` footer, `A` the alpentick, `U` an UpdateParent replay
/// starts at (written as header on the side parent, one abandoned batch,
/// marker), `u` an UpdateParent met in the middle of a block.
///
/// Rows the table marks Ok but that hold a mid-block tick are expected not
/// to vote: the processor accepts the tick and `verify_ticks` then counts
/// two. Rows with a genesis certificate are left out (this chain has
/// Alpenglow from slot 0, where the marker is never valid).
fn agave_table() -> Vec<Case> {
    const OK: bool = true;
    const ERR: bool = false;
    let rows: &[(&str, bool, &str)] = &[
        ("hFA", OK, "valid block"),
        ("heeFA", OK, "valid block"),
        ("UeFA", OK, "valid block from UpdateParent"),
        ("UFA", OK, "valid block from UpdateParent"),
        (
            "htFA",
            ERR,
            "table Ok: mid-block tick passes the processor, not the tick count",
        ),
        (
            "UtFA",
            ERR,
            "table Ok: mid-block tick passes the processor, not the tick count",
        ),
        ("", ERR, "MissingBlockFooter"),
        ("e", ERR, "MissingParentMarker"),
        ("F", ERR, "MissingParentMarker"),
        ("A", ERR, "MissingParentMarker"),
        ("t", ERR, "MissingParentMarker"),
        ("hh", ERR, "MultipleBlockHeaders"),
        ("heh", ERR, "MultipleBlockHeaders"),
        ("hFh", ERR, "MultipleBlockHeaders"),
        ("Uh", ERR, "SpuriousUpdateParent"),
        ("Uu", ERR, "MultipleUpdateParents"),
        ("hu", ERR, "AbandonedBank"),
        ("heu", ERR, "AbandonedBank"),
        ("hFu", ERR, "SpuriousUpdateParent"),
        ("hA", ERR, "InvalidAlpentickPosition"),
        ("heA", ERR, "InvalidAlpentickPosition"),
        ("UA", ERR, "InvalidAlpentickPosition"),
        ("hFeA", ERR, "EntryBatchAfterBlockFooter"),
        ("hFF", ERR, "MultipleBlockFooters"),
        ("hFtA", ERR, "EntryBatchAfterBlockFooter"),
        ("hFe", ERR, "EntryBatchAfterBlockFooter"),
        ("hFAh", ERR, "MultipleBlockHeaders"),
        ("hFAe", ERR, "EntryBatchAfterBlockFooter"),
        ("hFAt", ERR, "EntryBatchAfterBlockFooter"),
        ("hFAA", ERR, "InvalidAlpentickPosition"),
        ("hFAF", ERR, "MultipleBlockFooters"),
        ("hFAu", ERR, "SpuriousUpdateParent"),
        ("h", ERR, "MissingBlockFooter"),
        ("he", ERR, "MissingBlockFooter"),
        ("Ue", ERR, "MissingBlockFooter"),
        ("hF", ERR, "InvalidAlpentickPosition"),
    ];
    rows.iter()
        .enumerate()
        .filter(|(_, (sequence, _, _))| !sequence.is_empty())
        .map(|(row, (sequence, votes, reason))| {
            let mut items = Vec::new();
            // A block whose replay starts at an UpdateParent, or that meets
            // one, starts on the side parent so the marker is a real switch.
            let switches = sequence.contains(['U', 'u']);
            let first_parent = if switches { SIDE } else { MAIN };
            for letter in sequence.chars() {
                match letter {
                    'h' => items.push(Item::Header(first_parent)),
                    'e' => items.push(batch(&[1])),
                    't' | 'A' => items.push(Item::Tick),
                    'F' => items.push(Item::Footer),
                    'U' => {
                        items.extend([Item::Header(first_parent), batch(&[1]), Item::Switch(MAIN)])
                    }
                    'u' => items.push(Item::Switch(MAIN)),
                    other => unreachable!("letter {other}"),
                }
            }
            Case {
                name: format!("agave-table/{row:02}-{sequence}-{}", reason_slug(reason)),
                family: "agave-table",
                recipe: Recipe::new(0, items),
                expect: if *votes {
                    Expect::Voted
                } else {
                    Expect::NotVoted
                },
                needs_handover: switches && *votes,
                freeze: false,
            }
        })
        .collect()
}

fn reason_slug(reason: &str) -> String {
    reason
        .split([' ', ':'])
        .next()
        .unwrap_or_default()
        .to_string()
}

fn random_batches(rng: &mut Rng, min: usize, max: usize) -> Vec<Item> {
    (0..rng.range(min, max))
        .map(|_| {
            Item::Batch(
                (0..rng.range(1, 3))
                    .map(|_| {
                        (0..rng.range(1, 3))
                            .map(|_| match rng.chance(8) {
                                true => Tx::Failing,
                                false => Tx::Transfer,
                            })
                            .collect()
                    })
                    .collect(),
            )
        })
        .collect()
}

fn random_honest(rng: &mut Rng, parent: Par) -> Vec<Item> {
    let mut items = vec![Item::Header(parent)];
    items.extend(random_batches(rng, 1, 3));
    items.extend([Item::Footer, Item::Tick]);
    items
}

fn random_switch(
    rng: &mut Rng,
    header: Par,
    to: Par,
    min_prefix: usize,
    extra_prefix: Vec<Item>,
) -> Vec<Item> {
    let mut items = vec![Item::Header(header)];
    items.extend(random_batches(rng, min_prefix, 2));
    items.extend(extra_prefix);
    items.push(Item::Switch(to));
    items.extend(random_batches(rng, 0, 2));
    items.extend([Item::Footer, Item::Tick]);
    items
}

fn random_trailer(rng: &mut Rng) -> Trailer {
    match rng.below(7) {
        0 => Trailer::Zeros(rng.range(1, 300)),
        1 => {
            let len = rng.range(1, 300);
            Trailer::Bytes(rng.nonzero_bytes(len))
        }
        2 => Trailer::Header(*pick(rng, &[MAIN, SIDE, GENESIS])),
        3 => Trailer::UpdateParent(*pick(rng, &[MAIN, SIDE, GENESIS])),
        4 => Trailer::Footer,
        5 => Trailer::Entry(transfers(rng.range(0, 2))),
        _ => Trailer::Transaction(Tx::Transfer),
    }
}

fn pick<'a, T>(rng: &mut Rng, from: &'a [T]) -> &'a T {
    &from[rng.below(from.len())]
}

/// Indexes in `items` of the entries that open a component.
fn component_items(items: &[Item]) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            !matches!(
                item,
                Item::Trail(_) | Item::EntryCount(_) | Item::TxCount(_) | Item::Truncate(_)
            )
        })
        .map(|(i, _)| i)
        .collect()
}

/// Case `n` of `--random` with `seed`: the family is `n` modulo the number
/// of families, and everything else comes from a generator seeded with both.
pub fn generate(world: &World, seed: u64, n: u64) -> Case {
    let family = &FAMILIES[(n % FAMILIES.len() as u64) as usize];
    let mut rng = Rng::new(seed.wrapping_mul(0x1_0000_0001).wrapping_add(n));
    let rng = &mut rng;
    let mut recipe = Recipe::new(seed.wrapping_mul(1_000_003).wrapping_add(n), vec![]);
    let mut needs_handover = false;
    let lengths = |world: &World, recipe: &Recipe| -> Vec<usize> {
        world
            .components(recipe, Hash::default())
            .iter()
            .map(Vec::len)
            .collect()
    };

    match family.name {
        "content/honest" => recipe.items = random_honest(rng, MAIN),
        "layout/split" => {
            recipe.items = random_honest(rng, MAIN);
            let lens = lengths(world, &recipe);
            for _ in 0..rng.range(1, 2) {
                let component = rng.range(1, lens.len() - 1);
                let most = lens[component].min(963).saturating_sub(1).max(1);
                recipe
                    .layout
                    .chunks
                    .insert(component, vec![rng.range(1, most)]);
            }
        }
        "layout/short" => {
            recipe.items = random_honest(rng, MAIN);
            let lens = lengths(world, &recipe);
            for _ in 0..rng.range(1, 3) {
                let component = rng.range(1, lens.len() - 1);
                let chunks = (0..rng.range(2, 20)).map(|_| rng.range(0, 120)).collect();
                recipe.layout.chunks.insert(component, chunks);
            }
        }
        "layout/padding" => {
            recipe.items = random_honest(rng, MAIN);
            let shreds = world.shape(&recipe).len();
            for _ in 0..rng.range(1, 6) {
                let index = rng.below(shreds) as u32;
                let len = rng.range(1, 60);
                let padding = rng.nonzero_bytes(len);
                recipe.layout.edits.push(Edit::Padding(index, padding));
            }
        }
        "layout/split-header" => {
            let parent = if rng.chance(30) { GENESIS } else { MAIN };
            recipe.items = random_honest(rng, parent);
            let first = if rng.chance(15) { 0 } else { rng.range(1, 53) };
            recipe.layout.chunks.insert(0, vec![first]);
        }
        "layout/complete-midset" => {
            recipe.items = random_honest(rng, MAIN);
            let components = lengths(world, &recipe).len();
            // The last component's flag lands on the block's last shred
            // whatever is asked, so it is left out.
            recipe
                .layout
                .ends
                .insert(rng.below(components - 1), End::MidSet);
        }
        "layout/complete-missing" => {
            recipe.items = random_honest(rng, MAIN);
            let components = lengths(world, &recipe).len();
            recipe
                .layout
                .ends
                .insert(rng.below(components - 1), End::Missing);
        }
        "layout/complete-extra" => {
            recipe.items = random_honest(rng, MAIN);
            let lens = lengths(world, &recipe);
            let component = rng.range(1, lens.len() - 3);
            let chunks: Vec<usize> = (0..rng.range(33, 60)).map(|_| rng.range(1, 6)).collect();
            recipe.layout.chunks.insert(component, chunks);
            // Components before it are one FEC set each.
            let last_of_first_set = (component as u32) * 32 + 31;
            recipe
                .layout
                .edits
                .push(Edit::OrFlags(last_of_first_set, FLAG_DATA_COMPLETE));
        }
        "layout/resigned" => {
            recipe.items = random_honest(rng, MAIN);
            let sets = (world.shape(&recipe).len() / 32) as u32;
            let all = rng.chance(40);
            recipe.layout.resigned_sets = (0..sets).filter(|_| all || rng.chance(40)).collect();
            if recipe.layout.resigned_sets.is_empty() {
                recipe
                    .layout
                    .resigned_sets
                    .insert(rng.below(sets as usize) as u32);
            }
        }
        "layout/last-in-slot" => {
            recipe.items = random_honest(rng, MAIN);
            let shreds = world.shape(&recipe).len() as u32;
            let edit = match rng.below(4) {
                // Early, at the end of a FEC set.
                0 => Edit::OrFlags(
                    32 * rng.range(1, shreds as usize / 32 - 1) as u32 - 1,
                    FLAG_LAST_IN_SLOT,
                ),
                // Anywhere but the end of a set.
                1 => {
                    let index = rng.below(shreds as usize - 1) as u32;
                    Edit::OrFlags(index - index % 32 + index % 31, FLAG_LAST_IN_SLOT)
                }
                // Missing.
                2 => Edit::SetFlags(shreds - 1, FLAG_DATA_COMPLETE),
                // The high bit without the DATA_COMPLETE bit.
                _ => Edit::SetFlags(rng.below(shreds as usize) as u32, 0x80),
            };
            recipe.layout.edits.push(edit);
        }
        "layout/shred-fields" => {
            recipe.items = random_honest(rng, MAIN);
            let shreds = world.shape(&recipe).len();
            let index = rng.below(shreds) as u32;
            let edit = match rng.below(3) {
                0 => Edit::ParentOffset(index, rng.below(40) as u16),
                1 => Edit::Size(index, rng.below(1300) as u16),
                _ => Edit::SetFlags(index, rng.next() as u8),
            };
            recipe.layout.edits.push(edit);
        }
        "content/markers" => {
            let mut items = random_honest(rng, MAIN);
            let footer = items.len() - 2;
            match rng.below(9) {
                0 => items.insert(1, Item::Header(MAIN)),
                1 => items.insert(rng.range(2, footer), Item::Header(MAIN)),
                2 => items.insert(footer, Item::Footer),
                3 => items.swap(1, footer),
                4 => {
                    items.remove(0);
                }
                5 => {
                    items.remove(footer);
                }
                6 => {
                    items.pop();
                }
                7 => items[0] = Item::Header(Par::Fake(PARENT_SLOT, rng.below(256) as u8)),
                _ => items.insert(rng.range(1, footer), Item::Raw(vec![0; 8])),
            }
            recipe.items = items;
        }
        "content/update-parent-ancestor" => {
            needs_handover = true;
            let (header, to) = *pick(rng, &[(SIDE, MAIN), (SIDE, MAIN), (MAIN, GENESIS)]);
            recipe.items = random_switch(rng, header, to, 0, vec![]);
        }
        "content/update-parent-same" => {
            recipe.items = random_switch(rng, MAIN, MAIN, 0, vec![]);
        }
        "content/update-parent-split-header" => {
            needs_handover = true;
            let (header, to) = *pick(rng, &[(MAIN, MAIN), (MAIN, MAIN), (SIDE, MAIN)]);
            recipe.items = random_switch(rng, header, to, 1, vec![]);
            recipe.layout.chunks.insert(0, vec![rng.range(1, 53)]);
        }
        "content/update-parent-zero-genesis" => {
            needs_handover = true;
            recipe.items = random_switch(rng, GENESIS, GENESIS, 1, vec![]);
        }
        "content/update-parent-duplicate-parent" => {
            needs_handover = true;
            let id = if rng.chance(30) {
                0
            } else {
                rng.range(1, 255) as u8
            };
            recipe.items = random_switch(rng, Par::Fake(PARENT_SLOT, id), MAIN, 1, vec![]);
        }
        "content/update-parent-hidden" => {
            let mut items = vec![Item::Header(MAIN)];
            items.extend(random_batches(rng, 1, 2));
            items.push(Item::Trail(Trailer::UpdateParent(*pick(
                rng,
                &[MAIN, SIDE, GENESIS],
            ))));
            items.extend(random_batches(rng, 0, 2));
            items.extend([Item::Footer, Item::Tick]);
            recipe.items = items;
        }
        "content/update-parent-broken" => match rng.below(5) {
            0 => {
                let mut items = random_switch(rng, SIDE, MAIN, 1, vec![]);
                let footer = items.len() - 2;
                let second = *pick(rng, &[MAIN, GENESIS]);
                items.insert(footer, Item::Switch(second));
                items.insert(footer + 1, batch(&[1]));
                recipe.items = items;
            }
            1 => {
                let mut items = random_honest(rng, SIDE);
                let tick = items.len() - 1;
                items.insert(tick, Item::Switch(MAIN));
                recipe.items = items;
            }
            2 => recipe.items = random_switch(rng, MAIN, SIDE, 1, vec![]),
            3 => {
                recipe.items = random_switch(rng, SIDE, MAIN, 1, vec![]);
                recipe.slot = MID_WINDOW_SLOT;
            }
            _ => {
                recipe.items = random_switch(rng, SIDE, MAIN, 1, vec![]);
                let marker = recipe
                    .items
                    .iter()
                    .position(|item| matches!(item, Item::Switch(_)))
                    .unwrap();
                recipe.layout.chunks.insert(marker, vec![0]);
            }
        },
        "content/decoy-footer" => {
            needs_handover = true;
            let (header, to) = *pick(rng, &[(SIDE, MAIN), (SIDE, MAIN), (GENESIS, GENESIS)]);
            let mut decoy = vec![Item::DecoyFooter];
            if rng.chance(50) {
                decoy.push(Item::Tick);
            }
            if rng.chance(30) {
                decoy.push(batch(&[1]));
            }
            recipe.items = random_switch(rng, header, to, 0, decoy);
        }
        "content/trailing" => {
            let with_switch = rng.chance(25) && world.handover;
            let mut items = match with_switch {
                true => random_switch(rng, SIDE, MAIN, 1, vec![]),
                false => random_honest(rng, MAIN),
            };
            needs_handover = with_switch;
            for _ in 0..rng.range(1, 2) {
                let components = component_items(&items);
                let after = *pick(rng, &components);
                // A trailer goes after any modifiers already there.
                let mut at = after + 1;
                while matches!(items.get(at), Some(Item::Trail(_))) {
                    at += 1;
                }
                items.insert(at, Item::Trail(random_trailer(rng)));
            }
            recipe.items = items;
        }
        "content/embedded-tx" => {
            let mut items = random_honest(rng, MAIN);
            let mut placed = false;
            for item in &mut items {
                if let Item::Batch(entries) = item {
                    for entry in entries {
                        for tx in entry {
                            if !placed || rng.chance(30) {
                                *tx = Tx::Embedding;
                                placed = true;
                            }
                        }
                    }
                }
            }
            recipe.items = items;
        }
        "content/count-lie" => {
            let mut items = random_honest(rng, MAIN);
            let batches: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, item)| matches!(item, Item::Batch(_)))
                .map(|(i, _)| i)
                .collect();
            let after = *pick(rng, &batches) + 1;
            let lie = match rng.below(6) {
                0 => Item::Trail(Trailer::Entry(transfers(rng.range(0, 2)))),
                1 => Item::Trail(Trailer::Transaction(Tx::Transfer)),
                2 => Item::EntryCount(1),
                3 => Item::EntryCount(-1),
                4 => Item::TxCount(1),
                _ => Item::TxCount(-1),
            };
            items.insert(after, lie);
            recipe.items = items;
        }
        "content/empty-entries" => {
            let mut items = random_honest(rng, MAIN);
            let footer = items.len() - 2;
            match rng.below(3) {
                0 => items.insert(rng.range(1, footer), Item::Tick),
                1 => items.insert(footer + 1, Item::Tick),
                _ => {
                    let Some(Item::Batch(entries)) = items.get_mut(1) else {
                        unreachable!("an honest block has a batch after its header")
                    };
                    entries.insert(rng.below(entries.len() + 1), vec![]);
                }
            }
            recipe.items = items;
        }
        other => unreachable!("family {other} has no generator"),
    }

    if recipe.slot != MID_WINDOW_SLOT {
        recipe.slot = window_slot(recipe.header_parent().slot());
    }
    Case {
        name: format!("random/{}/{seed}-{n}", family.name),
        family: family.name,
        recipe,
        expect: Expect::Report,
        needs_handover,
        freeze: false,
    }
}

/// Per-family tally of a run.
#[derive(Debug, Clone, Default)]
pub struct Tally {
    /// Cases run.
    pub cases: usize,
    /// Cases Agave voted for.
    pub voted: usize,
    /// Claims offered to the verifier.
    pub claims: usize,
    /// Claims it accepted.
    pub accepted: usize,
    /// Property violations.
    pub violations: usize,
}

/// Checks a run's tallies against the floors. Returns one line per family
/// that broke its floor.
pub fn check_floors(tallies: &BTreeMap<String, Tally>, handover: bool) -> Vec<String> {
    let mut failures = Vec::new();
    for family in FAMILIES {
        let Some(tally) = tallies.get(family.name) else {
            continue;
        };
        let must_vote = match family.floor {
            Floor::Votes => Some(true),
            Floor::VotesWithHandover => Some(handover),
            Floor::Never => Some(false),
            Floor::Any => None,
        };
        match must_vote {
            Some(true) if tally.voted == 0 => failures.push(format!(
                "FLOOR {}: 0 of {} cases voted, so soundness was never exercised for it. It \
                 should vote because {}",
                family.name, tally.cases, family.why
            )),
            Some(false) if tally.voted > 0 => failures.push(format!(
                "CEILING {}: {} of {} cases voted, and none should{}: {}",
                family.name,
                tally.voted,
                tally.cases,
                if family.floor == Floor::VotesWithHandover {
                    " with fast leader handover off"
                } else {
                    ""
                },
                family.why
            )),
            _ => {}
        }
    }
    failures
}
