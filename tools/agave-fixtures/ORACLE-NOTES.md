# Oracle spike: notes

What `src/oracle.rs` and `diff-fuzz --smoke` established against Agave v4.4.1,
and what they leave open. Written for whoever builds the full oracle next.

## Build and run

```
cd tools/agave-fixtures
cargo build --release --bin diff-fuzz
target/release/diff-fuzz --smoke
```

The run takes about 0.2 s and is deterministic: two runs print the same
genesis hash, bank hashes and block ids. `CHECK` lines decide the exit status.
`ANSWER` lines report what the run observed and never fail the run. An
abridged run is at the end of this file.

## Result

Replay came up. The fallback (insert-only oracle) was not needed.

For an honest block cut by `testkit::BlockBuilder` and signed by the oracle,
Agave's filter, sigverify, parser, untrusted insert and `process_single_slot`
all accept it, the bank freezes with the footer's hash, and:

- the light client's block id equals `get_double_merkle_root`;
- the light client's parent equals `SlotMeta`'s `(parent_slot, parent_block_id)`;
- the light client's signature list equals what Agave executed, in order;
- the executed list read from `get_slot_component_views_with_shred_info` and
  the one drained from the `TransactionStatusSender` agree, with coordinates
  `(component start, entry, transaction)` equal to what was built;
- every recipient holds its transfer in the frozen bank.

## Answers

**(i) Is the bank hash independent of shred layout?** Yes, for the case tried.
The first entry batch (1227 bytes, FEC set 32..63) was re-cut so its first
shred carries 100 bytes and the rest moves into the following shreds; the
deshredded component bytes are identical. The block is voted with the same
footer and the same bank hash. The block id changes, as it must. So layout
mutators can reuse one settled footer, and only content mutators need the
two-pass footer. One layout was tried, not a family.

**(ii) Do data-only FEC sets yield `is_full()` and a block id?** Yes. No coding
shred is ever inserted; the testkit's filler coding leaves only exist inside
the Merkle proofs. `SlotMeta::is_full()` is true and the double Merkle root is
present and equal to the light client's.

**(iii) Wall time per case.** About 2 ms for the 9-transaction block (160
shreds: ingest 1.1 ms, replay 0.8 ms), slot reset included. A 500-transaction
block in 224 shreds: ingest 1.6 ms, replay about 10 ms. A two-pass content
case costs twice that plus building. Oracle construction is about 70 ms.
2000 random cases are a matter of seconds, not minutes.

**Other things the run settled.**

- Slot time under the all-features genesis is 200 ms, not 400: the footer
  window for 36 on 32 is 1600 ms wide (`2 * 4 * 200 ms`). Use
  `Oracle::footer_time_bounds`, which calls Agave's `nanosecond_time_bounds`;
  the smoke checks both edges.
- The bank hash depends on the footer timestamp (same block, timestamp on the
  upper bound: different computed hash).
- Entries whose transactions conflict (all transfers are paid by the mint,
  several per entry) replay fine under the unified scheduler.
- A transaction that cannot be committed (unknown blockhash, bad signature)
  fails the whole block and kills the slot. A transaction that is committed
  and fails (transfer of more than the payer has) leaves the block valid; its
  commit status is `Ok(Err(InstructionError(0, Custom(1))))` and the recipient
  holds nothing. That status is how an included-but-ineffective transaction
  shows up.
- `process_single_slot` panics (`"Full block must have block id"`) if a slot
  replays without a double Merkle root; the oracle checks for one first.

## Library API

`agave_fixtures::oracle`:

- `Oracle::new(OracleConfig) -> Oracle`. One validator (seeded keys), all
  features active, Alpenglow from slot 0, `EpochSchedule::custom(32, 32,
  false)`, fixed `creation_time`, one blockstore in a temp dir, a unified
  scheduler pool with a `TransactionStatusSender`.
- `oracle.build_honest(&HonestSpec) -> HonestBlock`: component bytes
  (wincode of Agave's `BlockComponent`s), the transactions with their
  positions, recipients and amounts. `HonestSpec::abandoned` adds an abandoned
  prefix and an UpdateParent marker.
- Pieces for content mutators: `header_bytes`, `update_parent_bytes`,
  `footer_bytes`, `entry_batch_bytes(&mut chain, entries)`, `transfer`,
  `recipient`, `block_ref(slot)`, `last_blockhash(slot)`, `footer_time`,
  `footer_time_bounds`.
- Shredding: `oracle.shred(slot, parent, &components) -> BlockBuilder`,
  `set_layout(&mut builder, start, chunks)`, `split_first(bytes, n)`,
  `oracle.sign(&mut payloads)`, `oracle.shred_and_sign(..)`.
- `oracle.judge(slot, &payloads) -> Verdict`, `judge_with(.., &JudgeOptions {
  replay, batch })`. `Verdict` holds per-shred outcomes (filter reason,
  signature, parse error), insert error, duplicate reports, `MetaView`,
  `dead_after_insert`, `dead`, `block_id`, `replay: Replay` (`Skipped`,
  `NotReplayable`, `Deferred`, `Failed { error, bank_hash_mismatch }`, `Ok`),
  `bank_hash`, `voted`, `replay_start`, `view`, `statuses`, `executed`, and
  timings. `Verdict::order_independent()` is the string to compare across
  arrival orders.
- `oracle.settle_bank_hash(&spec) -> (Option<Hash>, Verdict)`: pass 1 of the
  two-pass footer.
- `oracle.reset_slot(slot)`, `oracle.bank(slot)`, `oracle.blockstore()`,
  `oracle.alpenglow_shred_rules(slot)`, `oracle.fast_leader_handover()`.
- `replay_start(..) -> ReplayStart`: the copied replay-stage rule.

`judge` resets the slot first and leaves its state behind afterward, so a
voted block stays as a frozen bank and can parent later blocks. The same slot
can be judged any number of times; the smoke judges slot 36 about forty times
and ends by checking the honest block still gets its original verdict.

## What is copied from Agave rather than called

Both are private to `solana-core`, which is why they are copies.

- `replay_start` is `child_bank_replay_start`
  (`core/src/replay_stage/update_parent.rs:56`), verbatim in logic.
- The duplicate handler in `judge_with` is the closure in
  `run_check_duplicate` (`core/src/window_service.rs:112`): the
  `no_verify_chained_merkle_root` feature check, `handle_duplicate_shred`,
  then `set_dead_slot_if_duplicate_and_not_full` once past the Alpenglow
  genesis. Gossip and the duplicate-slot channel are left out.

Slot cleanup in `reset_slot` follows `purge_unconfirmed_slot`
(`core/src/replay_stage.rs:2274`): `dump_slots`, `remove_unrooted_slots`,
`clear_slot_signatures`, `prune_program_cache_by_deployment_slot`, plus
`purge_slots_cleanup_chaining(.., PurgeType::Exact)` on the blockstore.

## Deviations from the brief

- **Replay-start condition.** The brief gives the UpdateParent start as "fast
  leader handover active, slot % 4 == 0, `has_update_parent()`". At v4.4.1
  `child_bank_replay_start` tests only `has_update_parent()`. The other two
  conditions are enforced elsewhere in code the oracle calls: the blockstore
  kills a slot with an UpdateParent outside the first slot of a leader window
  (`validate_update_parent_slot`), and `confirm_slot` only lets an UpdateParent
  be the first marker when the feature is on and the slot index is 0. The
  source was followed.
- **Parent chain.** Not 32 real blocks. Slot 32 is one honest block built
  directly on genesis (slots 1..31 skipped), and test slots build on 32. That
  puts every judged slot in epoch 1 with a parent that has a real block id.
  The bank for slot 32 crosses the epoch boundary in one step.
- **Genesis bank.** `Bank::new_for_tests`, frozen as is, instead of replaying
  slot 0 from a genesis ledger. Its last blockhash is the genesis hash.
- **Bank hash verification.** `process_single_slot` always compares the footer
  hash. The live replay stage skips that comparison for blocks the node itself
  led. The oracle is the leader of every slot by key but judges as a
  non-leader, which is the behavior wanted.
- **More than asked.** Teeth checks, the UpdateParent case and the arrival
  order preview were added because they were cheap and the next task leans on
  them.

## Caveats and things not verified

- **Final state only.** The oracle inserts every shred, then replays the full
  slot once. The live replay stage replays partial slots as shreds arrive, can
  hit `AbandonedBank` on a prefix and restart from the UpdateParent, and has
  soft-dead handling (`is_update_parent_recoverable_replay_error`). None of
  that interleaving is modeled. A slot that never fills is reported
  `NotReplayable("slot is not full")`; the live stage would have replayed its
  prefix.
- **`process_single_slot` is the startup path**, not
  `replay_blockstore_into_bank`. Both go through `confirm_slot`; the
  bank-completion code differs (see the bank hash point above). No difference
  that changes a verdict was found by reading, but only the cases in the smoke
  were run.
- **Deferred is not dead.** A deferred slot stays undead in the blockstore
  forever in this model. In a live validator votor could repair a different
  parent block and replay could continue. "Would vote" treats deferred as no.
- **Root never moves.** The root stays at genesis, so `MigrationStatus` is
  `AlpenglowEnabled`, never `FullAlpenglowEpoch`. At v4.4.1 that phase is only
  read by gossip and cluster-slots code, not by blockstore or replay. The
  shred filter's slot window is `root + 500`.
- **Epoch 0 is untested.** Shred rules gated on a feature apply one epoch
  after activation (`first_effective_shred_slot`), so for slots below 32 the
  duplicate handler would treat a broken chained Merkle root as fatal. The
  testkit chains FEC sets correctly inside a slot, so honest blocks would
  probably pass there too; nothing was run below slot 32 except as a parent.
- **The testkit's first chained root is arbitrary** (`sha256("testkit-chain",
  parent id)`), not the parent's last FEC set root. Alpenglow slots do not
  check it (`check_chained_block_id` returns `Inactive`), and the run confirms
  that.
- **One validator.** No certificates in footers (`block_final_cert`, reward
  certs all `None`), so `ValidatedBlockFinalizationCert` and the reward paths
  are unexercised.
- **Do not reset a slot that has a retained child.** `reset_slot` drops one
  bank; a child keeps its `Arc` to the dropped parent and its accounts would be
  gone from under it. The smoke never does this.
- **`executed` is `None` when replay stops part way**: the component view
  lists every transaction in the loaded components, the status drain only
  those that ran. `view` and `statuses` are still available separately.
- **Filter reasons** are the non-zero counters of `ShredFetchStats` after one
  shred, read from its `Debug` output because most fields are private. A
  renamed field changes the string, not the verdict.
- `cargo clippy` was not run on this crate. Only the three new files were
  formatted (`rustfmt --edition 2024`).

## The full harness (after the spike)

`src/harness.rs` holds a case and the properties; `src/corpus.rs` the named
cases, Agave's own component-sequence table, and the mutator families.

```
diff-fuzz --corpus [DUMP_DIR]      every named case, both worlds, a table
diff-fuzz --random N --seed S      N generated cases per world
diff-fuzz --emit DIR               frozen vectors for tests/oracle_corpus.rs
options: --handover on|off|both  --filter SUBSTRING  --verbose  --dump DIR
         --recovery (with --corpus or --random; see "Erasure recovery")
DIFF_FUZZ_LOG=warn diff-fuzz ...   Agave's own log lines (most refusals are
                                   only explained there)
```

A world is one oracle with fast leader handover on or off. A case is a
`Recipe` (content items plus a shred layout); `World::run` settles its bank
hash, judges it forward, reversed and shuffled, and then offers the verifier
every claim that can be built from the shreds the blockstore kept: every shred
as a component start, every position `block::reachable` finds, each with the
fewest shreds opened and with every shred opened, plus every footer-shaped
component as the footer. Certificates are signed only over a block id Agave
voted for.

Exit status is non-zero on any P0, P1, P2, premise or opening violation, and
when a family in `corpus::FAMILIES` breaks its floor (should vote and never
did) or its ceiling (should never vote and did).

Things the harness had to learn about Agave:

- **The blockstore has memory a purge does not clear.**
  `update_parent_shred_parent_cache` (`ledger/src/blockstore.rs`) maps
  `(slot, UpdateParent FEC set)` to the marker shred's parent slot and is
  never invalidated. Judging a second block at the same slot whose shreds
  point at another parent gets its shreds refused ("parent != expected shred
  parent after UpdateParent") and the slot marked dead. The harness therefore
  uses one test slot per shred parent (`harness::window_slot`: 36, 40, 44).
  A validator that dumps a slot and repairs another version of it has the
  same stale entry.
- **Claims must be offered with every shred opened as well.** The verifier
  reads as much of a component as the proof supplies. A header split across
  shreds needs shred 1 opened. An opening of the fewest shreds showed it for a
  component starting at shred 32 only because `RawBlock::open` opens one
  contiguous run per FEC set, and shreds 0 and 31 make that run all of set 0;
  for a component further on it opened shred 0 alone and the bug was missed.
- **Check identity over what the blockstore kept**, not over what was sent:
  with `LAST_IN_SLOT` set early, Agave's block is the shorter one.
- **Not every refused shred is refused by the filter.** Flags `0x80` without
  `0x40` pass `should_discard_shred` and fail `Shred::new_from_serialized_shred`.
- **`SlotMeta` moves with arrival order** for blocks no order votes for
  (conflicting UpdateParents, early `LAST_IN_SLOT`). That is reported per
  run and is not counted as P0. P0 is counted when some order votes.

## Erasure recovery (`--recovery`)

Everything above hands Agave every data shred. A validator often receives
part of them and rebuilds the rest from coding shreds, so `--recovery` asks
two things by running: is a shred the blockstore rebuilds checked like the
same shred received, and does a block that arrives partly as parity get the
verdict, block id and executed transactions it gets whole?

**Coding shreds and the block id.** The testkit's tree for a FEC set has 64
leaves: the 32 data shreds and 32 filler hashes
(`sha256("testkit-coding", slot, set, i)`) where the coding shreds go. No
coding shred hashes to a filler, so real ones cannot belong to those trees,
and the roots the oracle signs are roots no coding shred verifies under.
`oracle::erasure_code` therefore re-seals the block:

- Reed-Solomon 32:32 parity (`reed-solomon-erasure` 6.0.0, the codec Agave
  uses) over bytes 64 to the end of the data buffer of each data shred:
  headers and padding included, chained root and proof not;
- 32 coding shreds per set: the set's common header, `num_data` and
  `num_coding` 32, index `fec_set_index + position`, the parity shard, the
  same chained root; for a resigned set the resigned variant with a zero
  retransmitter signature, as the data shreds have;
- one tree over the 64 real leaves, its proof written into all 64 shreds,
  and its root chained into the next set.

Every FEC root moves, so the block id is not the one the other modes see for
the same recipe. The bytes replay reads do not move, and neither does the
bank hash. The verifier needs no change: a proof carries the coding half of
a set as one node, read from the shreds' own Merkle proofs. Agave's code for
this (`finish_erasure_batch`, `ReedSolomonCache::get`) is private, so the
layout is written out, and each run starts by holding it to
`Shredder::make_shreds_from_data_slice`: 128 data shreds (32 resigned) and
128 coding shreds come out byte for byte Agave's. No hook in the testkit
was needed.

**What a case does.** `World::run_with_recovery` runs the case as before on
the re-sealed block, which is the baseline: the whole block, forward,
reversed and shuffled. Then, for each loss in `harness::losses`, it withholds
shreds and judges what is left forward in one insert call, reversed 32
shreds per call (a set's parity before its data, so a shred is rebuilt
before it arrives) and shuffled one shred per call:

| loss | data shreds withheld | coding shreds withheld |
| --- | --- | --- |
| `parity-added` | none | none |
| `set-edges` | first and last of every set (shred 0, last of the block) | none |
| `all-data` | all | none |
| `random` | per set, none to all | as many as leave 32 shreds, often exactly |
| `refused-only` | the ones the filter or parser refuses on receipt | none |
| `one-short` (control) | 1 to 32 of one set | all but one fewer than needed |

Each recovery run is then retold without recovery (`harness::as_received`):
the same data shreds, in the order they reached the blockstore, received or
rebuilt, in the same insert calls, with no coding shred. The run fails
(`recovery`) unless the two give the same `SlotMeta`, deadness, block id,
vote, bank hash, executed list and stored shreds byte for byte. That is the
test of "rebuilt is treated as received", and it does not depend on arrival
order. The verdict is also held to the whole block's in some arrival order
(the three, or the retold one if every shred came back), every withheld
shred is accounted for (`reconstruct` if one is missing for no known reason),
and P0, P1 and P2 run on every verdict with a block id that is not already
the whole block's.

**Results** (Agave v4.4.1, both worlds):

- `--corpus --recovery`: 274 case runs, clean, 94 s. Per world, 1,686
  recovery judgments, each retold once; of 90,372 data shreds withheld,
  89,358 were back in the blockstore byte for byte and the other 1,014 are
  accounted for below.
- `--random 2000 --seed 1 --recovery`: 4,000 case runs, clean, 17 minutes a
  world and 3.0 GB each. Per world, 24,450 recovery judgments over 2,000
  blocks (1,174 voted with handover on, 759 with it off); with handover on,
  1,587,042 data shreds withheld, 1,575,687 back byte for byte and the
  other 11,355 accounted for below.
- `recovery` 0 and `reconstruct` 0 in every run: no verdict reached through
  reconstruction differed from the same shreds received, and none differed
  from the whole block's except as explained below. P0, P1, P2 unchanged.
- The control never rebuilt a shred: 2,000 sets one short, 33,213 shreds.

**What the runs showed.**

1. **A rebuilt shred gets the checks a received one gets.** The filter runs
   again after reconstruction (`ShredRecoveryContext::recover` calls the same
   `should_discard_shred`), `merkle::recover` sanitizes what it rebuilds, and
   `check_insert_data_shred` reads the shred's source only for logs and
   counters. Run: in 150 random cases a world (14 in the corpus) the shreds
   refused on receipt were withheld, so they existed only as rebuilt shreds.
   In none of the three arrival orders did one reach the blockstore, and
   the verdict was the whole block's every time: 116 misplaced
   `DATA_COMPLETE` or `LAST_IN_SLOT` (`unexpected_data_complete_shred`), 7
   bad sizes (`invalid_data_size`), 27 flag bytes the parser refuses. The `recovery/refused-shred-rebuilt/*`
   corpus cases put a misplaced flag on shred 0, on the first shred of a
   set, next to the last shred of the block, and in every set at once.
2. **A set with one unparseable data shred cannot be rebuilt at all**
   (`agave-unrecoverable-set`, noted and not counted: 45 runs a world in
   the corpus, 288 in the random run). `merkle::recover` stops at the first
   rebuilt shred that fails `sanitize`, so nothing of the set comes back;
   Agave logs `Unable to perform shred recovery for slot 40 fec set 32:
   InvalidShredFlags(128)`, and tries again on every insert that touches the
   set. A validator that was sent the set's other 31 data shreds holds them;
   one that needed parity for them holds none, and if shred 0 is among them
   its `SlotMeta` has no parent block id. The slot fills for neither, so
   nobody votes and the verdict is the same. A parseable shred the filter
   refuses does not do this: the set is rebuilt and that one shred dropped.
3. **Recovery adds arrival orders, not verdicts.** Where the whole block's
   verdict already moves with arrival order, the recovered one lands on
   another of them (281 judgments a world), or on the order recovery itself
   produced (3: a shred with another parent offset, rebuilt before shred 0
   arrived, set `SlotMeta`'s parent). The one known order-dependent shape
   shows up unchanged, and no block that votes in any order moved under
   recovery.
4. **A refused shred counts as lost.** When the blockstore refuses a shred
   that arrived (an early `LAST_IN_SLOT` that came after later shreds, a
   header after a conflicting marker), its set can be left with 31 shreds
   and nothing rebuilds the rest (813 shreds a world, `short*`). Those slots
   were dead or never full whole as well.
5. **How far a failing replay gets is not deterministic.** Entry hashes are
   verified beside execution, so the same shreds gave `executed` of 12
   transactions in one run and an inconsistent list in the next, with the
   same error. Comparisons of blocks that do not vote leave it out.

**Not covered.** Coding shreds that are themselves wrong (parity from other
data, a conflicting erasure config, a shred from another tree); the
reconstruction can only be checked against the signed root, and that path
was read, not run. Repair, retransmission of rebuilt shreds, and the
re-signing of resigned shreds on receipt. The frozen vectors carry no coding
shreds, so `cargo test --test oracle_corpus` is unchanged and the
`recovery/*` corpus cases are not frozen.

## Output of `diff-fuzz --smoke` (abridged)

```
oracle: genesis Dd4m2UuFpZL9u6A7fNDCJLGaY4or3f6Byc7WUPsraAra shred version 50093 leader AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9 fast leader handover true (80 ms)
shred-level Alpenglow rules: slot 31 false, slot 32 true, slot 36 true
CHECK ok   test slots are past the one-epoch delay of shred rules

== parent block, slot 32 on genesis ==
  shreds: 128 given, 0 discarded by filter, 0 bad signature, 0 unparsed
  insert: ok duplicates []
  meta: parent_slot=Some(0) parent_block_id=11111111111111111111111111111111 replay_fec_set_index=0 has_update_parent=false full=true consumed=128 last_index=Some(127)
  dead: after insert false, now false
  block id: 38acfiKASoprV5DUUdtHvvTPFb9dfH3RVKUL4dai4NcF
  replay: Ok (from shred 0)
  bank hash: 5vU2LCuZaaZR34jyhrb1fUmchPmftR8PEuX7hsk3zF69
  transactions: 1 in replay's view, 1 statuses, joined 1
  voted: true
  time: ingest 1.0 ms, replay 0.6 ms
CHECK ok   parent block voted
CHECK ok   parent bank carries the blockstore's block id

== honest block, slot 36 on 32 ==
pass 1 (placeholder bank hash):
  shreds: 160 given, 0 discarded by filter, 0 bad signature, 0 unparsed
  insert: ok duplicates []
  meta: parent_slot=Some(32) parent_block_id=38acfiKASoprV5DUUdtHvvTPFb9dfH3RVKUL4dai4NcF replay_fec_set_index=0 has_update_parent=false full=true consumed=160 last_index=Some(159)
  dead: after insert false, now true
  block id: EpoyMBbBJGxPkAd1PrE49MWKxjwwu3XmBZmQnU3jFU7c
  replay: Failed { error: "bank hash mismatch at slot 36: expected 11111111111111111111111111111111, got LvZA29u57zx3ZrRiuuZffU988YDWqX2sSiT1QgxZrpG", bank_hash_mismatch: Some((11111111111111111111111111111111, LvZA29u57zx3ZrRiuuZffU988YDWqX2sSiT1QgxZrpG)) } (from shred 0)
  transactions: 9 in replay's view, 9 statuses, joined 9
  voted: false
  time: ingest 1.2 ms, replay 0.8 ms
CHECK ok   pass 1 stops at a bank hash mismatch
CHECK ok   pass 1 leaves the slot dead
pass 2 (bank hash LvZA29u57zx3ZrRiuuZffU988YDWqX2sSiT1QgxZrpG):
  shreds: 160 given, 0 discarded by filter, 0 bad signature, 0 unparsed
  insert: ok duplicates []
  meta: parent_slot=Some(32) parent_block_id=38acfiKASoprV5DUUdtHvvTPFb9dfH3RVKUL4dai4NcF replay_fec_set_index=0 has_update_parent=false full=true consumed=160 last_index=Some(159)
  dead: after insert false, now false
  block id: 59jgrkMi1pobdLJEdTF5FYGs5wVUVWg2HCYweq5J2ufV
  replay: Ok (from shred 0)
  bank hash: LvZA29u57zx3ZrRiuuZffU988YDWqX2sSiT1QgxZrpG
  transactions: 9 in replay's view, 9 statuses, joined 9
  voted: true
  time: ingest 1.3 ms, replay 0.8 ms
CHECK ok   every shred passes filter, sigverify and parse
CHECK ok   insert raised no error and no duplicate
CHECK ok   voted
CHECK ok   bank hash is the footer's
block id: agave 3daba926fd6f51c225f157346404a36ad05fe65d686d5f6ff4ff7389de09cb40 light client 3daba926fd6f51c225f157346404a36ad05fe65d686d5f6ff4ff7389de09cb40
CHECK ok   block id: light client equals Agave's double merkle root
parent: agave Some((32, "1fa872b499ef537eb958b56dd6885c751ff46d43f7314f78ee0b8c1dcca38518")) light client (32, "1fa872b499ef537eb958b56dd6885c751ff46d43f7314f78ee0b8c1dcca38518") built (32, "1fa872b499ef537eb958b56dd6885c751ff46d43f7314f78ee0b8c1dcca38518")
CHECK ok   parent: light client equals Agave's slot meta
CHECK ok   parent: is the parent bank's block
executed (component start, entry, tx, signature, commit) vs built:
  built ( 32,0,0) d6b1f9edee62   agave ( 32,0,0) d6b1f9edee62 Ok(Ok(()))
  built ( 32,0,1) 900bd0c4f26f   agave ( 32,0,1) 900bd0c4f26f Ok(Ok(()))
  built ( 32,1,0) fd8e2eb0a171   agave ( 32,1,0) fd8e2eb0a171 Ok(Ok(()))
  built ( 32,2,0) f12747be28e4   agave ( 32,2,0) f12747be28e4 Ok(Ok(()))
  built ( 32,2,1) 27aebb1f66c1   agave ( 32,2,1) 27aebb1f66c1 Ok(Ok(()))
  built ( 64,0,0) 5daaaf839e0a   agave ( 64,0,0) 5daaaf839e0a Ok(Ok(()))
  built ( 64,1,0) 8f6d905c0307   agave ( 64,1,0) 8f6d905c0307 Ok(Ok(()))
  built ( 64,1,1) 1c8a94b05906   agave ( 64,1,1) 1c8a94b05906 Ok(Ok(()))
  built ( 64,1,2) aa913785685d   agave ( 64,1,2) aa913785685d Ok(Ok(()))
CHECK ok   executed: status drain and replay's component view agree
CHECK ok   executed: equals what was built, coordinates included
CHECK ok   executed: every transaction committed successfully
CHECK ok   executed: every recipient holds its transfer in the frozen bank
CHECK ok   light client signatures equal Agave's executed list, in order

== questions ==
ANSWER (ii) data-only FEC sets (no coding shreds inserted): full=true block id present
ANSWER order, honest block: reversed and shuffled, in one insert call and one shred per call: same verdict as forward in all 5
ANSWER (i) re-split of the first entry batch (1227 bytes, first shred cut to 100; 128 payloads differ): voted=true bank hash unchanged block id changed
       light client on the re-split block: block id equals Agave's, signatures equal Agave's

== teeth ==
unsigned shreds: 160 bad signature, meta none, voted=false
CHECK ok   teeth: unsigned shreds all fail sigverify and nothing is stored
wrong shred version: 160 discarded, reason Some("shred_version_mismatch"), voted=false
CHECK ok   teeth: a wrong shred version is discarded by the filter
tampered transaction signature: Failed { error: "invalid block error: invalid entry hash", bank_hash_mismatch: None } dead=true
CHECK ok   teeth: a tampered transaction signature fails replay and kills the slot
header with a wrong parent id: Deferred("slot meta parent block id US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx is not the parent bank's Some(38acfiKASoprV5DUUdtHvvTPFb9dfH3RVKUL4dai4NcF)")
CHECK ok   teeth: a header naming another parent block is deferred
footer time bounds for 36 on 32: 1792590852600000001..=1792590854200000000 (1600 ms wide)
footer past the clock bound: Failed { error: "block component processor error: Nanosecond clock out of bounds", bank_hash_mismatch: None }
CHECK ok   teeth: a footer time past the upper bound fails replay
footer exactly on the clock bound: Failed { error: "bank hash mismatch at slot 36: expected LvZA29u57zx3ZrRiuuZffU988YDWqX2sSiT1QgxZrpG, got G3E7eV2xJwRa6iaWMpAH72mhDLUYDFLeFrNc4HCWUGWY", bank_hash_mismatch: Some((LvZA29u57zx3ZrRiuuZffU988YDWqX2sSiT1QgxZrpG, G3E7eV2xJwRa6iaWMpAH72mhDLUYDFLeFrNc4HCWUGWY)) }
CHECK ok   teeth: a footer time on the upper bound gets as far as the bank hash
footer at the parent's time: Failed { error: "block component processor error: Nanosecond clock out of bounds", bank_hash_mismatch: None }
CHECK ok   teeth: a footer time not after the parent's fails replay
forged transaction signature, entry hash consistent: Failed { error: "invalid transaction error: Transaction did not pass signature verification", bank_hash_mismatch: None }
CHECK ok   teeth: a forged transaction signature fails replay and kills the slot
transaction with an unknown blockhash: Failed { error: "invalid transaction error: Blockhash not found", bank_hash_mismatch: None }
CHECK ok   teeth: an uncommittable transaction fails replay and kills the slot
ANSWER a block holding a transfer that fails: voted=true commit statuses [Ok(Ok(())), Ok(Err("InstructionError(0, Custom(1))"))] recipient balance Some(0)
CHECK ok   a failing transaction is committed as failed and the block still votes

== timing ==
ANSWER (iii) per case over 5 repeats of the honest block (160 shreds, 5 FEC sets, 9 transactions): 2.1 ms total, of which ingest 1.1 ms and replay 0.9 ms
ANSWER (iii) a block of 500 transactions in 224 shreds: voted=true, two passes with building and shredding 41.3 ms, second pass ingest 1.7 ms and replay 9.4 ms
CHECK ok   the honest block still gets the same verdict after all of the above

smoke: all checks passed (0.2 s)
```
