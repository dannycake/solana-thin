# Working notes (2026-11-23)

`README.md` says what the crate does and `docs/DESIGN.md` says why each check
exists. This file holds everything else: what was measured, where each fact
came from, what was tried and dropped, and what to do next.

## State of the repo

- Branch `main`, pushed.
- Five crates: the verifier, the set log and its tool, the prover, the
  Kotlin and Swift binding, and the WebAssembly module, with the binding
  generator. `cargo test --workspace --all-features` runs about 300 tests.
- CI on GitHub runs, on every push: fmt, clippy, the tests with and without
  all features, the verifier, the set log and the prover on Rust 1.85, docs,
  the example, `cargo deny`, the published crate's tests away from the
  repository, the Kotlin binding on the JVM, and the verifier as WebAssembly
  under node and WASI.
- On this machine, nightly: the differential oracle that runs Agave's own
  blockstore and replay (with erasure recovery), eight fuzz targets, the
  third-party shred fixtures and the tripwire. As of 2026-11-25 the mainnet
  feature gates `alpenglow_fast_leader_handover`,
  `stricter_shred_validation`, `relax_fee_payer_constraint` and
  `enforce_correct_proof_size` have no account, and public RPC runs 4.4.0
  (`scripts/tripwire.py`).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` is
  clean. `cargo doc` is clean.
- `rust-version` is 1.85, and the tests pass on 1.85.0. It was declared as
  1.75 and never built there: with the committed `Cargo.lock`, `blst` pulls in
  `zeroize_derive` 1.5, which is an edition 2024 crate.
- Unaudited. One independent read against Agave v4.4.1's source was done on
  2026-11-23 and found a soundness bug; see "Review" below. That is
  a reason to expect more, not fewer.

## What is verified, and how strongly

| Claim | Evidence | Strength |
|---|---|---|
| Block id computation is right | Equal to ids read back from an Agave v4.4.1 `Blockstore` for 3 blocks | Strong |
| Vote payload bytes are right | Equal to `agave_votor_messages::wire::get_vote_payload_to_sign` | Strong |
| BLS scheme and thresholds are right | Same verdict as `agave_bls_cert_verify::verify_certificate` on 13 certificates (5 accepted, 8 rejected) | Strong for the cases covered |
| Validator ranking and filters are right | Equal to `BLSPubkeyToRankMap::new` on 14 random vote accounts, including zero stake and a duplicated key | Strong for ranking. Admission happens before the rank map and is handled by the fetch tool, not the crate |
| Proof of possession format is right | Verifies PoPs made with `solana-bls-signatures` over the vote program's message | Strong |
| Transaction walking is right | 254 Agave-serialized transactions (248 legacy, 2 v0, 4 v1, 2 multi-signer) parse to the same message bytes and positions | Good; v0 and v1 samples are few |
| Footer and header parsing is right | Parses footers Agave serialized, including fast and slow embedded certificates | Good |
| Live mainnet keys load | The BLS keys of the 664 validators admitted in epoch 1095 decode and pass subgroup checks | Strong, but says nothing about certificates |
| Works against a running validator | 447 block ids, 446 footer certificates and 312 transactions from `solana-test-validator` v4.4.1; see `docs/LOCAL-VALIDATOR.md` | Strong for formats and the pipeline. One signer |
| Works against several running validators | 709 block ids and 705 certificates (330 fast, 375 slow) from a four-validator `LocalCluster`, over 14 epochs | Strong for aggregation, both thresholds, skipped slots. Four signers, not hundreds |
| The epoch-stake offset is right | On that cluster every certificate verifies with the set fetched one epoch earlier; 19 fail with the same-epoch set and 19 with the set from two epochs earlier | Strong |
| Stake from `getVoteAccounts` is the snapshot stake | **False.** The set fetched in epoch 1095 failed 4 of 4 certificates of epoch 1096; with the stake the cluster froze, 4 of 4 verify and 1,245 of 1,245 transactions prove. 8 of 664 ranks differed. On testnet 50 of 481 ranks differ, on devnet none | Strong |
| Membership of the mainnet set is right | 664 `VATDebit` entries in the first block of epoch 1095 match 664 staked accounts with keys; 20 staked accounts with keys had none. The epoch-stakes map in a bank snapshot has the same 664 | Strong |
| Block ids are right on mainnet | For 3 of 3 mainnet blocks, the id computed from shreds equals the id in the certificate the next leader put in its footer | Strong. Needs no validator set |
| A live mainnet certificate verifies | 455 of 455 certificates of epoch 1096 (451 fast, 4 slow) against the exact set of 664; rejected with another epoch's set (20 of 20), without the admission filter, and with another shred version | Strong |
| Mainnet transactions prove and verify | 175,981 of 175,981 in 413 blocks of epoch 1096: legacy, v0 with lookup tables, v1; 72 blocks from Firedancer leaders. 331 of an earlier block's are a test | Strong. No block switched parent |
| The exact set can be obtained | Three sources agree to the lamport: epoch stakes in bank snapshots from three unrelated nodes; `getVoteAccounts` less `Staking` rewards (662 of 662 on mainnet against the snapshot, 481 of 481 and 21 of 21 against the rank map on testnet and devnet); `getVatActiveSetRankMap` on 4.5. The crate's rank order equals Agave's rank map for mainnet epochs 1095 to 1097 | Strong that they agree, and the set for epoch 1097, fixed during 1096, verified that epoch's certificates. None is a proof |
| A certificate vouches for a set | **False.** It fixes the order of keys only. Devnet's previous-epoch set verified 64 of 64 certificates of the next; a set with one stake multiplied by 200 verifies mainnet's | Strong |
| Works on Agave 4.5 | 288 blocks, 288 certificates and 7,419 transactions from testnet and devnet (4.5.0-beta.0), 1,754 of them v1; 38 testnet blocks from leaders not running Agave | Good. The parser is also fuzzed against 4.5's (`transaction_view_45`, `transaction_wincode_45`) |
| A rebuilt shred is a received shred | The oracle with real coding shreds and withheld data: corpus and 2,000 random cases, same verdict, metadata and stored bytes | Strong for one Agave build |
| Runs off x86-64 | Test suite on arm64 (macOS native, Linux emulated) and WASI; a mainnet proof in `wasm32-unknown-unknown`; through Swift, 331 of 331 mainnet proofs on an iPhone 17 Pro (0.82 ms each) | Good. No Android phone |

The Agave vectors use random keys, so regenerating them changes the bytes.
The tests depend on structure, not on specific values.

## Facts measured from mainnet

All from `https://api.mainnet-beta.solana.com` on 2026-11-23.

- `getVersion`: `solana-core 4.4.0`, feature set 2681577653.
- `getEpochInfo`: epoch 1095, 432,000 slots per epoch, slot about 473,062,000.
- Shred version **50093** (from `getClusterNodes`).
- Genesis hash `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`.
- `getAgGenesisCert` works. Alpenglow's genesis block is slot **459,652,999**,
  block id starting `38df705e…`. Its certificate has a 192-byte (uncompressed)
  signature and an 87-byte bitmap covering 672 ranks.
- `getBlockTime(459652999)` = 1792590840, which is 2026-10-21. That confirms
  the activation date.
- Slot rate since activation: about 13.4 million slots in 33.2 days, roughly
  **214 ms per slot**. At 432,000 slots that makes an epoch about **26 hours**.
  This was computed from two block times, not read from a spec.
- 686 vote accounts, 684 with stake and a BLS key, **664 admitted**. Total
  admitted stake 425.8M SOL. The top 58 validators hold 60% of stake and the
  top 137 hold 80%.
- The first block of epoch 1095 (slot 473,040,000) has 664 `VATDebit` rewards
  of 0.8 SOL each. 0.8 SOL is the ticket for 200 ms slots
  (`runtime/src/slot_params.rs`), which fits the measured slot rate. The 20
  staked accounts left out hold 0.02% of stake; the largest has 37,544 SOL
  delegated.
- Validator set size 37,188 bytes; signer bitmap 86 bytes.
- Set hash for the snapshot in `tests/vectors/mainnet-vote-accounts.json`:
  `7cc14b596ad61f6aff8b5e638831c3c40c1fd3b7a15d831f23e23a6c2515b1ee`. Its
  members and keys are those of epoch **1096**'s set. Its stake is not, and
  so its order and this hash are not: see the next item. It replaces
  `90e2d142…`, which was built from all 684 staked accounts and was wrong.
- **That snapshot failed every certificate of epoch 1096.** Four consecutive
  slots (473,475,740 to 473,475,743) were fetched over repair early in the
  epoch. Block ids matched the footers; all four certificates were
  refused on the signature. The signer bitmaps were 664 bits, so the size was
  right. Four slots from the last minutes of epoch 1095 verified against the
  epoch 1095 set with the same binary, so nothing had changed in the formats.
  No single account added or removed made them verify. The cause: Agave takes
  the snapshot before it pays the previous epoch's staking rewards
  (`process_new_epoch` in `runtime/src/bank.rs`), and `getVoteAccounts`
  reports stake after. Two validators whose delegators had left were
  reported at 77.4 and 46.2 SOL; the rewards on the departed stake were 75.3
  and 42.8 SOL of that. Subtracting each validator's rewards (Trillium's
  per-epoch figures) moved ranks 649 to 656 and nothing else, and then 4 of
  4 certificates verified. For those two validators the public RPC gives
  reward totals that agree with Trillium's to its precision
  (`getProgramAccounts` on the stake program by voter, then
  `getInflationReward` per stake account), so an exact correction may be
  possible; it was not built or tested for the whole set, and stake accounts
  that have moved or closed since would be missed.
- **The exact stake, found the next day.** Trillium's figure includes
  rewards on stake that was already inactive, which never entered the
  stake, so subtracting it gave the right order and stake that was off by
  up to 38.9 SOL for one validator and 110 SOL in all. Three sources give
  the frozen stake itself and agree to the lamport; see "Three clusters"
  below. The tests now use it and pin the set hashes of epochs 1095 and
  1096.
- Fetching twice in the same epoch, 18,000 slots apart, gave identical
  accounts. The hash is stable within an epoch.

### Mainnet blocks over the repair protocol

A throwaway client (not in the repo) spoke Agave's repair protocol to 24
validators picked at random from `getClusterNodes`, with a fresh Ed25519 key
and no stake.

- All 24 sent a ping, accepted the pong, and served shreds. Nobody refused an
  unstaked stranger.
- Slots 473,100,910 to 473,100,913: 512, 512, 576 and 704 data shreds, each
  slot complete in about half a second, no retries, 2,424 requests in all.
- Wire format, hand-serialized: `u32` variant (8 `WindowIndex`, 9
  `HighestWindowIndex`, 7 `Pong`), then signature, sender, recipient,
  millisecond timestamp, `u32` nonce, slot, shred index. The signature covers
  everything but itself. A reply is the shred followed by the nonce. The
  first request to a peer earns a 132-byte ping; answer with
  `sha256("SOLANA_PING_PONG" ‖ token)`, signed. `HighestWindowIndex` returns
  the slot's last shred, which gives its length.
- Each block had 331 to 442 transactions in 12 to 15 entry batches, the
  largest 60 to 61 KB. Footers named `agave/4.4.0 … client:JitoLabs`. Every
  footer carried a fast certificate for the slot before. No `UpdateParent`.
- Proof sizes over the 1,048 transactions: minimum 3.2 KB, median 19 to
  21 KB, 90th percentile 43 to 53 KB, maximum 64 KB.
- The set for epoch 1095 was rebuilt after the fact: members from the 666
  `VATDebit` rewards in slot 472,608,000, keys from the vote accounts, stake
  from Trillium's epoch 1094 data. Five pairs of validators tie at Trillium's
  precision; the certificates verified anyway.

A second throwaway served proofs over HTTP from the local validator's shreds:
300 of 300 fetched and verified, 0.13 ms to build one, 0.8 ms to verify one,
5 MB of memory for 43 blocks.

### The genesis certificate, tried and not verified

`getAgGenesisCert` returns a real certificate: 446 signers over slot
459,652,999. Its payload is tag `0x06` with the same layout as a notarize
vote. Checking it needs the ranked set of epoch 1064, which is stake as it
stood in epoch 1063, exact to the lamport, because one wrong rank changes the
aggregate key. Public RPC only reports current stake. Trillium's per-epoch
API (`api.trillium.so/validator_rewards/1063`) has every validator's BLS key
but rounds stake to 10^-5 SOL, has ties at that precision, and one record
with unreadable keys. A set rebuilt from it puts 82.15% of stake behind the
bitmap, which is the right neighborhood for a genesis certificate, but the
signature does not verify, with or without a gap for the unreadable record.
The rebuilt set also ignored admission, which was not understood at the time
of the attempt. So this is not evidence either way about the crate.

The lesson: fetch and keep `getVoteAccounts` every epoch from now on.
A certificate can only be checked against a set that was saved in time.

RPC methods that do **not** help:

- `getBlock` on 4.4.0 returns no block id, footer or certificate.
- `getVatActiveSetRankMap` exists on Agave's development branch and returns
  "Method not found" on mainnet's 4.4.0. When it ships it should replace
  `tools/fetch_vote_accounts.py`.
- No RPC method on either branch returns a finality certificate other than the
  genesis one.

Geyser does: the Solana Foundation's Alpenglow page says footer certificates
reach plugins through a `notify_block_footer` callback, and that Yellowstone
gRPC does not forward them yet. That gives a node operator certificates but
not shreds. Not tried here.

## Where each format was read from

Agave was read at two commits: `master` at `1a5aa5fb` (5.0.0-alpha.1) and tag
`v4.4.1` (`5bb30402`). The files below differ between the two only by
refactoring (a `BlockId` newtype, `NonZeroStake`, a new
`agave-shred-wire-format` crate). The wire formats are identical.

- Certificates and vote payloads: `votor-messages/src/{certificate,vote,wire}.rs`
- Certificate verification: `bls-cert-verify/src/cert_verify.rs`
- Footer certificate handling: `runtime/src/validated_block_finalization.rs`
- Rank map: `runtime/src/epoch_stakes.rs` (`BLSPubkeyToRankMap::new`)
- Block components, header, footer: `entry/src/block_component.rs`
- Block validity state machine, UpdateParent, clock bounds:
  `runtime/src/block_component_processor.rs`
- Shred layout: `ledger/src/shred/merkle.rs`; on master also
  `shred/wire-format/src/constants.rs`
- Merkle tree: `ledger/src/shred/merkle_tree.rs`
- Double Merkle block id: `ledger/src/blockstore.rs`
  (`build_double_merkle_tree`)
- Component boundaries: `ledger/src/blockstore.rs`
  (`get_completed_data_ranges`, "one range in CompletedRanges corresponds to
  one BlockComponent") and `ledger/src/shredder.rs` (`deshred`)
- Parent marker rules: `ledger/src/blockstore.rs` (`ParentInfo`,
  `should_write_parent_info`, `UpdateParentMatchesBlockHeader`)
- FEC set rules: `ledger/src/shred/filter.rs` (32:32 sets, `DATA_COMPLETE`
  only on the last data shred of a set). An earlier note here cited a
  `check_fec_set` in `merkle.rs`; v4.4.1 has no such function.
- Admission: `runtime/src/bank.rs` (`get_top_epoch_stakes`,
  `minimum_vote_account_balance_for_vat`, `maybe_burn_vat_from_staked_accounts`),
  `vote/src/vote_account.rs` (`clone_and_filter_for_vat`),
  `runtime/src/slot_params.rs` for the ticket price
- Where the blockstore reads the header: `ledger/src/blockstore.rs`
  (`ParentInfo::maybe_parse_block_header`, shred 0 only)
- Transaction parsing in replay: `entry/src/block_component_parser.rs`, which
  uses `agave-transaction-view`, not `solana-transaction`
- Bitmap encoding: crate `solana-signer-store` 0.1.0
- BLS: crate `solana-bls-signatures` 4.0.0 (`src/hash.rs` for the domain tags)
- PoP message: `programs/vote/src/vote_state/mod.rs` (`generate_pop_message`)
- Vote state layout: crate `solana-vote-interface` 7.0.0
  (`state/vote_state_v4.rs`). The BLS key is an `Option<[u8; 48]>` at byte 144
  of the account data, after a `u32` version tag of 3.
- Transaction formats: crates `solana-message` 5.0.0 and `solana-transaction`
  5.0.0 (`versioned/mod.rs` for how v1 is told apart)

## Details worth remembering

These are easy to get wrong and are not all spelled out in `DESIGN.md`.

- **Which stake a certificate is checked against.**
  `bank.epoch_stakes_from_slot(slot)` uses the epoch of the certificate's slot.
  Epoch stakes for epoch `E + 1` are stored at the first slot of epoch `E`. So
  `getVoteAccounts` during epoch `E` gives the stake for `E + 1`. Observed on
  a four-validator cluster; see `docs/LOCAL-VALIDATOR.md`.
- **A fast certificate reuses the notarize payload.** Tag `0x01`, same bytes as
  a plain notarization. There is no separate "fast finalize" vote.
- **Finalization certificates must use the base-2 bitmap.** Agave rejects the
  base-3 form for them (`Base3Finalization`). Base 3 is only for skip and
  notarize-fallback certificates, which this crate does not handle.
- **Bits past the declared count in a bitmap are ignored**, by Agave and here.
- **Every component is padded to a whole FEC set.** A partly filled shred must
  be followed by empty shreds, and the last shred of the set must carry
  `DATA_COMPLETE`. A full FEC set may continue into the next one.
- **`DATA_COMPLETE` is only kept on the last data shred of a FEC set.** Agave
  discards any other shred that carries it (`filter.rs`), and so does the
  verifier (`DataShred::sanitize`).
- **Only two shred variants are accepted:** `0x96` (data) and `0xb6` (data with
  a retransmitter signature). Body capacity is 963 and 899 bytes.
- **The Merkle leaf covers bytes 64 up to the proof**, which includes the
  chained Merkle root. All shreds of a FEC set share that root.
- **UpdateParent is only legal in the first slot of a leader window** (four
  slots per window). The verifier does not rely on this; it compares the
  header's parent with the tree's parent instead.
- **Block time is bounded.** The footer's clock must be after the parent's and
  within a bound derived from elapsed slots
  (`nanosecond_time_bounds`). It is a checked value, not a free claim.
- **v1 transactions put signatures after the message**, one per required
  signer, and start with byte `0x81`. Legacy and v0 start with a one-byte
  signature count below `0x80`.

## Decisions made, and alternatives dropped

- **Use `blst` directly, not `solana-bls-signatures`.** Fewer dependencies for
  a client meant for phones. Compatibility is covered by the conformance
  vectors.
- **Refuse blocks with UpdateParent** instead of proving inclusion after the
  marker. It would be sound to support (prove from the marker onward), but it
  needs more rules and nothing was known about how often such blocks occur.
- **Dropped: accepting a new validator set if it overlaps the old one enough**
  ("bounded churn"). An attacker who is the client's only source could shift a
  little stake each epoch and compound it, and unknown keys allow a rogue-key
  forgery.
- **Dropped: built-in signed attestations of the set hash** (m-of-n Ed25519).
  `trust_validator_set` with a pinned hash covers it without a new dependency;
  how the hash is agreed is left to the application.
- **Dropped: proving execution success by indirect tricks** (fee-payer
  balances, durable nonces). Too fragile to claim anything from.
- **The crate uses `std`.** `no_std` was not attempted. `blst` supports it.
- **Transaction signatures are not re-verified.** A block with a badly signed
  transaction is invalid and would not be finalized.

## Review (2026-11-23)

One independent read of the verifier against Agave v4.4.1's source. Each
item was then checked against the source or the network before acting.

1. **Soundness bug, fixed.** An early read found the verifier reading a block
   differently from the rule it must mirror: it took the block header from the
   whole first component, when it must read it from shred 0 alone. The verifier
   now refuses a block whose header is not wholly in shred 0. Fix and test:
   `ThinClient::verify_transaction` step 4,
   `a_header_split_across_shreds_does_not_hide_an_abandoned_prefix`.
2. **Stale-set mode had a counterexample, removed.** Stake that is active but
   outside the ranked set can join in one epoch with no activation, so the 9%
   cap does not bound drift. The mode was removed before the first release.
3. **Admission was not reproduced, fixed in the tool.** See the mainnet facts
   above. `ValidatorSet::from_vote_accounts` still ranks whatever it is
   given; it is the fetch tool that drops accounts without a `VATDebit`.
4. **"Fetch at any time during the epoch" was too strong.** Stake is frozen;
   BLS key and node identity are read live. Documented.
5. **A wrong claim about `DATA_COMPLETE`**, corrected above.
6. **The replay transaction parser is `agave-transaction-view`** and is
   stricter than this crate's. No length differs for anything it accepts.
7. **A `u32` multiplication** in `BlockProof::verify` could overflow if a
   caller raised `Limits::max_fec_sets` past 2^27. Now checked.

## The differential oracle (2026-11-24)

`diff-fuzz` (see `tools/agave-fixtures/README.md`) runs Agave's own
blockstore and replay beside the verifier, and holds the verifier to the rule
that whatever it accepts, Agave executed.

1. **A second soundness hole in the verifier, fixed.** A block whose parent is
   a cluster's first block has a parent id of all zeros, which the verifier
   could not tell from an unset one; v0.1 proved a transaction, and a footer,
   in such a block. The verifier now refuses every block whose parent id is all
   zeros (`Error::ZeroParentId`). The oracle reached this from a recipe, not a
   special case.
2. **The ledger's premises hold.** Each premise the conformance ledger
   (`docs/CONFORMANCE.md`) leans on is exercised by a case built for it and
   judged by Agave's own code: a dropped shred never completes a block, a
   component that fails to parse kills the slot, every batch is executed, and
   so on.
3. **Erasure recovery, run and not only read** (`diff-fuzz --recovery`): the
   oracle gives each block real coding shreds, withholds data shreds and
   lets Agave rebuild them. Over the corpus and 2,000 random cases a rebuilt
   shred was treated exactly as the same shred received: same verdict, same
   `SlotMeta`, same stored bytes, and a shred the filter refuses on receipt
   never reached the blockstore by being rebuilt either. One Agave recovery
   behavior is noted and not counted: a FEC set holding a data shred that
   fails `sanitize` is never rebuilt at all, so the slot never fills. Coding
   shreds with wrong parity or a conflicting erasure config were read, not run.
4. **Not modeled:** the live replay stage (partial replay and its restarts),
   more than one slot of ancestry, and anything that is not this one Agave
   build.

Confirmed to match, with file and line, by the same read: shred header
offsets and capacities, the leaf and node hashing, the double-Merkle tree and
its parent leaf, component boundaries, marker and entry-batch layout, vote
payloads, both thresholds, bitmap decoding, the rank map's filters and order,
and both BLS domain tags. Not covered: `blst` against `blstrs` beyond the
tags, base-3 bitmaps, pre-migration blocks, Agave's master branch.

## Three clusters (2026-11-25)

Run by hand with throwaway tools; the captures are not in the repository.

**Mainnet, 4.4.** An unstaked client asked 54 validators for 480 slots of
epoch 1096, from six minutes to 22 hours old, at 300 requests a second.

- 457 fetched; the other 23 were skipped slots. A block took a median 566
  requests, 642 KB and 3.4 s. 129 of 263,584 shreds needed a second ask.
- 403 of 403 block ids computed from shreds equal the certified id. 455 of
  455 certificates verify. 175,981 of 175,981 transactions prove and verify,
  10 of them through one ancestry step. 44 blocks at the ends of runs had no
  certificate in the capture and were not attempted.
- Proofs: median 21.6 KB, 95th percentile 56.0 KB, largest 65.7 KB. Verifying
  one took a median 1.1 ms of CPU.
- Transactions: 89,925 v1, 48,011 v0 (21,179 with lookups, up to 14 tables),
  38,045 legacy; the largest 4,046 bytes.
- The first two blocks of an epoch carry the certificate for the last block
  of the epoch before, so a client at a boundary needs both sets.
- A slot RPC lists as skipped was served, complete, by 20 validators: a
  block the cluster abandoned. It has no certificate, so the verifier would
  never accept it, but a prover that fetches by slot can pick one up.
  Fetching by block id cannot.
- The block-id repair requests (`ParentAndFecSetCount`, `FecSetRoot`,
  `WindowIndexForBlockId`) were answered by 162 of 164 Agave 4.4 peers and
  37 of 37 Firedancer peers. Walking back 40 blocks from one certified id
  with only those, checking each reply on arrival: nothing rejected, 22,334
  of 22,334 transactions proven.
- How long a slot stays fetchable is a slope, not the 18 hours estimated
  earlier: 95% of peers have it at two hours, about 40% at four to nine,
  17% at 22 hours, 3% at 36. One slot 20 days old came back whole from two
  peers.

**Testnet and devnet, 4.5.0-beta.0.** 144 blocks each, against sets of 481
and 21 validators from `getVatActiveSetRankMap`: 288 of 288 certificates
(282 fast, 6 slow), 3,970 and 3,449 transactions, all proven and verified.
38 of 136 testnet blocks had leaders not running Agave. No block had an
`UpdateParent` marker and the three feature gates the argument depends on
have no account on either cluster. Between 4.4 and 4.5 the block id,
markers, footer, certificates, bitmap, rank map and repair wire are
unchanged; the transaction parser's limits are raised (see `DESIGN.md`) and
fast leader handover got its real feature id.

**The validator set.** See `DESIGN.md`, "Where the exact snapshot can be
read". What was measured:

- Snapshots: 24 of 253 RPC-advertising mainnet nodes serve one, 20 of them
  current. The bank file is complete 68 MB into an incremental archive
  (71 MB into a full one), 2.5 to 13 s. Three nodes, three slots, identical
  maps for epochs 1093 to 1097.
- Rewards: on mainnet 522 block fetches for 1,039,996 staking rewards and
  687 `getProgramAccounts` calls for 1.30 million stake accounts; 346
  accounts had merged since and were traced. `getInflationReward` is too
  slow for this (4.3 s per 32 addresses). The result equals the snapshot's
  map for all 662 validators of epoch 1097.
- Agreement between RPC providers: four keyless endpoints returned the same
  `getVoteAccounts`, and stake and keys did not change within the epoch
  once rewards were paid.
- The turn of epochs 1096 and 1097, watched. The set for 1097 had been
  read from a snapshot seven hours before (`f546d44b…`); the first four
  certificates of 1097 verify against it, and 1,887 of 1,887 transactions
  in the three blocks fetched prove and verify
  (`a_set_fixed_a_day_ahead_verifies_its_epochs_certificates`). Polling
  `getVoteAccounts` across the boundary from two providers caught, about
  half a second after the epoch's first block, an answer equal to the stake
  the cluster froze for epoch 1098 for 688 of 688 vote accounts; every later
  answer had more of the rewards in it, partition by partition. That
  confirms the cause directly. As a source it is a race, not a method.

**The set tool, the same day.** With `snapshot-stakes` and `setlog` as
committed:

- Mainnet: 251 nodes advertised RPC; three on different networks gave
  extracts at slots 473,895,632, 473,895,832 and 473,895,832, each stopping
  68.0, 67.9 and 70.8 MB into the archive after 2.5 to 5.2 s. All three give
  identical sets for epochs 1093 to 1097. For 1095 and 1096 the hashes are
  the ones the tests pin (`0692eac1…`, `87318834…`), and for 1097 the one
  measured by hand earlier in the day (`f546d44b…`). Agave's rank map and
  this crate's ranking were equal for all 15 maps. Two more nodes, read a
  few minutes before at slot 473,895,232, agree with them.
- One mainnet node served a snapshot of slot 459,656,693, 14 million slots
  old, holding epochs 1061 to 1065. The tool now compares a snapshot's slot
  with the cluster's before downloading. Another redirected its archive to a
  second host; that is not followed.
- Testnet: `api.testnet.solana.com` and one other RPC node gave the same
  rank map for epochs 1098 and 1099 (481 validators, `299dcb43…` and
  `b4137a0a…`), and one node's snapshot, parsed by Agave 4.4.1 code though
  the node runs 4.5, gave the same two. Its bank file was complete after
  109.3 MB.
- Devnet: one RPC endpoint (`4.5.0-beta.0`), 21 validators, `9be7a510…` for
  epoch 1218 and `0d91fb17…` for 1219, equal to the sets read by hand
  earlier. None of the nine other 4.5 nodes that advertise RPC answered.
- A log of two records (epochs 1096 and 1097) is 1,506 bytes; the set file
  for 1097 is 74.6 KB.

**Platforms.** Loading a 664-validator set takes 28 to 32 ms natively
(subgroup checks 22 ms, decompression 7 ms) and 168 ms in wasm; verifying a
proof with the set loaded 0.9 to 1.2 ms natively and 7.2 ms in wasm; peak
heap 239 KB. The pairing dominates a verification, not key aggregation.

**An independent review** of the crate found no way to make it accept a
transaction a validator did not execute, and found what the next commits
fix: a set was validated before its hash was compared, limits did not apply
on one path, three ledger rows named tests that did not test them, and the
advice to check a set against a certificate was wrong.

## The prover, live (2026-11-25)

`crates/solana-thin-prover` as committed, run by hand. `docs/PROVER.md` has
the procedure and the tables.

**Mainnet, epoch 1097**, about 40 minutes after it began (slot index
12,167). Twenty slots chosen at random from the epoch so far, `prover fetch
--prove-all` at 300 requests a second, set `f546d44b…` (662 validators),
shred version 50093.

- `getClusterNodes` listed 3,747 nodes: 2,939 could be asked, 608 had no
  repair address, 199 were on a release that does not answer.
- 20 of 20 slots held a block, and all 20 were fetched by certified id. 20
  certificates verified, all fast: 17 found in the next slot's footer and 3
  in the one after; 19 for the block itself and 1 for its child, reached
  through one parent link. No block id differed from its certified id.
- 10,213 of 10,213 transactions proven and verified. Proofs 3,096 to 65,025
  bytes.
- A block's shreds: 439 to 1,328 requests (median 687) and 2.7 to 6.9 s
  (median 4.0), for 416 to 1,280 shreds (median 656). Finding its
  certificate: 81 requests on average. On mainnet the footer is the
  next-to-last component, one FEC set, followed by one more entry batch, so
  reading it takes the last two FEC sets and the shred before them.
- In all: 17,204 requests, 3.2 MB sent, 20.0 MB received, 113 s. 44 of
  15,345 pieces were asked for twice. No answer failed its check and none
  arrived twice. 64 validators answered.
- Nothing was refused.
- Five signatures from those blocks, taken from RPC `getBlock`, through
  `prover prove` with no slot given: `getSignatureStatuses` with history
  named the right slot each time, and each run took 5.2 to 7.5 s from a
  new process and an empty store to a proof on disk (5.4 to 32.3 KB), each
  verified by `examples/verify_proof` in a process of its own.
- An earlier run the same hour, before requests were spread over a growing
  pool of peers, fetched another 20 random slots and proved 9,025 of 9,025
  transactions from 8 validators.

**A local validator**, `solana-test-validator --alpenglow`, Agave 4.4.1,
shred version 58320, its set built from `getVoteAccounts` (one validator, so
the stake caveat above changes nothing) and written as a set file. 24 memo
transfers landed in 24 blocks, slots 37 to 68. `prover serve` answered
`GET /proof/<signature>` for all 24 in 24.8 s, 4,777 requests in all, 1,991
or 1,992 bytes each, and all 24 verified in separate processes that had the
proof, the set file and the epoch length. In a first run earlier the same
day, with the same result for 24 other transactions, a proof with one bit
changed was refused, an unknown signature got `404` and the reason,
`/finality/<slot>` returned 143 bytes and `/set/0` the pinned file.

**Not exercised live:** a slow certificate, an epoch boundary (the run began
after it), a skipped slot among the ones asked for, peers going quiet, a
block more than an hour old, and anything on testnet or devnet. The tests
cover the first four against stand-in validators.

## The admission check (2026-11-26)

Read in Agave 4.4.1 first. `process_new_epoch` filters the vote accounts
for admission and cuts them to 2,000 (`clone_and_filter_for_vat`), stores
the result as the new epoch-stakes map (`update_epoch_stakes`), and charges
every account of that map the ticket (`maybe_burn_vat_from_staked_accounts`).
The rank map is built later from the same map and drops accounts that
share a BLS key or node identity (`BLSPubkeyToRankMap::new`). So the
debited accounts equal a snapshot's map, and a rank map is that less the
shared ones.

- Mainnet: the first block of epoch 1096 (slot 473,472,000) debited 662
  accounts, the same 662 as epoch 1097's map in six extracts; the first
  block of 1097 (473,904,000) debited 659, the same as 1098's map. Against
  the maps of the other epochs in those extracts the debits differ by 2 to
  7 accounts each.
- `setlog agree` with the check gave `f546d44b…` (662) for 1097 and
  `a3685e2e…` (659) for 1098. One extract with its maps for 1097 and 1098
  swapped was refused, naming the four accounts not debited and the one
  debited and missing.
- `setlog from-rank-map` with the check: testnet 1098 and 1099 (481 ranked,
  481 debited) and devnet 1219 (21 and 21).
- No map of mainnet epochs 1093 to 1098 has two accounts sharing a key or
  an identity, and testnet and devnet rank every account they debit. The
  path for shared keys has run only in tests.

## Things I am least sure of

1. **Other places where the verifier reads a block differently from the rule
   it mirrors.** The header-in-shred-0 rule was one such place, and it was not
   found by any test written beforehand. Firedancer was read only for the
   header rule, and never run.
2. **What blocks look like once fast leader handover is active.** Its
   feature has no account on mainnet, testnet or devnet, and none of 805
   captured blocks switched parent. The rules for such blocks are tested
   only on hand-built ones.
3. **Blocks from other clients.** 72 mainnet blocks from Firedancer leaders
   and 38 testnet blocks from leaders not running Agave verified. Firedancer
   itself was never run as an oracle.
4. **What vouches for a set hash.** The exact set can be read three ways
   that agree, and none is a proof. A certificate does not vouch for stake.
5. **The 2^80 leader collision attack** is my own analysis of the 20-byte
   Merkle truncation. Nobody has reviewed it.

## Prior work, as checked on GitHub

- `tinydancer-io/tinydancer`: last commit Dec 6, 2023. Not archived.
- `tinydancer-io/diet-rpc-validator`: a modified validator adding
  `get_block_headers` and `get_shreds` RPC methods; org page shows June 2024.
- `tinydancer-io/solana-spv-plugin`: fork of `Sovereign-Labs/solana-proofs`;
  its README says it verifies the account proof "and not the votes". Tested on
  validator v1.18.7.
- `Sovereign-Labs/solana-proofs`: README calls it a proof of concept, dated
  Nov 2023.
- SIMD-0052 (receipt root in the bank hash): pull request closed unmerged on
  Jan 7, 2025, "due to staleness".
- SIMD-0064 (transaction receipts): document merged Oct 2023, now marked
  Stagnant. Never implemented.
- `solana-labs/solana` issue 7053 (bank hash does not follow the SPV design):
  opened Nov 2019, last comment Feb 2023, still open in an archived repo.
- A search also surfaced an arXiv paper, "Guppy: Efficient Light Clients via
  Recursive Zero-Knowledge Proofs" (2609.07963). **I did not read it.** Worth
  checking before claiming nobody else is working on this.

"Abandoned" is my reading of the dates. None of these repos says so itself.

Guppy, from its abstract and excerpts only: an untrusted off-chain service
keeps a Merkle tree over chain state and proves each new root with recursive
zero-knowledge proofs, for chains whose validators do not commit to state. It
is about state, which this crate cannot prove, and it needs a proving
service. It is complementary, not the same thing. A web search for an
Alpenglow light client or inclusion-proof library found none, which is not
the same as none existing.

## Environment gotchas

- `tools/agave` is gitignored. It can be a symlink to a checkout of Agave
  v4.4.1. On a new machine:
  `git clone --depth 1 --branch v4.4.1 https://github.com/anza-xyz/agave tools/agave`
- `tools/agave-fixtures` pins Rust 1.98.1 through its own
  `rust-toolchain.toml`, because Agave does. It copies Agave's `Cargo.lock` and
  its four `[patch.crates-io]` entries.
- The fixture build needs `libclang` for RocksDB. If the build cannot find it,
  point `LIBCLANG_PATH` at a directory containing `libclang.so`. The first
  build took about 8 minutes on 4 cores.
- The Agave checkout must sit **outside** `tools/agave-fixtures`. Inside it,
  Cargo treats Agave's crates as members of the fixture workspace and fails on
  `workspace.package.edition`.
- A build piped through `tail` reports the exit code of `tail`. The first
  fixture build looked successful and was not.
- `solana-test-validator` needs `--alpenglow` to start with Alpenglow active
  on v4.4.1. Its epoch is 432,000 slots, so a short run never crosses one.
- The `solana` CLI of v4.4.1 writes `--with-memo` to Memo version 4.
- `ledger-dump` opens the ledger read-only, so it runs beside the validator.
  Dump a few slots behind the tip: the newest slots may not be full yet.

## Next steps, in order

1. **Find independent signers for the set log, and publish it.** The tool is
   built (`docs/SETS.md`) and checks each set's members against the admission
   debits of the block that admitted them, so that membership check is done.
   What is left is not code: several signers independent of one another, each
   reading the set themselves every epoch, and a published place for the file.
   The one code path not yet run on real data is the shared-key rank map,
   which no mainnet epoch seen so far has needed.
2. **Run the prover for longer than an afternoon.** It is built
   (`docs/PROVER.md`) and was measured on 20 fresh mainnet blocks. Still to
   see live: an epoch boundary with both sets, slow certificates, old
   blocks near the end of what validators keep, and a day of steady
   requests.
3. **Outside review.** Post to the Solana developer forum and ask Anza or
   Firedancer engineers to check the certificate and block id handling. The
   three protocol asks in `DESIGN.md` are a natural thread.
4. **Support UpdateParent blocks** if a wider sample of mainnet shows them.
5. **Shrink proofs.** The median is 21.6 KB because a proof carries the batch
   in front of its transaction. Nothing in the crate can fix that; a protocol
   change could (see `DESIGN.md`, open questions).

## Where to share, once reviewed

Solana Developer Forums first, then the Anza and Solana Tech Discord, RPC
providers (Helius, Triton) who could serve proofs, Solana Mobile and wallet
teams, bridge teams (IBC, Wormhole, LayerZero), Solana Stack Exchange, and
after review r/solana, r/rust, Hacker News and This Week in Rust.
