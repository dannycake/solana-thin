# Working notes (2026-11-23)

`README.md` says what the crate does and `docs/DESIGN.md` says why each check
exists. This file holds everything else: what was measured, where each fact
came from, what was tried and dropped, and what to do next.

## State of the repo

- Branch `main`, pushed.
- `cargo test`: 78 tests pass (35 unit, 21 attacks, 8 conformance, 8
  end-to-end, 2 mainnet snapshot, 3 properties, 1 doctest). The attack suite
  takes about 25 seconds; the rest is quick.
- `cargo clippy --workspace --all-targets --features testkit -- -D warnings`
  is clean. `cargo doc` is clean.
- `rust-version` is 1.85, and the tests pass on 1.85.0. It was declared as
  1.75 and never built there: with the committed `Cargo.lock`, `blst` pulls in
  `zeroize_derive` 1.5, which is an edition 2024 crate.
- There is no CI. Run the three commands above before pushing.
- Unaudited. One independent read against Agave v4.4.1's source was done on
  2026-11-23 and found a soundness bug; see "Review findings" below. That is
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
| Membership of the mainnet set is right | 664 `VATDebit` entries in the first block of epoch 1095 match 664 staked accounts with keys; 20 staked accounts with keys had none | Good. Not confirmed by a certificate |
| A live mainnet certificate verifies | **Not tested.** No source for shreds or footers was reachable. The genesis certificate was tried and could not be checked; see below | None |

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
  `7cc14b596ad61f6aff8b5e638831c3c40c1fd3b7a15d831f23e23a6c2515b1ee`. This
  is the set for epoch **1096**. It replaces `90e2d142…`, which was built
  from all 684 staked accounts and was wrong.
- Fetching twice in the same epoch, 18,000 slots apart, gave identical
  accounts. The hash is stable within an epoch.

### The genesis certificate, tried and not verified

`getAgGenesisCert` returns a real certificate: 446 signers over slot
459,652,999. Its payload is tag `0x06` with the same layout as a notarize
vote. Checking it needs the ranked set of epoch 1064, which is stake as it
stood in epoch 1063, exact to the lamport, because one wrong rank changes the
aggregate key. Public RPC only reports current stake. Trillium's per-epoch
API (`api.trillium.so/validator_rewards/1063`) has every validator's BLS key
but rounds stake to 10^-5 SOL, has ties at that precision, and one record
with unreadable keys. A set rebuilt from it puts 82.15% of stake behind the
bitmap, which is the right neighbourhood for a genesis certificate, but the
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
  discards any other shred that carries it (`filter.rs`). The verifier
  follows the flags wherever they are, which accepts a superset and is
  harmless. `components_may_end_mid_fec_set` tests a shape validators drop.
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
  forgery. Replaced by stale-set mode, which trusts no new stake values and
  cannot be chained.
- **Dropped: built-in signed attestations of the set hash** (m-of-n Ed25519).
  `trust_validator_set` with a pinned hash covers it without a new dependency;
  how the hash is agreed is left to the application.
- **Dropped: proving execution success by indirect tricks** (fee-payer
  balances, durable nonces). Too fragile to claim anything from.
- **The crate uses `std`.** `no_std` was not attempted. `blst` supports it.
- **Transaction signatures are not re-verified.** A block with a badly signed
  transaction is invalid and would not be finalized.

## Review findings (2026-11-23)

One independent read of the verifier against Agave v4.4.1's source. Each
finding was then checked against the source or the network before acting.

1. **Soundness bug, fixed.** The verifier read the block header from the
   whole first component; the blockstore reads it from shred 0 alone. A
   leader could split the header over two shreds, switch to the same parent
   with `UpdateParent`, and have the verifier accept a transaction from the
   discarded prefix. Fix and test: `ThinClient::verify_transaction` step 4,
   `a_header_split_across_shreds_does_not_hide_an_abandoned_prefix`. The
   Agave side was read, not run: nobody built such a block on a validator.
2. **Stale-set mode has a counterexample.** Stake that is active but outside
   the ranked set can join in one epoch with no activation, so the 9% cap
   does not bound drift. Documented; the mode is still there, off by default.
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

Confirmed to match, with file and line, by the same read: shred header
offsets and capacities, the leaf and node hashing, the double-Merkle tree and
its parent leaf, component boundaries, marker and entry-batch layout, vote
payloads, both thresholds, bitmap decoding, the rank map's filters and order,
and both BLS domain tags. Not covered: `blst` against `blstrs` beyond the
tags, base-3 bitmaps, pre-migration blocks, Agave's master branch.

## Things I am least sure of

1. **Other places where the verifier and a validator read a block
   differently.** The split header was one, and it was not found by any test
   written beforehand. Firedancer was not read at all.
2. **Stale-set mode.** No sound bound is known. It may be better removed.
3. **Whether fast leader handover is active on mainnet.** If it is common,
   refusing those blocks will be a visible gap.
4. **Batch sizes on mainnet.** Proof size depends on them. The 2.0 KB and
   31.5 KB figures come from a test validator with light traffic.
5. **BLS key and node identity at the snapshot.** The fetch tool reads them
   live. `getVatActiveSetRankMap`, when it ships, removes the guess.
6. **The 2^80 leader collision attack** is my own analysis of the 20-byte
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

1. **Get one real mainnet block and certificate.** The set for epoch 1096 is
   already in `tests/vectors/mainnet-vote-accounts.json` (fetched in epoch
   1095). What is missing is a slot's data shreds from epoch 1096 and the
   footer that certifies it. Routes, cheapest first: ask an RPC provider or a
   validator operator to run `ledger-dump` on one slot; fetch the shreds over
   the repair protocol from the `serveRepair` addresses in `getClusterNodes`;
   subscribe to a shred stream. This settles items 3 to 5 in "least sure of",
   and it is the result a Solana engineer will ask for first.

   On the repair route: v4.4.1's `core/src/repair/serve_repair.rs` answers
   unstaked requesters (after a ping), dropping them first under load. It
   also has `ParentAndFecSetCount` and `FecSetRoot` requests keyed by block
   id, which return the same Merkle openings this crate's proofs carry. So
   validators already serve most of a proof to each other. Not tried.
2. **Save `getVoteAccounts` every epoch.** A cron job running
   `tools/fetch_vote_accounts.py`. Without it, step 1 has a one-epoch window.
3. **Build the split-header block on a real validator.** The fix follows
   Agave's source, but the attack was only run against this crate. Shredding
   such a block with Agave's `Shredder` and replaying it would show whether
   validators really finalize it.
4. **Outside review.** Post to the Solana developer forum and ask Anza or
   Firedancer engineers to check the certificate and block id handling. The
   three protocol asks in `DESIGN.md` are a natural thread.
5. **Support UpdateParent blocks** if step 1 shows they are common.
6. **Measure and shrink proofs** once real batch sizes are known.
7. **A prover that runs somewhere.** The library needs a host with shreds: a
   Geyser plugin or a sidecar reading a node's ledger, serving
   `getTransactionProof` over HTTP.

## Where to share, once reviewed

Solana Developer Forums first, then the Anza and Solana Tech Discord, RPC
providers (Helius, Triton) who could serve proofs, Solana Mobile and wallet
teams, bridge teams (IBC, Wormhole, LayerZero), Solana Stack Exchange, and
after review r/solana, r/rust, Hacker News and This Week in Rust.
