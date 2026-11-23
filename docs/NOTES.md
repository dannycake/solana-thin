# Session notes (2026-11-23)

Handoff notes from the session that built v0.1. `README.md` says what the
crate does and `docs/DESIGN.md` says why each check exists. This file holds
everything else: what was measured, where each fact came from, what was tried
and dropped, and what to do next.

## State of the repo

- Branch `main`, pushed.
- `cargo test`: 76 tests pass (34 unit, 20 attacks, 8 conformance, 8
  end-to-end, 2 mainnet snapshot, 3 properties, 1 doctest). The attack suite
  takes about 25 seconds; the rest is quick.
- `cargo clippy --workspace --all-targets --features testkit -- -D warnings`
  is clean. `cargo doc` is clean.
- Built with Rust 1.97. The crate declares `rust-version = "1.75"`, which was
  **not** tested on 1.75.
- There is no CI. Run the three commands above before pushing.
- Unaudited. Nobody but the author has read the code.

## What is verified, and how strongly

| Claim | Evidence | Strength |
|---|---|---|
| Block id computation is right | Equal to ids read back from an Agave v4.4.1 `Blockstore` for 3 blocks | Strong |
| Vote payload bytes are right | Equal to `agave_votor_messages::wire::get_vote_payload_to_sign` | Strong |
| BLS scheme and thresholds are right | Same verdict as `agave_bls_cert_verify::verify_certificate` on 13 certificates (5 accepted, 8 rejected) | Strong for the cases covered |
| Validator ranking and filters are right | Equal to `BLSPubkeyToRankMap::new` on 14 random vote accounts, including zero stake and a duplicated key | Strong |
| Proof of possession format is right | Verifies PoPs made with `solana-bls-signatures` over the vote program's message | Strong |
| Transaction walking is right | 254 Agave-serialized transactions (248 legacy, 2 v0, 4 v1, 2 multi-signer) parse to the same message bytes and positions | Good; v0 and v1 samples are few |
| Footer and header parsing is right | Parses footers Agave serialized, including fast and slow embedded certificates | Good |
| Live mainnet keys load | All 684 BLS keys from public RPC in epoch 1095 decode and pass subgroup checks | Strong, but says nothing about certificates |
| A live mainnet certificate verifies | **Not tested.** No source for certificates or shreds was reachable | None |
| Works against a running validator | **Not tested.** See "Next steps" | None |

The Agave vectors use random keys, so regenerating them changes the bytes.
The tests depend on structure, not on specific values.

## Facts measured from mainnet during the session

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
- 686 vote accounts, 684 with a BLS key, 684 ranked. Total stake 425.9M SOL.
  The top 58 validators hold 60% of stake and the top 137 hold 80%.
- Validator set size 38,308 bytes; signer bitmap 89 bytes.
- Set hash for the snapshot in `tests/vectors/mainnet-vote-accounts.json`:
  `90e2d142812017087d75ccc1918f5215fd99bb17b1dbba4b6f75372590905b6d`. Per the
  epoch-stake rule below this should be the set for epoch **1096**. That has
  not been confirmed against a certificate.

RPC methods that do **not** help:

- `getBlock` on 4.4.0 returns no block id, footer or certificate.
- `getVatActiveSetRankMap` exists on Agave's development branch and returns
  "Method not found" on mainnet's 4.4.0. When it ships it should replace
  `tools/fetch_vote_accounts.py`.
- No RPC method on either branch returns a finality certificate other than the
  genesis one.

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
- FEC set rules: `ledger/src/shred/merkle.rs` (`check_fec_set`, SIMD-0504)
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
  `getVoteAccounts` during epoch `E` should give the set for `E + 1`. This was
  derived from reading the code, not observed.
- **A fast certificate reuses the notarize payload.** Tag `0x01`, same bytes as
  a plain notarization. There is no separate "fast finalize" vote.
- **Finalization certificates must use the base-2 bitmap.** Agave rejects the
  base-3 form for them (`Base3Finalization`). Base 3 is only for skip and
  notarize-fallback certificates, which this crate does not handle.
- **Bits past the declared count in a bitmap are ignored**, by Agave and here.
- **Every component is padded to a whole FEC set.** A partly filled shred must
  be followed by empty shreds, and the last shred of the set must carry
  `DATA_COMPLETE`. A full FEC set may continue into the next one.
- **`DATA_COMPLETE` may be set on any shred.** `check_fec_set` does not forbid
  it mid-set, so the verifier follows the flags and does not assume components
  align to FEC sets. Covered by `components_may_end_mid_fec_set`.
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

## Things I am least sure of

1. **Stale-set mode's drift assumption.** The 9% per epoch figure is the stake
   warm-up and cool-down cap as I remember it; it was not re-checked in the
   source. Validators can also leave the rank map by routes that cap does not
   cover. Treat stale mode as experimental.
2. **The epoch-stake offset** (the `E` versus `E + 1` rule above). One real
   certificate would settle it.
3. **Whether fast leader handover is active on mainnet.** If it is common,
   refusing those blocks will be a visible gap.
4. **Batch sizes on mainnet.** Proof size depends on them and they were not
   measured. The 1.9 KB and 50 KB figures come from synthetic blocks.
5. **Validator admission (the "VAT" in `getVatActiveSetRankMap`).** If an
   admission rule filters the rank map beyond what `BLSPubkeyToRankMap` does in
   v4.4.1, `from_vote_accounts` would produce the wrong set. Not investigated.
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
I could not see earlier chats from this session, so projects named there may
be missing.

## Environment gotchas

- `tools/agave` is gitignored. In the session it was a symlink to a checkout
  of Agave v4.4.1. On a new machine:
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
- In the cloud session, running the downloaded Agave release binaries was
  blocked by the permission system. That is why the local-validator test was
  not done.

## Next steps, in order

1. **Local validator test.** Run `solana-test-validator` (Agave v4.4.x), send a
   few Memo transactions, stop it. Write a small tool (extend
   `tools/agave-fixtures`, which already links `Blockstore`) that opens the
   ledger directory and dumps, per slot, the data shred payloads. Feed them to
   `BlockData::from_shreds`, take a certificate from a later block's footer,
   build the validator set from the test validator's vote account, and run
   `prover::prove` then `ThinClient::verify_signature`. Things to watch for:
   - whether the test validator on 4.4.x starts with Alpenglow active (the
     changelog on master says it does by default; not checked for 4.4.x);
   - its shred version, which will not be 50093;
   - its epoch length, which is short by default, so the stake offset rule
     will be exercised quickly.
2. **Get one real mainnet certificate and block.** Any of: an RPC provider
   with a Geyser plugin, ledger access through `agave-ledger-tool`, or a shred
   stream. One block's data shreds plus one footer certificate is enough to
   settle items 2 to 5 in "least sure of".
3. **Outside review.** Post to the Solana developer forum and ask Anza or
   Firedancer engineers to check the certificate and block id handling. The
   three protocol asks in `DESIGN.md` are a natural thread.
4. **Support UpdateParent blocks** if step 2 shows they are common.
5. **Measure and shrink proofs** once real batch sizes are known.

## Where to share, once reviewed

Solana Developer Forums first, then the Anza and Solana Tech Discord, RPC
providers (Helius, Triton) who could serve proofs, Solana Mobile and wallet
teams, bridge teams (IBC, Wormhole, LayerZero), Solana Stack Exchange, and
after review r/solana, r/rust, Hacker News and This Week in Rust.
