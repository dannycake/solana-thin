# agave-fixtures

Writes `crates/solana-thin/tests/vectors/agave-v4.4.1.json` using Agave's own
code, so the conformance tests compare solana-thin with the validator rather
than with itself.

```
git clone --depth 1 --branch v4.4.1 https://github.com/anza-xyz/agave ../agave
cargo run --release -- ../../crates/solana-thin/tests/vectors/agave-v4.4.1.json
```

It links the blockstore, so the first build takes several minutes and needs
`libclang` (set `LIBCLANG_PATH` if it is not found). Keys are random, so each
run writes different vectors; the tests depend on their structure, not their
bytes.

## Tools for testing against running validators

Two more binaries share this crate because they need the same Agave build.
`docs/LOCAL-VALIDATOR.md` has the procedures.

- `ledger-dump <ledger dir> <first slot> <last slot> <out.jsonl>` writes each
  full slot's data shreds, and the block id Agave computed, from a ledger
  directory. Read-only, so it runs beside a live validator.
- `cluster-run <out dir>` runs four validators in this process with Agave's
  `LocalCluster`, stops one half way, and leaves the bootstrap validator's
  ledger and a validator set per epoch in `<out dir>`. `LocalCluster` writes
  its ledgers inside the Agave checkout; `cluster-run` moves or deletes them
  when it finishes.
## Validator sets from snapshots

`snapshot-stakes` is here for the same reason: it parses a bank snapshot
with Agave's own code. It reads the front of the incremental snapshots that
nodes serve over HTTP, stops when the bank file is complete (about 70 MB
into an archive several times that size), and writes each node's
epoch-stakes maps as an extract for `setlog agree`. `docs/SETS.md` has the
procedure.

```
cargo build --release --bin snapshot-stakes
snapshot-stakes --cluster mainnet-beta --rpc https://api.mainnet-beta.solana.com --out extracts
snapshot-stakes --cluster mainnet-beta --shred-version 50093 --out extracts --node 192.0.2.1:8899
```

The first form finds nodes with `getClusterNodes`, probes them in a shuffled
order, and reads from three on different networks whose snapshot is recent.
The second reads from the nodes named. Each node gets one request at a time
and is never asked twice in a run; a download ends at `--max-bytes`
(256 MiB unless given). Every map is ranked by Agave and by solana-thin, and
an extract is written only if they give the same list.

## The differential oracle

`diff-fuzz` asks Agave and the verifier about the same shreds and fails when
they disagree. `src/oracle.rs` runs Agave's pipeline (fetch filter, signature
check, blockstore insert, the replay stage's parent and start rules,
`process_single_slot`); `src/harness.rs` enumerates the verifier's claims and
checks the properties; `src/corpus.rs` holds the named cases and mutators.
`ORACLE-NOTES.md` says what was measured and what is not modeled.

```
cargo build --release --bin diff-fuzz
diff-fuzz --smoke                 # one honest block, 29 checks, 0.2 s
diff-fuzz --corpus                # every named case, handover on and off
diff-fuzz --random 2000 --seed 1  # generated cases
diff-fuzz --emit ../../crates/solana-thin/tests/vectors/oracle
diff-fuzz --corpus --recovery     # the same cases, partly rebuilt from parity
diff-fuzz --random 2000 --seed 1 --recovery
```

It exits non-zero on any case where the verifier accepts something Agave did
not execute (P1), the block id or parent differs (P2), Agave's verdict
depends on shred arrival order (P0), or a mutator family that should get
Agave to vote never did. One known order-dependent shape is not counted,
because the verifier refuses it outright.

After changing the verifier, rerun `--corpus`, and `--emit` to refresh the
frozen cases that `cargo test --test oracle_corpus` replays without Agave.

### Erasure recovery

A validator often receives only part of a block's data shreds and rebuilds
the rest from coding shreds. `--recovery` judges every case that way too.
`oracle::erasure_code` gives the block its real coding shreds (Reed-Solomon
parity over each FEC set, in the layout of Agave's shredder, which the run
first checks byte for byte against `Shredder::make_shreds_from_data_slice`)
and rebuilds the Merkle trees over them. The testkit's trees hold filler
hashes where coding leaves go, so the block id is not the one the other
modes see; the bytes replay reads are. The case then runs as usual on that
block, and again under each loss in `harness::losses`: parity added and
nothing withheld, the first and last data shred of every set, every data
shred, a random subset down to exactly the 32 shreds of a set that
reconstruction needs, and exactly the shreds the filter or parser refuses on
receipt. Each loss arrives forward, reversed (parity before data) and
shuffled one shred per insert.

On top of the properties above, the run fails when:

- a block judged through recovery does not get what the same shreds get
  arriving in the same order with nothing to reconstruct (the harness
  replays every recovery run that way), verdict, `SlotMeta` and stored
  shreds alike;
- its verdict (voted, dead, parent, block id, executed transactions) is not
  one the whole block gets in some arrival order;
- a withheld shred that the whole block keeps never comes back, although its
  set reached the blockstore with 32 shreds;
- a set one shred short of 32 is rebuilt anyway.

One more thing is known, reported, and not counted: a FEC set holding a data
shred that fails `Shred::sanitize` cannot be rebuilt at all, because recovery
sanitizes what it rebuilds and gives up on the whole set. Such a slot never
fills however its shreds arrive.

Recovery runs take about 0.5 s a case. `--emit` does not take `--recovery`:
frozen vectors are rebuilt by the testkit, without parity. `ORACLE-NOTES.md`
has what the runs showed.

## Code adapted from Agave

This crate links Agave and, in two places, copies a few lines of it that are
private to `solana-core`: the replay stage's rule for choosing a block's
parent and where replay starts (`child_bank_replay_start` in
`core/src/replay_stage/update_parent.rs`), and the duplicate-shred handler
(`run_check_duplicate` in `core/src/window_service.rs`). The insert pipeline
follows the shape of Agave's own conformance harness
(`conformance/src/shred.rs`). Each is marked where it appears in
`src/oracle.rs`. Agave is copyright its
contributors and licensed under Apache-2.0, as this repository also is.

