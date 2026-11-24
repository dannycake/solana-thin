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
- `cluster-inject <out dir>` runs the same four-validator Alpenglow cluster
  with a fixed leader schedule, stops the 10% validator, and injects
  hand-built blocks for the slots it would have led, signed with its held node
  keypair, straight into the running validators' TVU ports with
  `Cluster::send_shreds_to_validator`. The footer's bank hash is settled by
  replaying the block against a child of a live validator's in-process
  `BankForks` bank on a scratch blockstore. For each case it prints the
  injected slot, what the validators did (inserted / dead / full / rooted,
  from the target validator's own blockstore and bank forks), whether the
  abandoned transfer X and the suffix transfer executed (recipient balances),
  and what the light client says — both `BlockData::from_shreds` on the
  injected shreds and, for a finalized block, a proof of a suffix transaction
  against the real footer finality certificate and the recorded validator set
  (as `examples/verify_ledger.rs` does). It turns "seen in a single-process
  replay" into "seen on running validators". See `ORACLE-NOTES.md` for what
  each case did. Exit status is 0 if the run completed, whatever the
  validators decided; it cleans up `LocalCluster`'s ledgers like `cluster-run`.

## The differential oracle

`diff-fuzz` asks Agave and the verifier about the same shreds and fails when
they disagree. `src/oracle.rs` runs Agave's pipeline (fetch filter, signature
check, blockstore insert, the replay stage's parent and start rules,
`process_single_slot`); `src/harness.rs` enumerates the verifier's claims and
checks the properties; `src/corpus.rs` holds the named cases and mutators.
`ORACLE-NOTES.md` says what was measured and what is not modelled.

```
cargo build --release --bin diff-fuzz
diff-fuzz --smoke                 # one honest block, 29 checks, 0.2 s
diff-fuzz --corpus                # every named case, handover on and off
diff-fuzz --random 2000 --seed 1  # generated cases
diff-fuzz --emit ../../crates/solana-thin/tests/vectors/oracle
```

It exits non-zero on any case where the verifier accepts something Agave did
not execute (P1), the block id or parent differs (P2), Agave's verdict
depends on shred arrival order (P0), or a mutator family that should get
Agave to vote never did. One order dependence is known, reported, and not
counted: a block on a zero-id parent with an UpdateParent to the same parent,
which Agave accepts or kills depending on which shred arrives first.

After changing the verifier, rerun `--corpus`, and `--emit` to refresh the
frozen cases that `cargo test --test oracle_corpus` replays without Agave.

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

