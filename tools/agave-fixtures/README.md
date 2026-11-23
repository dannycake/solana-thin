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
