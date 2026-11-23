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
