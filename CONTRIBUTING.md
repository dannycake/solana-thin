# Contributing

Issues and pull requests are welcome. For anything larger than a fix, open an
issue first so the approach can be agreed before you write it. Security and
soundness bugs go through [SECURITY.md](SECURITY.md), not public issues.

## Building and testing

Rust 1.85 or newer.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace                  # default features
cargo test --workspace --all-features   # also the setlog and bindings tests
cargo deny check                        # if you have cargo-deny
```

CI runs these on every push, on stable and on 1.85. With `--all-features`
the tests of the `setlog` tool run too; they start the binary against local
servers and need `curl` on the path.

A plain `cargo build` or `cargo test` covers the verifier alone. The
`--workspace` commands above also build the bindings and UniFFI's generator,
which needs a current stable compiler. If you change what the bindings
export, or anything they are built from, also run:

```sh
scripts/bindings.sh    # the exported interface and the Kotlin smoke test (JDK, kotlinc)
scripts/wasm.sh        # a mainnet proof in the WebAssembly module (node, clang)
```

[docs/BINDINGS.md](docs/BINDINGS.md) says what each needs and checks.

Some checks are too heavy for CI and need extra setup. You do not have to run
them for a pull request; say which you ran.

| Check | Command | Needs |
|---|---|---|
| Fuzz targets | `scripts/fuzz.sh` | nightly, `cargo-fuzz` |
| Public shred fixtures | `cargo run --release` in `tools/shred-fixtures` | network, `curl` |
| Differential oracle | `diff-fuzz --corpus` in `tools/agave-fixtures` | an Agave v4.4.1 checkout at `tools/agave` |
| Upstream tripwire | `scripts/tripwire.py` | `gh`, network |
| All of the above | `scripts/nightly.sh` | all of the above |

## Changing the verifier

The verifier (`crates/solana-thin/src`) is small on purpose, and a change to
it is held to more than "the tests pass":

- **It only ever gets stricter than a validator.** Never accept something on
  an inference about what validators would do. If a rule is not checked, the
  ledger must say which premise makes that safe.
- **Every refusal has its own `Error` variant** and a test in
  `tests/attacks.rs` that builds the input and checks the reason. A new
  variant also takes one of the kinds in `ErrorKind`'s table, which is what
  the bindings and most apps match on.
- **Update the ledger.** `docs/conformance.toml` lists every validator check
  and what the verifier does about it. Change the row, run
  `python3 scripts/conformance.py`, and `cargo test --test conformance_ledger`
  will tell you if a row no longer resolves.
- **Rerun the oracle** if you can (`diff-fuzz --corpus`, then `--emit` to
  refresh `tests/vectors/oracle`). If you cannot, say so and a maintainer
  will.
- **No new dependencies in the verifier** without a strong reason. It depends
  on `blst` and `sha2`, has no network code and no `unsafe`, and should stay
  that way.

Formats are taken from Agave's source, not from memory or from this crate's
own tests. When you add or change one, cite the Agave file and line.

## What will not be merged

- Claims about whether a transaction succeeded, or about account state, built
  on heuristics. Solana does not commit to either in a form a proof can open.
- Fetching, caching or networking inside the verifier crate. Tools that do
  those live beside it.
- Anything that follows validator-set changes without a trusted input, until
  the protocol offers a commitment to check.

## Commits and license

One logical change per commit, with a message that says why. Do not include
machine-specific paths or generated build output.

By contributing you agree that your work is licensed under Apache-2.0, the
same as the rest of the repository.
