<!-- Soundness or security fix? Please report it privately first: see SECURITY.md. -->

## What and why

## Checks run

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace` and `cargo test --workspace --all-features`
- [ ] Heavy checks, if any (fuzz, oracle, fixtures):

## If this touches the verifier

- [ ] It only makes the verifier stricter, or the ledger says why not
- [ ] New refusals have their own `Error` variant and a test in `tests/attacks.rs`
- [ ] `docs/conformance.toml` updated and `scripts/conformance.py` rerun
- [ ] Agave file and line cited for any format or rule
