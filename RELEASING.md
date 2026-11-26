# Releasing

## Versioning

The project is before 1.0. Under Semantic Versioning a `0.x` release makes no
stability promise across a minor bump: while the version is `0.y.z`, a change
to `y` may break the API, and only a change to `z` is guaranteed not to. Treat
every `0.y.0` as a release that may need code changes to adopt.

Three crates are published to crates.io and share one version, the workspace
version in the root `Cargo.toml`:

- `solana-thin`
- `solana-thin-prover`
- `solana-thin-setlog`

They are versioned and released together, even when only one of them changed,
so that a given version names one consistent set. The `solana-thin-prover` and
`solana-thin-setlog` crates depend on `solana-thin` by that same version;
bump the workspace version and those dependency requirements in one step.

The `solana-thin-ffi`, `solana-thin-wasm` and `uniffi-bindgen` crates are
`publish = false`. They are built from this repository and not released to a
registry.

## Steps

1. Update [CHANGELOG.md](CHANGELOG.md): rename the pending section to the new
   version and start a fresh one for the next.
2. Bump `version` under `[workspace.package]` in the root `Cargo.toml`, and
   the `solana-thin` dependency requirement in the prover and set-log crates
   to match.
3. Run the checks in [CONTRIBUTING.md](CONTRIBUTING.md).
4. `cargo publish` the three crates in dependency order: `solana-thin`,
   then `solana-thin-setlog`, then `solana-thin-prover`.
5. Tag the release `vX.Y.Z`.
