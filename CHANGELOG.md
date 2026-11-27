# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/) with the pre-1.0 caveat in
[RELEASING.md](RELEASING.md).

## [Unreleased]

### Added

- **Explorer** (`explorer/`, `scripts/explorer.sh`): a static web page that
  fetches a proof from a prover, verifies it in WebAssembly, and shows the
  proven transaction. It has no server code and makes the same requests for
  every visitor, so its host never learns what was looked up.
- `solana-thin-wasm`: `verify` also returns the block's parent, the block the
  certificate was for, the transaction's position, the footer's bank hash and
  client, and the transaction itself (signatures, account keys, recent
  blockhash, instructions, message bytes).
  It also returns the proof's anatomy: the certificate's signers (by rank)
  and their share of stake, the parent links, the block's FEC set count, and
  which shreds the proof opens.
- `prover serve` sends `Access-Control-Allow-Origin: *` with every answer, so
  a page on any origin can read it.

## [0.1.0]

First release. `solana-thin` checks, from a small proof and an untrusted
server, that a transaction is in a block Solana's validators finalized after
Alpenglow. It runs no node, replays nothing, and keeps no chain state; its
only trust root is the hash of an epoch's validator set.

### Added

- **Verifier** (`solana-thin`): given a pinned validator-set hash and a proof
  from any source, checks a finality certificate and that a transaction's
  bytes sit in an executed part of the finalized block. No network, `std`
  only, `blst` for the BLS checks.
- **Prover** (`solana-thin-prover`): a small node that fetches finalized
  blocks from validators over the repair protocol and serves proofs that a
  transaction is in one.
- **Set log** (`solana-thin-setlog`): a signed, hash-chained log of
  validator-set hashes, one record per epoch, that a client checks before it
  pins a set. Ed25519, SHA-256 and JSON, with no dependency of the verifier
  on it.
- **Bindings** (`solana-thin-ffi`, `solana-thin-wasm`): Kotlin and Swift
  bindings generated with UniFFI, and a bare WebAssembly module with a small
  JavaScript wrapper. Built from this repository; not published to a package
  registry.

[0.1.0]: https://github.com/dannycake/solana-thin/releases/tag/v0.1.0
