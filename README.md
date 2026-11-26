# solana-thin

[![ci](https://github.com/dannycake/solana-thin/actions/workflows/ci.yml/badge.svg)](https://github.com/dannycake/solana-thin/actions/workflows/ci.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](#license)
[![rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange)](Cargo.toml)
[![status: unaudited](https://img.shields.io/badge/status-v0.1%2C%20unaudited-red)](SECURITY.md)

A thin client for Solana after Alpenglow. Hand it a proof from anyone, a few
tens of kilobytes, and it tells you whether your transaction is in a block the
validators finalized. No node, no replay, no trusted server.

```rust
use solana_thin::{ClusterParams, ThinClient, TxProof};

// Trust: the cluster's shred version and the hash of this epoch's validator set.
let mut client = ThinClient::new(ClusterParams::mainnet(50093));
client.trust_validator_set(epoch, validator_set, &pinned_hash)?;

// Proof: bytes from a relay, a friend's phone, a public server. Untrusted.
let proof = TxProof::from_bytes(&proof_bytes, client.limits())?;
let verified = client.verify_signature(&proof, &my_signature)?;

println!("final in slot {}", verified.block.slot);
```

Status: **v0.1, not reviewed by anyone who works on a validator.** The
verifier agrees with Agave v4.4.1 on every test vector, with a differential
oracle that runs Agave's own blockstore and replay, and with running
validators. On mainnet it has proven and verified 186,000 transactions from
about 480 blocks fetched from validators, Firedancer-led ones among them,
and refused none of those blocks; on testnet and devnet, which run Agave
4.5, 7,419 transactions from 288 blocks (see [Tests](#tests)). An early
review found one way to make it accept a transaction that never ran, and an
independent one later found none; both are in [docs/NOTES.md](docs/NOTES.md).
Do not put money behind it until someone other than its author has
reviewed it.

## What changed, and what this adds

Before Alpenglow, validators voted with ordinary transactions. Checking that a
block was final meant fetching hundreds of vote transactions and knowing every
validator's stake, which is most of a full node's work.

Alpenglow went live on mainnet on October 21, 2026. Votes are now BLS
signatures, and enough of them fold into one **finality certificate**: an
aggregate signature plus a bitmap of who signed, about 200 bytes for today's
664 validators. That is the first half of a light client: *is this block
final?*

The second half was still missing: *is my transaction in it?* This crate
supplies it. An Alpenglow block id is a Merkle root over the block's shreds
and its parent, so a transaction's bytes can be hashed up to the same id the
certificate signs. No protocol change is needed.

| Question | How it is answered | Size |
|---|---|---|
| Is block `F` final? | BLS aggregate over the pinned validator set, 80% of stake (or 60% + 60%) | ~200 B |
| Is block `B` an ancestor of `F`? | One parent leaf and Merkle path per hop | ~170 B per hop |
| Are these bytes in `B`? | Shreds hashed up to `B`'s id | the shreds, plus ~300 B |
| Are these bytes a *transaction* of `B`? | Parse the batch from a proven boundary, as a validator does | the batch up to your transaction |

Measured proof sizes on mainnet, over 1,048 transactions: **3.2 KB** at
best, **19 KB** at the median, **64 KB** at worst. A proof carries the entry
batch in front of its transaction, and mainnet leaders cut batches at about
60 KB. On a quiet test validator a lone transaction proves in 2.0 KB. The
validator set itself is 37 KB per epoch (56 bytes per validator).

## What a successful check means

All of this held:

1. Validators holding at least 80% of the pinned stake signed the block, or 60%
   signed it and 60% signed to finalize its slot, on this cluster.
2. The transaction's bytes hash up to that block's id, or to an ancestor's.
3. Those bytes sit where a validator reads a transaction, in a part of the
   block that was executed.

What it does **not** mean:

- **That the transaction succeeded, or did anything.** A transaction whose
  program returned an error is still included and still pays its fee. One
  whose fee payer cannot pay may, where the cluster has activated SIMD-0290,
  be included as a no-op that runs nothing and pays nothing. Nothing a block
  commits to records the difference in a form a small proof can open.
- **Anything about account state.** Solana's state commitment (the accounts
  lattice hash, [SIMD-0215](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0215-accounts-lattice-hash.md))
  cannot prove that an account is or is not included.
- **That your validator set is the right one.** That is your trust root.

## Limits, and how the design works around them

**1. Nothing on chain commits to the validator set.** This is the largest gap.
A light client on other chains follows validator-set changes with signed
handovers; Solana has no such commitment that a small proof can open.

- *Design:* a validator set is identified by a hash, and the client uses only
  sets whose hash you pinned. The set for epoch `E + 1` is fixed at the first
  block of epoch `E`, so there is a full epoch (about a day on mainnet) to
  fetch it.
- *Membership is not what `getVoteAccounts` lists.* The cluster admits only
  vote accounts that can pay a per-epoch fee, and records who paid in the
  epoch's first block. The tool reads that record. On mainnet in epoch 1095,
  664 of 684 staked validators with a key were admitted; a set built from all
  684 would have rejected every certificate.
- *Stake is not what `getVoteAccounts` reports either.* The cluster ranks
  validators by stake as it stood before the last epoch's staking rewards
  were paid; RPC reports it after. On mainnet that misplaced 8 of 664 ranks
  and on testnet 50 of 481, and every certificate of the next epoch failed
  against the fetched set. `tools/fetch_vote_accounts.py` produces that
  candidate, not the set.
- *The exact set can be read in three places that agree to the lamport:* the
  epoch-stakes map in the first 68 MB of any bank snapshot a node serves,
  `getVatActiveSetRankMap` on Agave 4.5, and `getVoteAccounts` less the
  staking rewards paid in the epoch's reward blocks
  ([docs/DESIGN.md](docs/DESIGN.md#validator-sets)). None is a proof: pin a
  hash that independent sources agree on.
- *A record of who read it.* `setlog` reads the set from snapshots served by
  several nodes and from the rank-map RPC, refuses if any two differ or if
  any names members other than the accounts the cluster charged to admit,
  and writes a signed, hash-chained record per epoch. A client checks the log
  against signer keys it ships with before it pins anything
  ([docs/SETS.md](docs/SETS.md)). That moves the trust to named signers; it
  does not remove it.
- *A real certificate does not vouch for a set.* It proves the order of the
  keys and nothing about their stake, so "the candidate verified a
  certificate" is a check against mistakes, not a reason to trust a hash.
- *What would fix it:* one hash of the next epoch's ranked validators in a
  block footer. See [docs/DESIGN.md](docs/DESIGN.md#what-solana-could-add).

**2. Execution results are not provable.** No receipts root exists
([SIMD-0064](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0064-transaction-receipt.md)
proposed one in 2023 and is marked Stagnant).

- *Design:* build on inclusion. Anchoring, ordering and timestamps need only
  that the bytes are in a finalized block at a known time, and that is fully
  proven, including the leader's validator-checked clock from the block
  footer. `examples/anchor.rs` shows the pattern: commit a fingerprint in a
  Memo instruction, and later prove the window in which it was made.

**3. Standard RPC does not serve what a prover needs.** `getBlock` returns
neither shreds nor block footers.

- *Design:* the prover (`solana_thin::prover`) is a library with no trust and
  no keys. It takes the data shreds exactly as a node stores them and nothing
  else. Anyone can run one; a client can ask several.
- *Where shreds come from:* validators hand them to anyone who asks over the
  repair protocol. An unstaked client with a fresh key fetched four full
  mainnet slots from 24 validators in half a second each. So a prover does
  not need to be a validator or an RPC node, only to ask soon enough:
  validators prune old slots.
- *A prover that does this:* `crates/solana-thin-prover` finds a block's
  certificate in the footers that follow it, fetches the block by its
  certified id, checking every shred against that id as it arrives, and
  serves `GET /proof/<signature>` ([docs/PROVER.md](docs/PROVER.md)). It
  proves recent transactions on demand; it is not an archive.

**4. Proof size depends on where the leader put your transaction.**
Transactions are not length-prefixed, so proving that bytes *are* a transaction
means carrying the whole batch in front of them.

- *Design:* shreds are sent in a compact form (three header bytes plus the
  body with padding removed), and runs of shreds share one Merkle multiproof.

**5. Inherited from the protocol.** Solana truncates Merkle nodes to 20 bytes.
Against everyone but the block's own leader that is 160-bit second-preimage
resistance. A *leader* willing to spend on the order of 2^80 hashes could build
two shreds that collide and show a light client the one validators never saw.
The validators themselves run on the same margin.

**6. Blocks that switch parent mid-way are refused.** With fast leader
handover a leader may switch parent partway through a block, abandoning its
first part. The verifier cannot prove which part of such a block ran, so v0.1
detects these blocks and refuses to prove anything in them rather than work
out which part ran. The feature is not active on mainnet as of November 2026,
so today this refuses nothing there. For the same reason nothing can be proven
in a block whose parent id is all zeros, which is only ever a block built
directly on a cluster's first block.

## Attacks this is built to refuse

Each has a test in [`tests/attacks.rs`](crates/solana-thin/tests/attacks.rs)
that builds the attack and checks the reason it is rejected.

| Attack | Why it works on a careless client | Rejected as |
|---|---|---|
| Embedded transaction | Your signed transaction's bytes are placed inside another transaction's data. They are in the block, correctly Merkle-proven, and never ran. | `NotComponentStart` |
| Abandoned prefix | A transaction sits in the part of a block the leader discarded. | `UpdateParentBlock` |
| Split header | A block header not contained wholly within shred 0, where the verifier reads it. | `InvalidComponent` |
| Zero parent id | A block built directly on a cluster's first block, whose parent id is all zeros; the verifier proves nothing in one. | `ZeroParentId` |
| Shreds no validator keeps | A completion flag in the middle of a FEC set, or a parent offset that disagrees with the block's parent. Validators drop such shreds, so the block they come from was never completed. | `InvalidShred` |
| Notarization as finality | A fast certificate and a notarization are the same signature; only the stake differs. | `InsufficientStake` |
| Slot-only finalize vote | Finalize votes name a slot, not a block. Paired with the wrong block they prove nothing. | `SignatureMismatch` / `InsufficientStake` |
| Rogue key | An unchecked key added to the set can cancel every honest key and sign alone for all of them. | `ValidatorSetHashMismatch` / `MissingProofOfPossession` |
| Phantom Merkle leaf | Odd tree levels pair the last node with itself, so it also verifies at the next index. | `InvalidShred` / `InvalidMerkleProof` |
| Cross-cluster replay | The same validator keys sign on testnets and across restarts. | `SignatureMismatch` |
| Fork or descendant | A sibling block, or a block after the certified one, claims its finality. | `BlockIdMismatch` / `InvalidParent` |
| Doubled key | A key listed twice lets one signature count twice. | `DuplicateValidator` |

## Prior work

Light clients for Solana have been proposed for years and the pieces they
needed never shipped. What I could verify:

- **Simple payment and state verification** (the original SPV design, in the
  [Anza docs](https://docs.anza.xyz/proposals/simple-payment-and-state-verification))
  notes that "the Block-Merkle is not implemented", so an inclusion proof would
  need every entry hash in the block.
- **[SIMD-0052](https://forum.solana.com/t/simd-0052-add-transaction-proof-and-block-merkle-for-light-clients/297)**
  (June 2023) proposed computing the blockhash as a Merkle tree with
  transaction statuses. I found no sign it was implemented.
- **[SIMD-0064](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0064-transaction-receipt.md)**,
  transaction receipts, is marked Stagnant.
- **[Tinydancer](https://github.com/tinydancer-io/tinydancer)** described
  itself as the first light client for Solana and planned SPV, then data
  availability sampling, then fraud proofs. Its repository was last updated in
  July 2024, and its plan depended on the proposals above.

These efforts were waiting on protocol changes: a succinct proof of finality
and a commitment that ties a transaction to a block. Alpenglow delivered both
as side effects of its consensus design. This crate uses them as they are.

## Tests

`cargo test --workspace --all-features` runs about 300 tests in about a
minute.

Run it from a checkout of this repository: that is the full suite. The crate
as published leaves out the two test files that read the repository around it
(the check ledger, below, and the test of `scripts/nightly.sh`). Unpacked on
its own, `cargo test --features testkit` runs everything else, and a plain
`cargo test` runs what needs no test builders.

- **A differential oracle** ([tools/agave-fixtures](tools/agave-fixtures),
  `diff-fuzz`), run nightly, not by `cargo test`. It builds blocks, cuts
  them into shreds in arbitrary layouts, and has Agave's own shred filter,
  blockstore and replay decide what it would vote for and which transactions
  it executed. Then it offers the verifier every claim a proof could make
  about the same shreds, from a prover that checks nothing. Whatever the
  verifier accepts, Agave must have executed, byte for byte; the block id
  and parent must be Agave's. Over a hundred named cases and seeded random
  ones, with fast leader handover on and off. 89 of its cases are frozen
  under `tests/vectors/oracle` and replayed by `cargo test` with no Agave
  present.
- **Fuzzing** (`fuzz/`, `scripts/fuzz.sh`), nightly. Eight targets; four hold
  the transaction parser to the validator's own (`agave-transaction-view`,
  and `solana-transaction` under `wincode`, each as Agave 4.4 and as 4.5
  ship it): whenever they accept bytes, this crate reads the same bytes to
  the same length.

- **The check ledger** ([docs/CONFORMANCE.md](docs/CONFORMANCE.md)). The 128
  checks an Agave validator applies between a shred arriving and a
  transaction counting as executed in a finalized block, with Agave's file
  and line for each, and what the verifier does about it: enforced (with the
  test that shows it), implied by finality (with the premise that makes that
  safe), or documented. `tests/conformance_ledger.rs` fails when a row stops
  resolving, and `scripts/tripwire.py` fails when a new Agave release changes
  a file a row cites, or when mainnet activates a feature the argument
  depends on.
- **Public shred fixtures** ([tools/shred-fixtures](tools/shred-fixtures)),
  run by hand. The 1,008 shred-parse fixtures that Agave and Firedancer are
  checked against: all 146,337 shred verdicts agree and all 4,557 FEC set
  roots are equal.

- **Conformance with Agave** (`tests/conformance.rs`). Vectors are generated by
  [`tools/agave-fixtures`](tools/agave-fixtures), which links Agave v4.4.1.
  Blocks are serialized and shredded by Agave, real coding shreds included, and
  their ids read back from an Agave blockstore. This crate computes the same
  block ids, reaches the same verdict as Agave's certificate verifier on 13
  certificates (5 valid, 8 invalid), ranks validators the same way, verifies
  the vote program's proofs of possession, and proves and parses 254
  Agave-written transactions (legacy, v0, v1, multi-signer) identically.
- **Attacks** (`tests/attacks.rs`), 37 tests, as listed above. One flips every
  bit of a valid proof in turn and checks that each mutant is either rejected
  or still true.
- **Live mainnet keys and certificates** (`tests/mainnet_snapshot.rs`). The
  BLS keys of all 664 validators admitted on mainnet in epoch 1095 decode,
  pass subgroup checks and rank. Four certificates from epoch 1096 are
  refused against that set as fetched from RPC, and verify against the stake
  the cluster froze, whose set hash is pinned in the test. A third test shows
  those certificates still verifying after one validator's stake is
  multiplied by 200.
- **Shapes** (`tests/properties.rs`). Random blocks, and batches sized exactly
  on, one under and one over shred and FEC set boundaries.

- **Running validators** ([docs/LOCAL-VALIDATOR.md](docs/LOCAL-VALIDATOR.md)),
  run by hand, not part of `cargo test`. Agave v4.4.1 with Alpenglow active.
  - One validator (`solana-test-validator`): 447 of 447 block ids equal the
    validator's, 446 of 446 footer certificates verify, 312 of 312
    transactions sent through its RPC were proven and verified.
  - Four validators with 40, 30, 20 and 10% of stake, the 30% one stopped
    half way: 709 of 709 block ids, 705 of 705 certificates (330 fast, 375
    slow) across 14 epochs with stake moving at each, proofs across skipped
    slots.

- **A mainnet block** (`tests/mainnet_block.rs`). The 512 data shreds of slot
  473,100,911, fetched over the repair protocol, and the certificate from the
  next block's footer. The block id computed from the shreds is the one the
  certificate names, the certificate verifies against the exact set of epoch
  1095 (666 validators, hash pinned in the test), and all 331 transactions
  prove and verify. With one validator missing from the set, or another
  shred version, it is rejected.

- **Three public clusters** ([docs/NOTES.md](docs/NOTES.md)), run by hand on
  2026-11-25 with throwaway tools, not part of `cargo test`.
  - Mainnet (Agave 4.4): 457 blocks fetched from validators by an unstaked
    client, from six minutes to 22 hours old. 455 of 455 certificates verify
    (451 fast, 4 slow) and 175,981 of 175,981 transactions prove and verify:
    legacy, v0 with up to 14 lookup tables, and v1. 72 of the blocks were
    led by Firedancer validators.
  - Testnet and devnet (Agave 4.5 beta): 288 blocks, 288 certificates
    (282 fast, 6 slow), 7,419 of 7,419 transactions, against sets of 481 and
    21 validators taken from `getVatActiveSetRankMap`.
  - No block in any of the three was refused.

- **Validator-set logs** (`crates/solana-thin-setlog/tests`). Records and
  logs round-trip; every refusal has a test (a broken link, too few
  signatures, two sets for one epoch, an epoch that goes backward, a change
  of cluster, sources that disagree, members that are not the accounts the
  admitting block debited); and changing any byte of a log file,
  each of several ways, leaves a file that does not verify. The `setlog`
  binary is run end to end, against local stand-ins for RPC nodes.
  By hand on 2026-11-25, with the tools as committed: on mainnet, snapshots
  from three nodes on three networks, at slots 473,895,632 and 473,895,832,
  gave identical sets for epochs 1093 to 1097, and for 1095 and 1096 the
  hashes pinned in `tests/mainnet_block.rs` and `tests/mainnet_snapshot.rs`;
  each download stopped after 68 to 71 MB. On testnet two RPC nodes and one
  node's snapshot gave one set of 481 validators for epoch 1099.

- **The prover** (`crates/solana-thin-prover/tests`,
  [docs/PROVER.md](docs/PROVER.md)). In `cargo test`, with no network:
  validators on loopback serve testkit blocks over the repair protocol, and
  the prover is driven through fetch, prove, serve and the verifier against
  honest ones and against ones that send wrong shreds, answers for another
  block, a parent the block does not commit to, every answer twice, or
  nothing; that serve an abandoned block by slot; and that carry a
  certificate the set did not sign. Every refusal has a test, and the
  binary is run end to end against a local stand-in for an RPC node.
  By hand on 2026-11-25, with the code as committed:
  - A local validator (Agave 4.4.1): 24 of 24 transactions served by
    `prover serve` and verified in a separate process that holds the proof,
    the set file and nothing else.
  - Mainnet, epoch 1097: 20 of 20 randomly chosen slots fetched by certified
    block id, 20 of 20 certificates verified, 10,213 of 10,213 transactions
    proven and verified, a median 687 requests and 4.0 s for a block's
    shreds, nothing refused. Five signatures from those blocks proven by
    `prover prove` from the RPC node's slot hint, 5 to 8 s each from a cold
    start.

- **Other platforms** ([docs/BINDINGS.md](docs/BINDINGS.md)). CI verifies a
  mainnet proof in a `wasm32-unknown-unknown` module under node, runs the
  test suite as a WASI program, and verifies the same proof from Kotlin on
  the JVM through the generated binding. By hand: the test suite passes on
  arm64 Linux under emulation and on arm64 macOS (but for the one test that
  needs Python 3.11, which that machine lacked). On an iPhone 17 Pro the
  Swift binding verified the proofs of all 331 transactions of a mainnet
  block, a median 0.82 ms each once the 666-validator set was pinned (21 ms).
  Elsewhere: about 1 ms natively and 7 ms in wasm, with the set loaded in
  about 30 ms and 170 ms.

What is not tested: a block whose leader switched parent (no public cluster
produces one), and a run on an Android phone.

## Using it

```toml
[dependencies]
solana-thin = { git = "https://github.com/dannycake/solana-thin" }
```

Verifier (phone, browser, server): `ThinClient`. Dependencies are `blst` and
`sha2`. No async, no network, no `unsafe`.

Cargo features, all off by default:

| Feature | What it changes |
|---|---|
| `no-threads` | `blst` checks signatures on the calling thread. Without it, `blst` starts a thread pool the first time a signature is checked. Turn it on for a phone or an embedded host. Targets without threads, such as `wasm32-unknown-unknown`, get it without asking. |
| `portable` | `blst` chooses its instructions when it runs, not when it is built. Without it, an x86-64 build uses ADX if the build machine has it and stops with an illegal instruction on a CPU that does not. Turn it on for a binary built on one machine and run on another. |
| `testkit` | Deterministic block and validator builders for tests and examples. |

From Kotlin, Swift or JavaScript: [docs/BINDINGS.md](docs/BINDINGS.md). A
`Verifier` object takes a validator set and its pinned hash for an epoch,
then proof bytes, and answers with a record or a typed error. It is built
from this repository; nothing is published to Maven, the Swift package
index or npm.

Prover (wherever shreds are):

```rust
use solana_thin::prover::{self, BlockData};

let block = BlockData::from_shreds(&data_shred_payloads)?; // 1,203 bytes each
let cert = block_after.footer().unwrap().1.finality.unwrap(); // or from gossip
let proof = prover::prove(cert, &[&certified_block, &block], &signature, true)?;
send(proof.to_bytes()?);
```

Run the worked example:

```
cargo run --example anchor --features testkit
```

`examples/verify_ledger.rs` runs the same pipeline on a real ledger.

To get proofs for transactions on a live cluster, run the prover
([docs/PROVER.md](docs/PROVER.md)):

```
cargo run --release -p solana-thin-prover -- serve --rpc <url> \
    --set <set file> --listen 127.0.0.1:8080
curl -o tx.proof http://127.0.0.1:8080/proof/<signature>
```

Where the pinned hash comes from is [docs/SETS.md](docs/SETS.md): a log of
signed records, checked with `solana-thin-setlog` (Ed25519, SHA-256 and JSON;
no network, and no dependency of the verifier on it).

## Layout

```
crates/solana-thin/src
  client.rs         ThinClient: what is trusted, and the verification steps
  certificate.rs    vote payloads, signer bitmaps, thresholds
  validator_set.rs  ranking, set hash, BLS checks
  merkle.rs         the double-Merkle block id
  shred.rs          data shred layout and compact form
  block.rs          headers, footers, entry batches
  transaction.rs    legacy, v0 and v1 wire formats
  proof.rs          TxProof and its encoding
  prover.rs         building proofs from data shreds
  error.rs          every refusal, and the kinds an app sorts them into
crates/solana-thin-ffi   the binding for Kotlin and Swift (UniFFI), with the
                         interface it exports and a Kotlin smoke test
crates/solana-thin-wasm  the verifier as a WebAssembly module with no imports,
                         and a JavaScript class around it
crates/uniffi-bindgen    the binding generator, and `describe-interface`
crates/solana-thin-setlog
  src/record.rs     a record: its bytes, hash, signatures and line of JSON
  src/log.rs        verifying a log; what to pin per epoch
  src/set_file.rs   a set with its cluster and epoch; agreement of sources
  src/rpc.rs        JSON-RPC through the system's `curl` (feature `rpc`),
                    shared by the tools that read from a cluster
  src/bin/setlog    the `setlog` tool (feature `cli`): from-rank-map, agree,
                    sign, append, verify, show
  examples/pin_from_log.rs   a client's side: verify a log, pin the set
crates/solana-thin-prover
  src/wire.rs       the repair protocol's packets, both directions
  src/peers.rs      whom to ask, from getClusterNodes, and who answers
  src/net.rs        one paced UDP socket and a key made at start
  src/fetch.rs      a block by its certified id; footers by slot
  src/prove.rs      from a signature and a slot hint to a verified proof
  src/store.rs      a bounded directory of blocks, proofs, certificates
  src/trust.rs      the verifier and the sets it is pinned to
  src/serve.rs      GET /proof, /finality, /set, /health
  src/refusal.rs    every reason for not producing a proof
  src/bin/prover    the `prover` tool: fetch, prove, serve
  examples/verify_proof.rs   a client's side: check a served proof
tools/agave-fixtures     everything that links Agave: conformance vectors,
                         the differential oracle (`diff-fuzz`), `ledger-dump`,
                         `cluster-run`, and `snapshot-stakes`, which reads
                         validator sets from the snapshots nodes serve
tools/shred-fixtures     runs the public shred conformance fixtures
tools/fetch_vote_accounts.py   builds a candidate set from any RPC node
                         (not exact; see `setlog` for sets to pin)
fuzz/                    fuzz targets, two against the validator's parsers
scripts/nightly.sh       the heavy checks: oracle, fuzzers, fixtures, tripwire
scripts/bindings.sh      holds the bindings to the library: the exported
                         interface, generation, the Kotlin smoke test
scripts/wasm.sh          builds the module and verifies a mainnet proof in node
scripts/wasi-test.sh     runs the verifier's tests as a WASI program
scripts/tripwire.py      fails when Agave or mainnet moves under the ledger
scripts/conformance.py   writes docs/CONFORMANCE.md from docs/conformance.toml
docs/DESIGN.md           formats, threat model, open problems
docs/SETS.md             producing and checking a validator-set log, and what
                         a signature on one is worth
docs/PROVER.md           running the prover, what it trusts, what it
                         costs, and what it is not
docs/CONFORMANCE.md      every validator check, and what the verifier does
docs/LOCAL-VALIDATOR.md  the test against a running validator
docs/BINDINGS.md         Android, iOS and WebAssembly: building, calling,
                         cost, and what was run where
docs/NOTES.md            working notes: evidence, sources, decisions, next steps
```

## Roadmap

Mainnet works: shreds come from any validator over the repair protocol, and
the certificates and transactions in them verify. What is missing is the
software around that.

1. **Signers for the set log.** The tool exists: it reads the exact set
   from snapshots served by several nodes and from the rank-map RPC, refuses
   when they disagree, checks each set's members against the admission debits
   in the epoch's first block, and writes a signed, hash-chained record per
   epoch that a client checks before pinning ([docs/SETS.md](docs/SETS.md)).
   What is missing is mostly not software. A log is worth what its signers
   are: it needs several, independent of each other, who each read the set
   themselves every epoch, and a published place for the file. The one code
   path not yet exercised on real data is the shared-key rank map, which no
   mainnet epoch seen so far has needed.
2. **A prover people run.** The node exists
   ([docs/PROVER.md](docs/PROVER.md)): it finds a block's certificate, fetches
   the block from validators by its certified id, and serves
   `GET /proof/<signature>`, a mainnet block in a median four seconds at a
   polite request rate. What is missing is operation: provers run by several
   parties so that a client can ask more than one, a soak longer than an
   afternoon, an epoch boundary crossed live with both sets, and a way to
   keep proofs for longer than validators keep blocks, which today means
   asking while the block is hours old.
3. **Bindings that ship.** The binding crate for Kotlin and Swift and the
   WebAssembly module exist and are checked in CI
   ([docs/BINDINGS.md](docs/BINDINGS.md)). Still to do: a run on a physical
   phone, the Swift side compiled and tested in CI, and packages an app can
   depend on (an Android archive, a Swift package, an npm module).
4. **Review by someone who works on a validator**, and the open items in
   [docs/NOTES.md](docs/NOTES.md).

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and change the
verifier. If you find an input the verifier accepts and should not, please
report it privately: [SECURITY.md](SECURITY.md).

## License

Apache-2.0 ([LICENSE](LICENSE)).
