# solana-thin

A thin client for Solana after Alpenglow. Hand it a few kilobytes of proof from
anyone, and it tells you whether your transaction is in a block the validators
finalized. No node, no replay, no trusted server.

```rust
use solana_thin::{ClusterParams, Limits, ThinClient, TxProof};

// Trust: the cluster's shred version and the hash of this epoch's validator set.
let mut client = ThinClient::new(ClusterParams::mainnet(50093));
client.trust_validator_set(epoch, validator_set, &pinned_hash)?;

// Proof: bytes from a relay, a friend's phone, a public server. Untrusted.
let proof = TxProof::from_bytes(&proof_bytes, &Limits::default())?;
let verified = client.verify_signature(&proof, &my_signature)?;

println!("final in slot {}", verified.block.slot);
```

Status: **v0.1, unaudited.** The verifier agrees with Agave v4.4.1 on every
test vector (see [Tests](#tests)). It has not yet verified a live mainnet
certificate, because public RPC does not serve them (see
[Limits](#limits-and-how-the-design-works-around-them)). Do not put money
behind it until someone other than its author has reviewed it.

## What changed, and what this adds

Before Alpenglow, validators voted with ordinary transactions. Checking that a
block was final meant fetching hundreds of vote transactions and knowing every
validator's stake, which is most of a full node's work.

Alpenglow went live on mainnet on October 21, 2026. Votes are now BLS
signatures, and enough of them fold into one **finality certificate**: an
aggregate signature plus a bitmap of who signed, about 200 bytes for today's
684 validators. That is the first half of a light client: *is this block
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

Measured proof sizes from the test suite: **1.9 KB** for a transaction in a
small batch; up to the size of the batch (about 50 KB in the test) for the
last transaction of a batch that spans two FEC sets. The validator set itself
is 38 KB per epoch (56 bytes per validator).

## What a successful check means

All of this held:

1. Validators holding at least 80% of the pinned stake signed the block, or 60%
   signed it and 60% signed to finalize its slot, on this cluster.
2. The transaction's bytes hash up to that block's id, or to an ancestor's.
3. Those bytes sit where a validator reads a transaction, in a part of the
   block that was executed.

What it does **not** mean:

- **That the transaction succeeded.** A transaction whose program returned an
  error is still included and still pays its fee. Nothing a block commits to
  records the difference in a form a small proof can open.
- **Anything about account state.** Solana's state commitment (the accounts
  lattice hash, [SIMD-0215](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0215-accounts-lattice-hash.md))
  cannot prove that an account is or is not included.
- **That your validator set is the right one.** That is your trust root.

## Limits, and how the design works around them

**1. Nothing on chain commits to the validator set.** This is the largest gap.
A light client on other chains follows validator-set changes with signed
handovers; Solana has no such commitment that a small proof can open.

- *Design:* a validator set is identified by a hash, and the client uses only
  sets whose hash you pinned. `tools/fetch_vote_accounts.py` builds the set
  from any RPC node; run it against several independent providers and compare
  hashes. The set for epoch `E + 1` is already fixed and readable throughout
  epoch `E`, so there is a full epoch (about a day) to fetch it.
- *Bridge:* `StalePolicy` (off by default) checks a certificate from a later
  epoch against an older pinned set. It counts only signers it already trusts,
  at the stake it already knows, and raises every threshold by a margin per
  epoch of distance. New keys must prove possession and carry no weight. This
  rests on an assumption about how fast stake moves; read its docs first.
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
neither shreds nor block footers, so today a proof has to be built by something
that keeps a slot's data shreds: a validator, an RPC node, a Geyser plugin.

- *Design:* the prover (`solana_thin::prover`) is a library with no trust and
  no keys. It takes the data shreds exactly as a node stores them and nothing
  else. Anyone can run one; a client can ask several.

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
handover a leader may abandon the first part of its block; that part is in the
finalized bytes but was never executed. v0.1 detects such blocks and refuses
to prove anything in them rather than work out which part ran.

## Attacks this is built to refuse

Each has a test in [`tests/attacks.rs`](crates/solana-thin/tests/attacks.rs)
that builds the attack and checks the reason it is rejected.

| Attack | Why it works on a careless client | Rejected as |
|---|---|---|
| Embedded transaction | Your signed transaction's bytes are placed inside another transaction's data. They are in the block, correctly Merkle-proven, and never ran. | `NotComponentStart` |
| Abandoned prefix | A transaction sits in the part of a block the leader discarded. | `UpdateParentBlock` |
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

`cargo test` runs 76 tests in about half a minute.

- **Conformance with Agave** (`tests/conformance.rs`). Vectors are generated by
  [`tools/agave-fixtures`](tools/agave-fixtures), which links Agave v4.4.1.
  Blocks are serialized and shredded by Agave, real coding shreds included, and
  their ids read back from an Agave blockstore. This crate computes the same
  block ids, reaches the same verdict as Agave's certificate verifier on 13
  certificates (5 valid, 8 invalid), ranks validators the same way, verifies
  the vote program's proofs of possession, and proves and parses 254
  Agave-written transactions (legacy, v0, v1, multi-signer) identically.
- **Attacks** (`tests/attacks.rs`), 20 tests, as listed above. One flips every
  bit of a valid proof in turn and checks that each mutant is either rejected
  or still true.
- **Live mainnet keys** (`tests/mainnet_snapshot.rs`). All 684 BLS keys the
  public RPC reported in epoch 1095 decode, pass subgroup checks and rank.
- **Shapes** (`tests/properties.rs`). Random blocks, and batches sized exactly
  on, one under and one over shred and FEC set boundaries.

What is not tested: a certificate signed by mainnet's validators. Until an RPC
or Geyser source for footers is wired up, the certificate path is checked
against Agave's code, not against the live network.

## Using it

```toml
[dependencies]
solana-thin = { git = "https://github.com/dannycake/solana-thin" }
```

Verifier (phone, browser, embedded): `ThinClient`. Dependencies are `blst` and
`sha2`. No async, no network, no `unsafe`.

Prover (wherever shreds are):

```rust
use solana_thin::prover::{self, BlockData};

let block = BlockData::from_shreds(&data_shred_payloads)?; // 1,203 bytes each
let cert = block_after.footer().unwrap().1.finality.unwrap(); // or from gossip
let proof = prover::prove(cert, &[&certified_block, &block], &signature, true)?;
send(proof.to_bytes());
```

Run the worked example:

```
cargo run --example anchor --features testkit
```

## Layout

```
crates/solana-thin/src
  client.rs         ThinClient: what is trusted, and the verification steps
  certificate.rs    vote payloads, signer bitmaps, thresholds
  validator_set.rs  ranking, set hash, BLS checks, stale-set mode
  merkle.rs         the double-Merkle block id
  shred.rs          data shred layout and compact form
  block.rs          headers, footers, entry batches
  transaction.rs    legacy, v0 and v1 wire formats
  proof.rs          TxProof and its encoding
  prover.rs         building proofs from data shreds
tools/agave-fixtures     generates conformance vectors with Agave itself
tools/fetch_vote_accounts.py   builds a validator set from any RPC node
docs/DESIGN.md           formats, threat model, open problems
```

## License

MIT or Apache-2.0, at your option.

## Next step: test against a running validator

Not done yet. The certificate path has been checked against Agave's libraries,
not against a validator that is actually running.

1. Install Agave v4.4.x and run `solana-test-validator` for a minute, sending a
   few Memo transactions.
2. Read each slot's data shreds from its ledger (Agave's `Blockstore`, as
   `tools/agave-fixtures` already does, or a Geyser plugin).
3. Build the validator set from the test validator's vote account, take a
   finality certificate from a later block's footer, and run
   `prover::prove` then `ThinClient::verify_signature`.

A test validator has one signer, so this checks formats and the pipeline end
to end. Checking mainnet needs shreds from an RPC node or a shred stream.
