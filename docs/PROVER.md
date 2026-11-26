# The prover

`solana-thin` checks a proof that a transaction is in a finalized block, and
builds one from the block's data shreds and a finality certificate. Public
RPC serves neither. Validators serve shreds to anyone who asks over the
repair protocol, and every block's footer carries a finality certificate
for a recent block.

`crates/solana-thin-prover` is the node that asks. It has a library and one
binary, `prover`, with three commands:

```sh
# The finalized blocks of some slots, fetched and kept.
prover fetch --rpc <url> --set <set file> 473913557 473915909

# One proof, written to a file. The RPC node says which slot to look in.
prover prove --rpc <url> --set <set file> <signature>

# Proofs over HTTP.
prover serve --rpc <url> --set <set file> --listen 127.0.0.1:8080
```

It is not a validator and holds no stake. It needs an RPC node of the
cluster, the validator set of each epoch it will verify (`docs/SETS.md`),
outbound UDP, and `curl` on the path.

## Running it

| Option | Meaning |
|---|---|
| `--rpc <url>` | An RPC node. Asked for the cluster's nodes (`getClusterNodes`), its epoch schedule, and the slot a signature landed in (`getSignatureStatuses`). |
| `--set <file>` | A set file, as `setlog` writes it. Repeat for each epoch. |
| `--log <file> --signer <key> ... --threshold <N>` | Take each set's hash from a verified set log. Without a log a set file is pinned by its own hash: the operator is trusting the file. |
| `--shred-version <N>` | Refuse to start unless the set files are for this shred version. They name it themselves, and the prover refuses to start if the cluster's nodes are on another. |
| `--slots-per-epoch <N>`, `--warmup` | The epoch schedule of a cluster that is not mainnet-beta, testnet or devnet. A test validator is `--slots-per-epoch 432000`. The RPC node's schedule must agree. |
| `--store <dir>`, `--store-cap-mb <N>` | Where blocks and proofs are kept, and how large that may grow. Default `prover-store`, 1,024 MB. |
| `--rate <N>` | Requests a second to validators, all peers together. Default 300, at most 1,000. |
| `--bind <addr>` | The UDP address to ask from. Default `0.0.0.0:0`. |
| `fetch --prove-all` | Also build and verify a proof for every transaction of each block. Nothing is kept of them; it is for measuring. |
| `prove --slot <N>`, `--out <file>` | A slot hint in place of the RPC node's; where the proof goes (default `<signature>.proof`). |
| `serve --listen <addr>`, `--workers <N>` | Where to listen, and how many threads answer (default 8). |

**Around an epoch boundary it needs both epochs' sets.** The first blocks of
an epoch carry certificates for the last blocks of the one before. If a
certificate cannot be checked for want of a set, the prover says which:

```
no validator set is pinned for epoch 1096, which the certificate for slot
473903999 needs (pinned: 1097); pass that epoch's set file
```

It looks further first. A later footer may certify a later block under a set
that is pinned, and a block is as final by a certificate for its descendant.
So the newer epoch's set alone reaches back across the boundary, and the
older one alone does not reach forward.

## The HTTP interface

| Request | Answer |
|---|---|
| `GET /proof/<signature>` | `200` and the proof (`application/octet-stream`). `404` and a line of text saying why it cannot be built. `503` when it could not be built just now: peers went quiet, the queue is full, or it is still being fetched. Ask again. |
| `GET /proof/<signature>?slot=N` | The same, with the caller's slot hint in place of the RPC node's. |
| `GET /finality/<slot>` | `200` and the certificate for that slot's block, if one is held: a kind byte (0 fast, 1 slow), the slot, the block id, then each aggregate as a 96-byte signature, a `u16` length and the signer bitmap. The same bytes as at the front of a proof; `solana_thin::FinalityCert::from_bytes` reads them. `404` otherwise. |
| `GET /set/<epoch>` | `200` and the set file that epoch is verified with (`application/json`). `404` otherwise. |
| `GET /health` | `200` and a JSON object: cluster, shred version, pinned epochs, peers known and answering, requests sent, proofs built and refused, what the store holds. |

A signature is base58, as explorers and the `solana` CLI print it.

One thread accepts connections, a fixed number answer them, and one owns the
socket to the validators and builds proofs one at a time from a bounded
queue. A connection has five seconds to send a request of at most 2 KB and
is closed after one answer; there is no keep-alive. A client that stalls
holds one answering thread until its timeout. It cannot hold the fetching
thread, which never touches a client's socket. When every thread is busy and
64 connections wait, new ones are closed unanswered.

A client checks what it gets. `examples/verify_proof.rs` is that side:

```sh
curl -o tx.proof http://127.0.0.1:8080/proof/<signature>
cargo run -p solana-thin-prover --example verify_proof -- \
    <set file> <signature> tx.proof
```

## How a proof comes about

1. **A hint.** The caller, or the RPC node, names the slot the transaction
   landed in.
2. **A certificate.** The prover reads the footers of the next slots, up to
   twelve, *by slot*: it asks a few peers for the slot's last shred, then one
   of them for the last FEC sets, and parses the footer out. On mainnet the
   footer is the next-to-last component, so this is about 70 requests. A
   footer read this way proves nothing; a peer can serve a block the
   cluster abandoned, or invent one. The certificate inside is verified with
   the pinned set before anything is built on it, and one that fails is
   skipped.
3. **A block id.** The first verified certificate for the hinted slot or a
   later one gives a certified id. If it is for a later block, the prover
   follows parent links down from it (`ParentAndFecSetCount`, one request a
   block), each checked against the id above. The hinted slot is in the
   finalized chain only if a link lands on it.
4. **The shreds, by id.** `FecSetRoot` for each FEC set and
   `WindowIndexForBlockId` for each shred, spread over the peers that showed
   they hold the block. Every answer is checked against the certified id as
   it arrives: a root by its Merkle path, a shred by its own path to its
   set's root. What fails is dropped and asked for again elsewhere; a peer
   that fails three times, or never answers, is no longer asked.
5. **The proof.** Built by `solana_thin::prover` from the block's shreds, the
   certificate and the parent links, then decoded from its bytes and verified
   by the same `ThinClient` a client would use, under the same limits. Only
   then is it kept and returned.

Blocks between the certified one and the transaction's are never fetched: a
proof needs only their parent links.

## What it trusts, and what it does not

**Trusted: the pinned validator sets.** Nothing else.

- *The RPC node.* Its node list decides whom to ask. Its slot is a hint.
  Wrong answers to either cost time: a hint that names another block ends in
  "the transaction is not in the block of slot N", and nothing is kept under
  the signature.
- *The validators.* Shreds are only fetched by an id that a verified
  certificate, or a parent link under one, names. A block fetched by slot
  alone is never kept.
- *The store directory.* A proof read back is verified again before it is
  served, and a block read back is hashed again and its anchor checked. A
  planted or damaged file costs a fetch.
- *Itself, as far as a client is concerned.* A client verifies the proof
  with its own pinned set. A prover with a wrong set serves proofs that
  clients with the right one refuse.

It signs repair requests with an Ed25519 key made when it starts and never
written anywhere. Validators answer any key.

## The store

```
<dir>/blocks/<slot>.block       a certified block: its anchor and shreds
<dir>/proofs/<signature>.proof  a proof that was built and verified
<dir>/certs/<slot>.cert         a verified certificate, by certified slot
```

A block's shreds are kept so that the next proof from the same block costs
no fetch. When the directory passes its cap, the oldest blocks go first and
the proofs built from them stay. Proofs and certificates may take half the
cap; past that the oldest of those go too. A mainnet block is about 0.9 MB
on disk and a proof about 20 KB, so the default cap holds about a thousand
blocks, and the half of it that proofs may take about 25,000 of them.

## Being a guest

The prover is an unstaked stranger on a network that owes it nothing.

- One pacer for everything it sends: 300 requests a second by default.
- A block's requests are spread over eight holders. Peers already heard from
  take turns, and until 64 are known each block is also asked of two that
  are not.
- A peer that never answers is dropped after eight requests.
- After 400 requests in a row with no packet from any peer, it stops asking
  for a minute and answers `503` in the meantime.
- Nodes on releases that never answer (Agave before 4.3) are not asked.
- It fetches on demand and nothing else. Idle, it sends nothing.

## What it costs

Measured on 2026-11-25 with the code as committed.

**Mainnet**, epoch 1097, twenty slots chosen at random from the epoch's
first 12,000, with `fetch --prove-all` at the default rate:

| | |
|---|---|
| Blocks fetched by certified id | 20 of 20, none refused |
| Certificates verified | 20 of 20, all fast: 17 from the next slot's footer, 3 from the one after; 19 for the block itself, 1 for its child |
| Transactions proven and verified | 10,213 of 10,213 |
| Requests for a block's shreds | 439 to 1,328, median 687 |
| Time for a block's shreds | 2.7 to 6.9 s, median 4.0 s |
| Finding a block's certificate | 81 requests on average |
| Everything, per block | 860 requests, 160 KB sent, 1.0 MB received |
| Pieces asked for twice | 44 of 15,345; no answer failed its check, none came twice |
| Peers that answered | 64 of 2,939 that could be asked |
| Proof size | 3.1 to 65.0 KB |

Five signatures taken from those blocks through `prover prove`, each a new
process with an empty store and the hint from the RPC node: 5.2 to 7.5
seconds from start to a proof on disk, 5.4 to 32.3 KB, each then verified by
`verify_proof` in a process of its own.

**A local validator** (`solana-test-validator --alpenglow`, Agave 4.4.1): 24
memo transfers in 24 blocks, each asked of `prover serve` over HTTP and
verified in a separate process holding the proof, the set file and nothing
else. 24 of 24, about one second each, 199 requests a proof, 1,992 bytes a
proof.

**How long a block stays fetchable** was measured before the prover existed,
by asking mainnet validators for slots of known age (`docs/NOTES.md`). It is
a slope, not a cliff:

| Age of the slot | Validators that still hold it |
|---|---|
| 2 hours | 95% |
| 4 to 9 hours | about 40% |
| 22 hours | 17% |
| 36 hours | 3% |

The prover asks up to 32 peers whether they hold a block before it gives
up. By these figures a day-old block is nearly always found, from fewer
holders and so more slowly, and a block of a day and a half about two times
in three. That is arithmetic, not a measurement: the prover's own live runs
fetched blocks under an hour old.

## Limits

These are stated, not solved.

- **It proves recent transactions on demand.** A proof can be built while
  validators still hold the block, which is hours for most of them and a day
  or two for a few. After that only a proof that was already built and kept
  can be served.
- **It is not an archive or a mirror.** It keeps what it was asked for, up
  to a cap, and drops the oldest. It does not follow the chain.
- **Unstaked clients are served last.** A validator under load answers
  staked peers first and sheds the rest, and a leader serves less while it
  leads. The prover retries elsewhere and then says `503`. It never
  escalates.
- **One block at a time.** Proofs are built in turn. A burst of requests
  for different blocks waits in a queue of 32 and is refused beyond that.
- **The slot hint comes from somewhere.** Without `?slot=`, the RPC node
  must still know the signature. Public nodes forget old transactions.
- **A certificate must show up within twelve slots.** In every block
  measured it was in the next slot or the one after, and up to five slots
  later across a skipped leader turn.
- **Blocks the verifier refuses stay refused.** A block whose leader
  switched parent, or whose parent id is all zeros, is fetched, found
  unprovable and not kept (`README.md`, limit 6).
- **`curl` is a dependency.** RPC calls are made by running it, which keeps
  a TLS stack out of the build. A lookup costs a process.
- **No signal handling, no TLS, no authentication.** Put it behind something
  that has them.
