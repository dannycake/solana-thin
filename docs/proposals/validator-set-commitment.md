# A footer commitment for the next epoch's validator set

*A light-client trust-root proposal for Solana after Alpenglow. Draft for the
Solana developer forum / a SIMD discussion; written from the `solana-thin`
light client's point of view.*

## Summary

Alpenglow gave a light client two things it never had: a succinct proof that a
block is final (the finality certificate) and a succinct proof that a
transaction is in a block (the double-Merkle block id the certificate signs). A
light client can now answer "is my transaction in a finalized block?" from a few
tens of kilobytes, with no node and no replay.

One trusted input remains, and it is the whole trust root: **the validator set**.
To check a certificate, the client needs that epoch's ranked list of
`(BLS key, stake)`. Nothing on chain commits to that list in a form a small
proof can open, so the client must take the set — or, at best, its 32-byte hash
— from an out-of-band source it trusts. Every other part of the pipeline is
cryptographic; this one is social.

This proposal asks for the smallest change that removes it: **commit the hash of
epoch `E+1`'s ranked `(BLS key, stake)` list in a block footer during epoch `E`.**
Footers are already inside the block id a certificate signs, so the commitment
is cert-verified for free, and a light client needs no new proof machinery — it
reads the hash from a footer it already parses and verifies.

## The problem, precisely

A `ThinClient` trusts exactly one thing per epoch: the hash of that epoch's
ranked validator set. It verifies a finality certificate by checking a BLS
aggregate signature against that set, in rank order, for a stake threshold. A
set with the right keys in the right order but the wrong stakes still verifies a
certificate, so the set — stakes included — must be authentic, not merely
well-formed.

Today the client obtains that 32-byte hash from people: operators read the set
from the cluster (from a bank snapshot, from the `getVatActiveSetRankMap` RPC on
Agave 4.5, cross-checked against the admission debits in the epoch's first
block), agree on a hash, and sign it into a hash-chained log. A client pins the
log's signer keys and a threshold. This *moves* trust — from "whoever handed me
this hash" to "a quorum of named readers each did the reading honestly" — but it
does not *remove* it. It is the last trusted input, and it is the one a
protocol change could eliminate.

## Why the bank hash cannot carry it

It is natural to ask whether the client can derive the set from state it already
verifies. When a proof opens a block's footer, the client holds a **bank hash
that the certificate transitively commits to**: the certificate signs the block
id, the block id is the Merkle root over the block's shreds, and the footer —
which carries `bank_hash` — is a component inside those shreds. So a light client
already has, for free, a Byzantine-secure bank hash for every block it verifies.

That is not enough, because of what the bank hash commits to. Since SIMD-0215
(the accounts lattice hash, `accounts_lt_hash`), Agave computes the bank hash
over a **homomorphic hash of account state** — an `LtHash` that is, in effect, a
sum of per-account hashes (`agave/runtime/src/bank.rs`, `hash_internal_state`;
feature `accounts_lt_hash`, "SIMD-0215: enables lattice-based accounts hash").
A homomorphic sum has **no single-account inclusion proof**: you cannot show that
one account is a term of the sum without knowing every other term. The earlier
accounts-*delta* hash was a Merkle tree over the accounts a slot modified, and it
*did* admit an inclusion proof for a modified account — but it is gone.

So **no account can be opened against the bank hash a light client holds.** This
is the gap SIMD-0676 runs into: putting the ranked set in an account under the
bank hash does not make it openable by a light client, because the bank hash's
accounts commitment is a lattice hash. SIMD-0676 is necessary (the set should be
on chain) but not sufficient (a light client still cannot read one account from
it). Adding an accounts-Merkle commitment alongside the lattice hash — a receipts
-root-style change (cf. SIMD-0052, SIMD-0064) — would reintroduce an openable
state commitment, but it is a large change whose only light-client use here is
this one list.

## The proposal

Commit, in a block footer during epoch `E`, the 32-byte hash

```
set_commitment(E+1) = H( canonical_encoding( ranked (BLS key, stake) list for E+1 ) )
```

where the ranked list is the same one Alpenglow already defines for certificate
verification: the epoch's admitted validators, ordered by stake descending then
by compressed BLS key ascending, each as `(48-byte compressed BLS key, u64 stake)`,
with a domain-separated hash over the count and the entries. (The exact encoding
is a spec detail; `solana-thin` uses `H("…/validator-set/v1" ‖ count ‖ (key‖stake)*)`.)

The leader can produce this during `E`: `E+1`'s stakes are frozen before `E+1`
begins (the same snapshot that fixes `E+1`'s leader schedule), so the ranked
list is known while `E`'s blocks are produced. The commitment needs to appear in
at least one finalized block of `E` whose footer a light client can obtain —
putting it in every footer of `E` (or every footer of the epoch's first leader
window) is simplest and costs 32 bytes per footer.

## What a light client does with it

Nothing new. The client already parses and cert-verifies footers. The flow
becomes:

1. Verify any finalized block of epoch `E` as usual; its footer carries
   `set_commitment(E+1)`, now cert-verified.
2. Pin `set_commitment(E+1)` as the trusted hash for epoch `E+1` (the existing
   `trust_validator_set_bytes(epoch, set_bytes, pinned_hash)` entry point — the
   hash now comes from the chain instead of a signed log).
3. When the client later obtains `E+1`'s set from any untrusted source, it
   accepts it only if its hash equals the pinned commitment.

One genesis pin bootstraps the chain; from there the set follows the chain with
one small proof per epoch and no trusted reader. The signed log, the quorum of
operators, and the "a certificate does not vouch for stake" caveat all go away.

## Cost and alternatives

- **Cost:** 32 bytes per footer, once per epoch of new information. No new proof
  system; the commitment rides on the footer, which is already covered by the
  block id. The leader already computes `E+1`'s ranked set for the leader
  schedule.
- **vs. SIMD-0676 (set in an account under the bank hash):** unopenable by a
  light client while the bank hash uses the accounts lattice hash. This proposal
  can be read as *how* SIMD-0676's on-chain set should be committed for light
  clients: in the footer, not (only) in an account.
- **vs. an accounts-Merkle / receipts-root commitment:** larger, and it would
  exist only to open this one list; the footer commitment targets exactly the
  bytes a light client needs.
- **vs. the status quo (a signed log):** the log works and is deployed, but it is
  social trust; this removes it.

## Relationship to existing work

- **SIMD-0676** (epoch stakes on chain) motivates putting the set on chain; this
  proposal supplies the light-client-openable commitment it is missing.
- **SIMD-0215** (accounts lattice hash) is the reason the account route does not
  work and the footer route is needed.
- The footer already carries the finality certificate for an earlier block and
  the bank hash; a 32-byte set commitment is a natural third field.

A reference light client that would consume this exists today and pins the set
hash by hand: [`solana-thin`](https://github.com/dannycake/solana-thin). With
this commitment, its `solana-thin-setlog` crate — a signed log of set hashes —
becomes unnecessary.
