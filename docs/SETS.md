# Validator-set logs

The verifier trusts one thing per epoch: the hash of that epoch's ranked
validator set. Nothing on chain commits to it in a form a small proof can
open ([DESIGN.md](DESIGN.md#validator-sets)), so the hash has to come from
people who read the set from the cluster and say what they found.

A *set log* is how they say it: one signed record per epoch, each naming the
record before it. `crates/solana-thin-setlog` is the format and the check a
client runs; its `setlog` binary and `snapshot-stakes` in
`tools/agave-fixtures` produce the records.

## What a record says

| Field | Meaning |
|---|---|
| `cluster` | A name: `mainnet-beta`, `testnet`, `devnet` |
| `shred_version` | The cluster's shred version when the record was made |
| `epoch` | The epoch whose certificates the set verifies |
| `set_hash` | `ValidatorSet::hash` of that set |
| `validators` | How many validators it ranks |
| `sources` | Where the set was read: a kind, a label, the slot it reflects. One of kind `admission` says the set's members were checked, and against which block ([below](#the-admission-check)) |
| `prev` | SHA-256 of the previous record's bytes; zeros in the first |

The bytes that are hashed and signed:

```
"solana-thin/set-record/v1"                 25 bytes
cluster        len:u8, bytes                lowercase letters, digits, '-'
shred_version  u16
epoch          u64
set_hash       32 bytes
validators     u32
prev           32 bytes
sources        count:u8, then for each, ascending by kind then label:
    kind       len:u8, bytes                "snapshot", "rank-map", "admission"
    label      len:u8, bytes                printable ASCII, no spaces
    slot       u64
```

Integers are little-endian. A signature is Ed25519 over these bytes. The
record's hash does not cover signatures, so a co-signer adding theirs moves
no link.

A log is a text file with one record per line, as JSON, with its
signatures. Each line has exactly one spelling, and `parse` refuses any
other, so no byte of a log can change without the line being refused or its
signatures failing. Publishing a log is copying the file.

A cluster restart changes the shred version and not the set. It appears as
one more record for the same epoch, with the same hash and the new version.

## Producing a record

Each signer does steps 1 to 3 on their own machine, from sources they chose.

**1. Read the set.** Two kinds of source give the exact set
([DESIGN.md](DESIGN.md#validator-sets) says why `getVoteAccounts` does not).

From bank snapshots, on any cluster running Agave 4.4 or later. This links
Agave, so it lives with the other tools that do:

```sh
cd tools/agave-fixtures
cargo run --release --bin snapshot-stakes -- \
    --cluster mainnet-beta --rpc https://api.mainnet-beta.solana.com --out extracts
```

It finds nodes that serve snapshots, reads the first 70 MB or so of the
newest incremental snapshot from three of them on different networks, and
writes one extract per node. An extract holds the epoch-stakes maps of the
epochs from three back to one ahead.

From the rank-map RPC, where nodes run Agave 4.5:

```sh
setlog from-rank-map --cluster testnet --epoch 1099 --quorum 2 \
    --url https://api.testnet.solana.com --url https://another.example \
    --set set-1099.json --record record-1099.json --log testnet.jsonl
```

(`setlog` is `cargo run -p solana-thin-setlog --features cli --`.)

**2. Check that the sources agree.** `from-rank-map` does this itself. For
extracts, and to combine sources of both kinds:

```sh
setlog agree --epoch 1097 --quorum 3 extracts/*.json \
    --admission-url https://api.mainnet-beta.solana.com \
    --set set-1097.json --record record-1097.json --log mainnet.jsonl
```

Set files written by `from-rank-map` or by an earlier `agree` are inputs
too, and count for the sources they name. Both commands print the hash each
source gives. They write the set file and an unsigned record only if *every*
source gives the same set, at least `--quorum` distinct sources did, and the
members pass the [admission check](#the-admission-check). One source that
differs stops it, however many agree: sources that are each exact cannot
differ, so a difference means something is wrong and is for a person to
look at. With `--log`, the record links to the end of that log.

**3. Sign.** The key is a 32-byte seed, read as hex from the environment
variable `SETLOG_SIGNING_KEY` and from nowhere else. `setlog keygen` prints
a new one, and its public half on standard error. Keep the seed in a secret
store; do not put it in a file in a repository.

```sh
setlog sign --record record-1097.json --set set-1097.json
```

`sign` refuses unless the set file says what the record says: same cluster,
shred version, epoch, hash and size. A co-signer receives the record file,
produces their *own* set file with steps 1 and 2, and signs with that. If
their sources gave another set, the tool will not sign and the two signers
have something to work out.

**4. Append and publish.**

```sh
setlog append --log mainnet.jsonl --record record-1097.json
```

`append` refuses a record that is unsigned or does not extend the log.
Publish the log and the set file anywhere: neither is secret and neither is
trusted for where it came from.

The set for epoch `E + 1` is fixed at the first block of epoch `E`, so there
is a full epoch to do this in before clients need the record.

## The admission check

The set for epoch `E` is drawn from the vote accounts admitted at the first
block of epoch `E − 1` (SIMD-0357). That block charges each admitted account
the admission ticket and lists the charge among its rewards as a `VATDebit`.
In Agave the accounts charged are exactly the epoch-stakes map kept for `E`:
the map is filtered for admission and cut to 2,000 accounts first, and then
every account in it is charged. The rank map is built from that map later
and leaves out every account that shares a BLS key or node identity with
another, so those accounts are charged and not ranked.

Before writing anything, `agree` and `from-rank-map` read that block's
debits from `--admission-url` (for `from-rank-map`, the first `--url` if none
is given) and compare them with each source:

- A snapshot extract's map for the epoch must list exactly the accounts
  debited.
- A rank map must rank only accounts that were debited, and each debited
  account it leaves out must share a BLS key or node identity with another
  debited account and with none it ranks. The rank map does not give the
  keys of the accounts it leaves out, so those are read from their vote
  accounts as they are now.
- A set file names no accounts, only keys. It passes if it carries a check
  against the same block, or if it is the same set as an input that names
  accounts and passed. Alone and unchecked, it is refused.

Any difference stops the command and names the accounts. So does a block
with no debits (admission not in force, or a node that keeps no rewards)
and a block that cannot be read: no answer is not a pass.

A record made with the check carries one more source: kind `admission`,
label `vat-debits`, and the slot of the block read. The label is fixed so
that no part of the URL, which may hold an API key, is written down. It does
not count toward `--quorum`, because it read no set. `setlog show` and
`setlog verify` say, for each set, whether its members were checked and
against which block.

`--no-admission-check` skips the check. The record then has no admission
source, and one an input carried is dropped, since this run did not check.

**What it shows.** That every source's members are the accounts the cluster
charged to enter the set: the snapshot or the node applied admission as the
cluster did, and an extract was read for the right epoch. A snapshot holds
the maps of five epochs, and neighboring epochs differ by only a few
accounts, so a map read for the wrong one would otherwise pass unnoticed.
The debits are a different record from the map: the node writes them to its
ledger as the bank charges the accounts.

**What it does not show.**

- **Stake, keys and order.** Only membership is compared. A source with the
  right accounts and a wrong stake passes this check.
- **That the debits are true.** The list of rewards is a node's word, like a
  rank map. Nothing here checks it against the bank hash. Reading it from a
  node that is not one of the sources makes the check more independent.
- **That the cluster followed SIMD-0357.** The map and the debits come from
  the same computation in the same bank. The check shows that a source
  reports what the cluster did, not that the cluster did it right.
- **Which accounts a rank map should leave out, as of the block.** Their
  keys are read as they are now. A key changed since can make the check
  refuse a right rank map, or pass one that leaves out accounts that came
  to share a key later. An extract has no such gap: it lists every account.

## Checking a log

A client ships with the signers' public keys and a threshold, and with
nothing else about sets.

```sh
setlog verify --log mainnet.jsonl --threshold 2 --signer <hex> --signer <hex> --signer <hex>
```

or, in the client itself
(`crates/solana-thin-setlog/examples/pin_from_log.rs` is the whole program):

```rust
let log = verify(&parse(&log_text)?, &signer_keys, threshold)?;
let pin = log.pin(epoch).ok_or("no record for this epoch")?;
client.trust_validator_set_bytes(epoch, set_file.set_bytes(), &pin.set_hash)?;
```

`verify` refuses the whole log, and says which record is at fault, for:

- a signature that does not verify;
- a record with fewer than `threshold` signatures from distinct listed keys;
- a record that does not name the hash of the one before it;
- two records for one epoch with different sets;
- an epoch earlier than the previous record's;
- a change of cluster name.

It cannot tell that a log was cut short: the first records of a valid log
are a valid log. A client that keeps `VerifiedLog::head` can check that the
next copy it is handed still contains that record, and treat one that does
not as rewritten.

The hash comes from the log and the bytes from the set file. The verifier
compares them before it looks at a single key, so a set file needs no
signature of its own.

## What a signer vouches for

A signature on a record means: *I read this cluster's validator set for this
epoch myself, from the sources listed, they all gave this hash, and this
record follows the log I had.*

It does not mean the signer checked someone else's file and found it well
formed. A signer who signs what they were sent adds a key to the record and
no evidence, and a threshold of such signers is one source. That is why
`sign` asks for the signer's own set file, and why it cannot do more than
ask.

The sources in a record are the signers' account of where they looked, and
of the block they checked the members against. They cannot be checked
afterward: a snapshot is gone in hours, and no node will serve the same one
again. They are there so that a reader can judge how
independent the reading was, and so that a wrong record can be traced.

Signers are accountable only through the log. Two records for one epoch with
different sets, both carrying valid signatures, are proof that those signers
contradicted themselves, and a client refuses a log that holds both.

## What agreement shows, and what it does not

Agreement between sources shows that the set was **read correctly**: the
download was not damaged, the tool did not rank or filter differently from
the cluster, the node was not on a minority fork or a stale snapshot, and
one operator did not alter what it served. Three nodes on three networks,
at three slots, giving maps equal to the lamport is hard to get by accident.
The snapshot path also ranks every map twice, with Agave's code and with
the verifier's, and requires the same list.

It does not show that the set is **true**:

- **No source is a proof.** The epoch-stakes maps are not an input to the
  bank hash, so nothing in a snapshot vouches for them, and an RPC answer is
  a node's word. A node that lies gives a wrong set with nothing to catch
  it but the other sources.
- **Sources are only as independent as their operators.** Nodes are picked
  from different networks, which is a guess at different operators, not
  knowledge of it. Three nodes of one company in three data centers pass.
  Two RPC URLs may be one provider behind two names. Whoever can answer for
  a quorum of the sources chooses the set.
- **All sources of one kind run the same software.** A bug in how Agave
  fills or serves the map shows up identically everywhere. Combining a
  snapshot with the rank map helps only a little: both read the same field
  of the same bank.
- **A real certificate does not settle it either.** A certificate verifies
  against any set with the right keys in the right order, whatever their
  stake ([DESIGN.md](DESIGN.md#validator-sets)).

So a log moves trust; it does not remove it. In place of "whoever handed me
this hash", a client trusts that `threshold` of a known list of signers each
did the reading honestly and did not all ask the same liar. That is a real
improvement and it is all it is. The protocol could end the need for it with
one hash of the next epoch's ranked validators in a block footer, which the
certificate already covers. Putting the set in an account instead (SIMD-0676)
would not reach a light client: the bank hash commits state with the accounts
lattice hash (SIMD-0215), a homomorphic sum with no inclusion proof. The case
is in [proposals/validator-set-commitment.md](proposals/validator-set-commitment.md)
([DESIGN.md](DESIGN.md#what-solana-could-add)).
