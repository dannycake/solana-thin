# Security policy

solana-thin is **v0.1 and unaudited**. It has been checked against Agave's own
code and against mainnet (see the README), and one outside read of it has
already found a soundness bug. Assume there are more.

## What counts

The crate makes one promise: if it accepts a proof, the transaction is in a
block the pinned validators finalized, in a part of that block they executed.
Anything that breaks the promise is a security bug here, in particular:

- an input the verifier accepts that a validator would not have treated as an
  executed transaction of a finalized block (a difference in how the two read
  a block, a certificate, or a validator set);
- a certificate accepted without the stake it needs;
- untrusted bytes that make the verifier panic, hang, or allocate without
  bound;
- a validator set built by `tools/fetch_vote_accounts.py` that differs from
  the one the cluster uses.

Not bugs, because they are documented limits: a proven transaction may have
failed or done nothing; account state cannot be proven; the validator-set hash
has to come from somewhere you trust; blocks that switch parent are refused;
and the `unsound-stale-set` feature is unsound by name.

## Reporting

Please report privately: on GitHub, **Security → Report a vulnerability**
(a private advisory). Do not open a public issue for a soundness bug.

What helps most, in order: a failing test in `crates/solana-thin/tests`; a
case for the differential oracle (`tools/agave-fixtures`, `diff-fuzz`); the
shreds or proof bytes in hex with the validator set and shred version.

This is maintained by one person in spare time. Expect an acknowledgement
within a week. Fixes land on `main` with a test that reproduces the report,
and you will be credited unless you ask not to be.

If what you found is a bug in a validator rather than in this crate (two
validators disagreeing about a block, say), it belongs with that validator's
own security process. Tell us too if the verifier is affected.

## Supported versions

Only `main`. There are no releases yet.
