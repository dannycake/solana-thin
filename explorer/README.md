# solana-thin explorer

A Solana transaction explorer that verifies in the browser. Choose a
provider, enter a signature or open a proof file, then inspect the verified
result. The result shows the opened block shreds, the parent links to the certified block, and
the validators who signed. Block facts and decoded transaction details follow.

It is a static site. There is no server code to run and nothing to configure.
Any host, or a file share, or `python3 -m http.server`, can serve it.

```sh
scripts/explorer.sh --serve 8000         # build into <target>/explorer and serve it
prover serve --rpc https://api.mainnet-beta.solana.com \
    --set mainnet-set-1098.json --listen 127.0.0.1:8080   # a prover to ask
```

Open `http://127.0.0.1:8000/`. Choose **A proof file**, then **Load mainnet
example** to verify a bundled proof with no prover at all.

## What it does not tell anyone

A hosted explorer learns every signature and address you look up, because
they are in its URLs and its API calls. This page is built so that its host
learns nothing about what you look up:

- **No server code.** The host serves the same fixed files to everyone.
- **Lookups never reach the host.** The signature and slot live in the page
  and, in a shared link, after the `#`, which browsers never send.
- **The same requests for every visitor.** On load the page fetches its own
  files and every validator set it ships with, all of them, so that
  fetching one would not give away the epoch you looked up.
- **No third parties.** No analytics, fonts, CDNs or images from elsewhere.
  A Content Security Policy in the page has the browser enforce that: scripts
  and styles from the page's own origin only, nothing framed, forms post
  nowhere, and no referrer sent.
- **No history.** Searches are not written to the address bar or to storage.
  `localStorage` holds only the prover's address and any set hashes you pin.
- **It shows its work.** The *Network* disclosure lists every
  request, from the browser's Resource Timing record and the page's own
  fetches, and marks the one that carries your signature.

`SHA256SUMS`, written by `scripts/explorer.sh`, lets anyone compare a hosted
copy with a build from a given commit.

## What it cannot hide

**The prover you ask learns the signature.** A proof is built for one
transaction, so the request names it. Who that prover is decides who learns it:

| Prover | Who learns what |
|---|---|
| Your own, on your machine (`prover serve --listen 127.0.0.1:8080`) | Validators answering repair requests learn which **block** is fetched, not which of its hundreds of transactions you care about. With a slot (*Slot (optional)*), no RPC node is asked about your signature at all. Without one, the prover asks its RPC node for the slot, and that node learns the signature. |
| Someone else's | That prover's operator can log the signature, your IP address and the time. |

The prover is not trusted for correctness, only for privacy. A proof from
anyone is checked against the validator set this page pins; a lying prover can
only make a lookup fail.

Other limits:

- **Your network sees where you connect**: the host, and the prover's address.
  Neither sees the content of an HTTPS request.
- **A shared link carries the signature** after the `#`. Whoever opens it
  learns it, and their browser asks their prover.
- **What the page shows is only what the bytes prove.** Not whether the
  transaction succeeded, not balances, not accounts loaded from address lookup
  tables (that needs account state). The page says so.

## Trust

The page trusts one thing per epoch: the hash of that epoch's ranked validator
set, from `explorer/trust.json`. Set files themselves come from the bundle or
from the prover, and the module refuses any that does not hash to the pin
([docs/SETS.md](../docs/SETS.md) says where the hashes come from).

For an epoch the page has no hash for, it stops and asks. You can paste a hash
from a source you trust, or take the prover's word for it, labeled as such.
Either is kept in this browser only once a set matching it has been pinned, and
can be forgotten under *Pinned set hashes*.

Mainnet epochs last about a day (432,000 slots at about 0.215 s each, measured
in November 2026). Publishing this page means adding each new
epoch's hash to `trust.json`, from a set log you have checked, and rebuilding.

## Building

```sh
scripts/explorer.sh [--out DIR] [--connect ORIGIN]... [--sets DIR] [--serve PORT]
```

- `--connect https://prover.example.org` narrows the page's `connect-src` to
  exactly the named provers. Without it the page may ask any `https` origin or
  a prover on `localhost`, whichever the reader sets.
- `--sets DIR` bundles set files as `setlog` writes them; each must match its
  hash in `trust.json` or the build stops.

The prover sends `Access-Control-Allow-Origin: *`, so a page on any origin can
read its answers.

`explorer/check.mjs`, run by `scripts/wasm.sh`, checks the page's base58 and
instruction decoding against the mainnet test vector.

## Files

```
index.html     the page and its Content Security Policy
explorer.js    fetching, pinning, verifying, rendering, the request ledger
decode.js      account roles and well-known instructions, from the proven bytes
base58.js      base58, so no code is loaded from elsewhere
explorer.css   the page's look; system fonts only
trust.json     the pinned set hash of each epoch
check.mjs      node check of the decoding (not shipped)
```
