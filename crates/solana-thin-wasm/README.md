# solana-thin (WebAssembly)

The [`solana-thin`](https://github.com/dannycake/solana-thin) verifier as a bare
WebAssembly module with a small, dependency-free JavaScript wrapper. It checks,
from an untrusted proof and a validator set you trust, that a transaction is in
a block Solana's validators finalized after Alpenglow. It runs no node, fetches
nothing, and keeps no chain state.

`v0.1`, unreviewed. Do not put money behind it until someone other than its
author has reviewed it. See the [repository](https://github.com/dannycake/solana-thin)
for the design, the limits, and what a successful check does and does not mean.

The module imports nothing and is about 240 KB. The wrapper exposes `load`,
which takes the module's bytes, and a `Verifier` you give a validator set and
its pinned hash for an epoch, then ask about a proof.

## Install

```sh
npm install solana-thin
```

## Node

```js
import { readFileSync } from 'node:fs';
import { load } from 'solana-thin';

const wasmUrl = new URL('./solana_thin_wasm.wasm', import.meta.resolve('solana-thin'));
const { Verifier } = await load(readFileSync(wasmUrl));

const verifier = Verifier.mainnet(shredVersion);          // a number
verifier.pin(epoch, validatorSetBytes, pinnedHashBytes);  // epoch is a BigInt; bytes are Uint8Array
const tx = verifier.verify(proofBytes);                   // throws a VerifyError on refusal
console.log(tx.slot, tx.finality, tx.transactionId);
verifier.free();
```

## Browser

```js
import { load } from 'solana-thin';

const wasm = new Uint8Array(await (await fetch('/solana_thin_wasm.wasm')).arrayBuffer());
const { Verifier } = await load(wasm);

const verifier = Verifier.mainnet(shredVersion);
verifier.pin(epoch, validatorSetBytes, pinnedHashBytes);
const tx = verifier.verify(proofBytes);
```

Serve `solana_thin_wasm.wasm` from your own origin (it ships in the package).
Slots, epochs and times are `BigInt`; byte strings are `Uint8Array`. A refusal
is thrown as a `VerifyError` whose `kind` names the reason.

## Trust

A successful check means the validators you pinned finalized a block and your
transaction is in an executed part of it. It does **not** say the transaction
succeeded, anything about account state, or that the validator set you pinned is
the right one — that is your trust root. The repository explains how to obtain a
set and its hash.

## License

Apache-2.0.
