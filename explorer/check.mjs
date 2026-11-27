// The explorer's own code under node: base58, account roles and instruction
// decoding, on the mainnet proof the page ships as its example.
//   node explorer/check.mjs <solana_thin_wasm.wasm> <mainnet-block-473100911.json>
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load } from '../crates/solana-thin-wasm/solana-thin.mjs';
import { encode, decode } from './base58.js';
import { accountRoles, describe, sol } from './decode.js';

const [modulePath, vectorPath] = process.argv.slice(2);
if (!modulePath || !vectorPath) {
  console.error('usage: node explorer/check.mjs <module.wasm> <vector.json>');
  process.exit(2);
}
const unhex = (text) => Uint8Array.from(text.match(/../g), (pair) => parseInt(pair, 16));

// Base58, against values the solana CLI prints.
assert.equal(encode(new Uint8Array(32)), '11111111111111111111111111111111');
assert.equal(encode(unhex('054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d')),
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
assert.deepEqual(decode('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
  unhex('054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d'));
assert.equal(decode('0OIl'), null);
for (let n = 0; n < 200; n++) {
  const bytes = Uint8Array.from({ length: n % 70 }, (_, i) => (i < n % 3 ? 0 : (i * 37 + n) & 0xff));
  assert.deepEqual(decode(encode(bytes)), bytes);
}
assert.equal(sol(1_500_000_000n), '1.5 SOL');
assert.equal(sol(1n), '0.000000001 SOL');

// The example proof, read as the page reads it.
const vector = JSON.parse(readFileSync(vectorPath, 'utf8'));
const { Verifier } = await load(readFileSync(modulePath));
const verifier = Verifier.mainnet(vector.shred_version);
verifier.pin(BigInt(vector.epoch), unhex(vector.validator_set), unhex(vector.validator_set_hash));
const { transaction: tx } = verifier.verify(unhex(vector.proof_of_first_transaction));
assert.equal(encode(tx.signatures[0]), encode(unhex(vector.first_signature)));

const roles = accountRoles(tx);
assert.deepEqual(roles[0], { signer: true, writable: true });
assert.equal(roles.filter((r) => r.signer).length, tx.signatures.length);

const described = tx.instructions.map((ix) => describe(tx, ix));
assert.deepEqual(described.slice(0, 2).map((d) => [d.programName, d.name, d.fields[0].value]), [
  ['Compute Budget', 'Set compute unit limit', '5,000 units'],
  ['Compute Budget', 'Set compute unit price', '3,200 micro-lamports per unit'],
]);
assert.equal(described[2].name, null, 'an unknown program is not guessed at');
verifier.free();

// Synthetic: a v0 message (header after the version byte) with a System
// transfer and a Token transferChecked whose destination is in a lookup table.
const key = (n) => Uint8Array.from({ length: 32 }, () => n);
const le = (value, bytes) => {
  const out = new Uint8Array(bytes);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
};
const synthetic = {
  version: 'v0',
  signatures: [new Uint8Array(64)],
  // 1 signature, 0 read-only signed, 2 read-only unsigned.
  message: Uint8Array.from([0x80, 1, 0, 2]),
  accountKeys: [key(1), key(2), new Uint8Array(32), decode('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')],
  recentBlockhash: key(9),
  instructions: [
    { programIdIndex: 2, accounts: [0, 1], data: Uint8Array.from([2, 0, 0, 0, ...le(2_500_000_000n, 8)]) },
    { programIdIndex: 3, accounts: [1, 4, 5, 0],
      data: Uint8Array.from([12, ...le(1_234_500n, 8), 6]) },
  ],
};
assert.deepEqual(accountRoles(synthetic), [
  { signer: true, writable: true },
  { signer: false, writable: true },
  { signer: false, writable: false },
  { signer: false, writable: false },
]);
const [transfer, tokens] = synthetic.instructions.map((ix) => describe(synthetic, ix));
assert.equal(transfer.name, 'Transfer');
assert.deepEqual(transfer.fields.map((f) => f.value),
  [encode(key(1)), encode(key(2)), '2.5 SOL']);
assert.equal(tokens.name, 'Transfer checked');
assert.deepEqual(tokens.fields.map((f) => f.value), [
  encode(key(2)), 'lookup table account 0', 'lookup table account 1', encode(key(1)), '1.2345',
]);
console.log(`explorer: base58, roles and ${described.length} instructions of the example read; OK`);
