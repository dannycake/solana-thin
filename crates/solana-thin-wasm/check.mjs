// Verifies a real mainnet proof in the WebAssembly module, under node:
//   node check.mjs <solana_thin_wasm.wasm> <mainnet-block-473100911.json>
// Exits non-zero unless every expectation below holds.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load, VerifyError } from './solana-thin.mjs';

const [modulePath, vectorPath] = process.argv.slice(2);
if (!modulePath || !vectorPath) {
  console.error('usage: node check.mjs <module.wasm> <vector.json>');
  process.exit(2);
}
const unhex = (text) => Uint8Array.from(text.match(/../g), (pair) => parseInt(pair, 16));
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const vector = JSON.parse(readFileSync(vectorPath, 'utf8'));
const set = unhex(vector.validator_set);
const setHash = unhex(vector.validator_set_hash);
const proof = unhex(vector.proof_of_first_transaction);
const signature = unhex(vector.first_signature);
const epoch = BigInt(vector.epoch);

/** Runs `call`, which must be refused as `kind`, and returns the error. */
const refused = (what, kind, call) => {
  let error;
  try {
    call();
  } catch (thrown) {
    error = thrown;
  }
  assert(error instanceof VerifyError, `${what}: ${error ?? 'accepted'}`);
  assert.equal(error.kind, kind, `${what}: ${error.message}`);
  console.log(`${what.padEnd(28)} -> ${error.kind}: ${error.message}`);
  return error;
};
const median = (runs, call) => {
  const times = Array.from({ length: runs }, () => {
    const start = performance.now();
    call();
    return performance.now() - start;
  }).sort((a, b) => a - b);
  return times[runs >> 1];
};

const bytes = readFileSync(modulePath);
// A module that imported anything could not be loaded with an empty object.
assert.deepEqual(WebAssembly.Module.imports(new WebAssembly.Module(bytes)), []);
const { Verifier, memoryBytes } = await load(bytes);
console.log(`node ${process.version}, module ${bytes.length} bytes, no imports`);

const verifier = Verifier.mainnet(vector.shred_version);
assert.equal(refused('no set pinned', 'EpochNotPinned', () => verifier.verify(proof)).epoch, epoch);
refused('another hash', 'InvalidValidatorSet', () => verifier.pin(epoch, set, new Uint8Array(32)));
refused('a hash of 31 bytes', 'InvalidParameters', () => verifier.pin(epoch, set, setHash.subarray(0, 31)));
verifier.pin(epoch, set, setHash);

const verified = verifier.verify(proof);
assert.deepEqual(verified, {
  slot: BigInt(vector.slot),
  blockId: unhex(vector.block_id),
  epoch,
  transactionId: signature,
  blockTimeNanos: verified.blockTimeNanos,
  finality: 'fast',
  memos: [],
});
assert.equal(typeof verified.blockTimeNanos, 'bigint');
assert.deepEqual(verifier.verify(proof, signature), verified);
console.log(`slot ${verified.slot}, epoch ${verified.epoch}, ${verified.finality} finality, ` +
  `block time ${verified.blockTimeNanos} ns`);
console.log(`transaction ${hex(verified.transactionId)}`);

const other = Uint8Array.from(signature);
other[0] ^= 1;
refused('another signature', 'WrongTransaction', () => verifier.verify(proof, other));
refused('a signature of 63 bytes', 'InvalidParameters', () => verifier.verify(proof, signature.subarray(0, 63)));
refused('a proof cut short', 'Malformed', () => verifier.verify(proof.subarray(0, proof.length - 1)));
const bent = Uint8Array.from(proof);
bent[bent.length >> 1] ^= 1;
refused('a proof with a byte changed', 'ProofRejected', () => verifier.verify(bent));

// The same keys sign on every cluster. The shred version tells their votes apart.
const elsewhere = Verifier.mainnet(vector.shred_version + 1);
elsewhere.pin(epoch, set, setHash);
refused('another cluster', 'CertificateRejected', () => elsewhere.verify(proof));
elsewhere.free();
assert.throws(() => elsewhere.verify(proof), /has been freed/);

const warm = Verifier.withWarmup(vector.shred_version, 432_000n);
warm.pin(epoch, set, setHash);
assert.equal(refused('a schedule with warm-up', 'EpochNotPinned', () => warm.verify(proof)).epoch, epoch + 12n);
warm.free();
refused('an epoch of 31 slots', 'InvalidParameters', () => Verifier.withoutWarmup(vector.shred_version, 31n));
refused('a shred version of 17 bits', 'InvalidParameters', () => Verifier.mainnet(0x1_0000));
assert.throws(() => Verifier.mainnet(-1), RangeError);

const verifyMs = median(50, () => verifier.verify(proof));
const pinMs = median(10, () => {
  const fresh = Verifier.mainnet(vector.shred_version);
  fresh.pin(epoch, set, setHash);
  fresh.free();
});
console.log(`verify with the set kept: median ${verifyMs.toFixed(1)} ms; ` +
  `pin a set of ${(set.length - 4) / 56} validators: median ${pinMs.toFixed(0)} ms; ` +
  `memory ${memoryBytes() >> 10} KiB`);
verifier.free();
console.log('OK');
