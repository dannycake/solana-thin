// The verifier's WebAssembly module behind a small class. Plain ECMAScript
// with no dependency: it runs in node and in a browser as it is.
//
//   import { load } from './solana-thin.mjs';
//   const { Verifier } = await load(bytesOfTheWasmFile);
//   const verifier = Verifier.mainnet(50093);
//   verifier.pin(1095n, validatorSetBytes, pinnedHash);
//   const transaction = verifier.verify(proofBytes, signature);
//
// Slots, epochs and times are BigInt, and bytes are Uint8Array. A refusal is
// thrown as a VerifyError.

/** Why a call was refused. `kind` is the name of a `solana_thin::ErrorKind`. */
export class VerifyError extends Error {
  constructor({ kind, detail, epoch }) {
    super(detail);
    this.name = 'VerifyError';
    this.kind = kind;
    /** With `EpochNotPinned`: the epoch to pin a set for, when the verifier could name it. */
    this.epoch = epoch === null ? null : BigInt(epoch);
  }
}

const unhex = (text) => Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
const block = ({ slot, id }) => ({ slot: BigInt(slot), id: unhex(id) });

/**
 * Instantiates the module. `source` is the bytes of the .wasm file or a
 * compiled WebAssembly.Module. The module imports nothing.
 */
export async function load(source) {
  const made = await WebAssembly.instantiate(source, {});
  const x = (made.instance ?? made).exports;
  // Views are made per use: growing the module's memory detaches older ones.
  const view = (pointer, length) => new Uint8Array(x.memory.buffer, pointer, length);

  /** Copies each array into the module's memory for the length of `call`. */
  const lend = (arrays, call) => {
    const held = [];
    try {
      for (const bytes of arrays) {
        // A wasm pointer comes back as a signed 32-bit number.
        const pointer = x.st_alloc(bytes.length) >>> 0;
        held.push([pointer, bytes.length]);
        view(pointer, bytes.length).set(bytes);
      }
      return call(...held.flat());
    } finally {
      for (const [pointer, length] of held) x.st_free(pointer, length);
    }
  };

  /** Reads an answer and frees it. Returns its fields, or throws its refusal. */
  const take = (answer) => {
    const pointer = answer >>> 0;
    const length = new DataView(x.memory.buffer).getUint32(pointer, true);
    const text = new TextDecoder().decode(view(pointer + 4, length));
    x.st_free(pointer, 4 + length);
    const fields = JSON.parse(text);
    if (!fields.ok) throw new VerifyError(fields);
    return fields;
  };

  const make = (shredVersion, slotsPerEpoch, warmup) => {
    // Anything else would be wrapped to 32 bits on its way into the module.
    if (!Number.isInteger(shredVersion) || shredVersion < 0 || shredVersion > 0xffff_ffff) {
      throw new RangeError(`shred version ${shredVersion} is not an unsigned integer`);
    }
    return take(x.st_verifier_new(shredVersion, BigInt(slotsPerEpoch), warmup)).verifier;
  };

  /** Checks proofs against the validator sets it has been told to trust. */
  class Verifier {
    #handle;

    constructor(handle) {
      this.#handle = handle;
    }

    /** Mainnet-beta: epochs of 432,000 slots from slot zero. */
    static mainnet(shredVersion) {
      return Verifier.withoutWarmup(shredVersion, 432_000n);
    }

    /** A cluster whose epochs are `slotsPerEpoch` long from slot zero. */
    static withoutWarmup(shredVersion, slotsPerEpoch) {
      return new Verifier(make(shredVersion, slotsPerEpoch, 0));
    }

    /** A cluster that began with warm-up epochs, as testnet and devnet did. */
    static withWarmup(shredVersion, slotsPerEpoch) {
      return new Verifier(make(shredVersion, slotsPerEpoch, 1));
    }

    // Address zero is ordinary memory to a wasm module, so a freed handle
    // has to be refused here.
    #live() {
      if (this.#handle === 0) throw new Error('this verifier has been freed');
      return this.#handle;
    }

    /**
     * Trusts `set` for `epoch`, provided it hashes to `pinnedHash` (32
     * bytes). The epoch is the caller's word: nothing is read from a proof.
     */
    pin(epoch, set, pinnedHash) {
      const handle = this.#live();
      lend([set, pinnedHash], (s, sLength, h, hLength) =>
        take(x.st_pin(handle, BigInt(epoch), s, sLength, h, hLength)));
    }

    /**
     * Checks a proof. With `signature` (64 bytes), also checks that it is for
     * the transaction with that id.
     */
    verify(proof, signature = new Uint8Array(0)) {
      const handle = this.#live();
      const found = lend([proof, signature], (p, pLength, s, sLength) =>
        take(x.st_verify(handle, p, pLength, s, sLength)));
      return {
        slot: BigInt(found.slot),
        blockId: unhex(found.blockId),
        epoch: BigInt(found.epoch),
        transactionId: unhex(found.transactionId),
        blockTimeNanos: found.blockTimeNanos === null ? null : BigInt(found.blockTimeNanos),
        finality: found.finality,
        memos: found.memos.map(unhex),
        parent: block(found.parent),
        finalizedBy: block(found.finalizedBy),
        position: found.position,
        footer: found.footer === null ? null : {
          bankHash: unhex(found.footer.bankHash),
          userAgent: unhex(found.footer.userAgent),
        },
        transaction: {
          version: found.transaction.version,
          signatures: found.transaction.signatures.map(unhex),
          accountKeys: found.transaction.accountKeys.map(unhex),
          recentBlockhash: unhex(found.transaction.recentBlockhash),
          instructions: found.transaction.instructions.map((ix) => ({
            programIdIndex: ix.programIdIndex,
            accounts: ix.accounts,
            data: unhex(ix.data),
          })),
          message: unhex(found.transaction.message),
        },
        anatomy: {
          ...found.anatomy,
          aggregates: found.anatomy.aggregates.map((aggregate) => ({
            ...aggregate,
            stakeSigned: BigInt(aggregate.stakeSigned),
            stakeTotal: BigInt(aggregate.stakeTotal),
          })),
          ancestry: found.anatomy.ancestry.map(block),
        },
      };
    }

    /** Releases the verifier's memory. It cannot be used afterwards. */
    free() {
      x.st_verifier_free(this.#live());
      this.#handle = 0;
    }
  }

  return { Verifier, memoryBytes: () => x.memory.buffer.byteLength };
}
