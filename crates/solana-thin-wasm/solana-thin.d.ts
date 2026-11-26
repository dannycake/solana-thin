// Type declarations for the solana-thin WebAssembly verifier wrapper.
// The wrapper is dependency-free ECMAScript; see solana-thin.mjs.

/** Why a call was refused. `kind` is the name of a `solana_thin::ErrorKind`. */
export declare class VerifyError extends Error {
  readonly name: "VerifyError";
  /** The error kind, e.g. "ProofRejected", "CertificateRejected", "EpochNotPinned". */
  readonly kind: string;
  /** With `EpochNotPinned`: the epoch to pin a set for, when the verifier could name it. */
  readonly epoch: bigint | null;
}

/** A verified transaction, as returned by {@link Verifier.verify}. */
export interface Verified {
  /** The slot of the block the transaction is in. */
  slot: bigint;
  /** The 32-byte block id. */
  blockId: Uint8Array;
  /** The epoch the block is in. */
  epoch: bigint;
  /** The transaction's first signature (its id), 64 bytes. */
  transactionId: Uint8Array;
  /** The block's producer time in nanoseconds, when the footer carried one. */
  blockTimeNanos: bigint | null;
  /** "fast" or "slow", the kind of finality certificate. */
  finality: string;
  /** The payloads of any Memo-program instructions in the transaction. */
  memos: Uint8Array[];
}

/** Checks proofs against the validator sets it has been told to trust. */
export interface Verifier {
  /**
   * Trusts `set` for `epoch`, provided it hashes to `pinnedHash` (32 bytes).
   * The epoch is the caller's word: nothing is read from a proof.
   */
  pin(epoch: bigint, set: Uint8Array, pinnedHash: Uint8Array): void;
  /**
   * Checks a proof. With `signature` (64 bytes), also checks that it is for
   * the transaction with that id. Throws a {@link VerifyError} on refusal.
   */
  verify(proof: Uint8Array, signature?: Uint8Array): Verified;
  /** Releases the verifier's memory. It cannot be used afterwards. */
  free(): void;
}

/** Constructors for {@link Verifier}, from {@link load}. */
export interface VerifierConstructor {
  /** Mainnet-beta: epochs of 432,000 slots from slot zero. */
  mainnet(shredVersion: number): Verifier;
  /** A cluster whose epochs are `slotsPerEpoch` long from slot zero. */
  withoutWarmup(shredVersion: number, slotsPerEpoch: bigint): Verifier;
  /** A cluster that began with warm-up epochs, as testnet and devnet did. */
  withWarmup(shredVersion: number, slotsPerEpoch: bigint): Verifier;
}

/**
 * Instantiates the module. `source` is the bytes of the .wasm file or a
 * compiled WebAssembly.Module. The module imports nothing.
 */
export declare function load(
  source: BufferSource | WebAssembly.Module,
): Promise<{ Verifier: VerifierConstructor; memoryBytes: () => number }>;
