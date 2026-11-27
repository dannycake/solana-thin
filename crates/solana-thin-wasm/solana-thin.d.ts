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
  /** The block's parent, as the block commits to it. */
  parent: BlockRef;
  /** The block the finality certificate was for: this block or a descendant. */
  finalizedBy: BlockRef;
  /** Where the transaction sits in its entry batch. */
  position: { entry: number; transaction: number };
  /** The block's footer, when the proof opened it. */
  footer: Footer | null;
  /** The transaction, as the verifier read it out of the block. */
  transaction: Transaction;
  /** What the proof is made of, every part of it checked. */
  anatomy: Anatomy;
}

/** How a verified proof holds together. */
export interface Anatomy {
  /** The proof's size in bytes. */
  proofBytes: number;
  /** How many validators the pinned set ranks. */
  validators: number;
  /** The certificate's aggregates: one notarize for fast finality, a
   * notarize and a finalize for slow. */
  aggregates: {
    vote: "notarize" | "finalize";
    /** Ranks, into the pinned set, of the validators whose votes it carries. */
    signers: number[];
    stakeSigned: bigint;
    stakeTotal: bigint;
  }[];
  /** Parents from the certified block down to the transaction's block,
   * newest first. Empty when the certificate is for the transaction's block. */
  ancestry: BlockRef[];
  /** FEC sets in the transaction's block (each holds 32 data shreds). */
  fecSets: number;
  /** The shreds the proof opens: `shreds` consecutive ones from position
   * `first` of FEC set `set`. */
  opened: { set: number; first: number; shreds: number }[];
  /** Index of the first shred of the batch holding the transaction. */
  componentStart: number;
  /** Index of the first shred of the block's footer, when the proof opens it. */
  footerStart: number | null;
}

/** A block: its slot and its 32-byte id. */
export interface BlockRef {
  slot: bigint;
  id: Uint8Array;
}

/** What the leader wrote after a block's last entry. */
export interface Footer {
  /** Hash of the bank after the block executed, 32 bytes. */
  bankHash: Uint8Array;
  /** Free-form client identification written by the leader. */
  userAgent: Uint8Array;
}

/** One instruction of a transaction. */
export interface Instruction {
  /** Index of the program in the transaction's account keys. */
  programIdIndex: number;
  /** Indexes of the accounts the instruction touches. Indexes past the
   * listed keys name accounts loaded from address lookup tables. */
  accounts: number[];
  data: Uint8Array;
}

/** A transaction as it appears inside a block. */
export interface Transaction {
  /** "legacy", "v0" or "v1". */
  version: string;
  /** Ed25519 signatures, 64 bytes each. The first is the transaction id. */
  signatures: Uint8Array[];
  /** Account keys listed in the message, 32 bytes each. Keys loaded from
   * address lookup tables are not here: resolving them needs account state. */
  accountKeys: Uint8Array[];
  /** The recent blockhash (or durable nonce) the transaction commits to. */
  recentBlockhash: Uint8Array;
  instructions: Instruction[];
  /** The exact bytes the signatures cover. */
  message: Uint8Array;
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
