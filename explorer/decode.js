// Reading a proven transaction for people: account roles from the message
// header, and the instructions of a few well-known programs.
//
// Everything here works from the bytes the verifier proved and nothing else.
// What those bytes cannot say (accounts loaded from lookup tables, balances,
// whether the transaction succeeded) is shown as unknown, never guessed.

import { encode } from './base58.js';

const SYSTEM = '11111111111111111111111111111111';
const COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111';
const TOKEN = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const MEMOS = new Set([
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',
  'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo',
  'Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH',
]);

/** Names for programs a reader is likely to meet. */
export const PROGRAM_NAMES = new Map([
  [SYSTEM, 'System Program'],
  [COMPUTE_BUDGET, 'Compute Budget'],
  [TOKEN, 'Token Program'],
  [TOKEN_2022, 'Token-2022'],
  [ATA, 'Associated Token Account'],
  ['MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', 'Memo v3'],
  ['Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo', 'Memo v1'],
  ['Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH', 'Memo v4'],
  ['Vote111111111111111111111111111111111111111', 'Vote Program'],
  ['Stake11111111111111111111111111111111111111', 'Stake Program'],
  ['AddressLookupTab1e1111111111111111111111111', 'Address Lookup Table'],
  ['BPFLoaderUpgradeab1e11111111111111111111111', 'BPF Upgradeable Loader'],
  ['ComputeBudget111111111111111111111111111111', 'Compute Budget'],
  ['JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4', 'Jupiter v6'],
  ['whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc', 'Orca Whirlpool'],
  ['675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8', 'Raydium AMM v4'],
  ['CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK', 'Raydium CLMM'],
  ['LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo', 'Meteora DLMM'],
  ['6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P', 'Pump.fun'],
  ['metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s', 'Token Metadata'],
]);

/** The name of program `address`, or null. */
export const programName = (address) => PROGRAM_NAMES.get(address) ?? null;

const u8 = (data, at) => (at < data.length ? data[at] : null);
const u32 = (data, at) =>
  at + 4 <= data.length ? new DataView(data.buffer, data.byteOffset).getUint32(at, true) : null;
const u64 = (data, at) =>
  at + 8 <= data.length ? new DataView(data.buffer, data.byteOffset).getBigUint64(at, true) : null;

/** Lamports as SOL, exactly: BigInt arithmetic, no floating point. */
export function sol(lamports) {
  const whole = lamports / 1_000_000_000n;
  const frac = (lamports % 1_000_000_000n).toString().padStart(9, '0').replace(/0+$/, '');
  return `${whole.toLocaleString('en-US')}${frac ? `.${frac}` : ''} SOL`;
}

/** A raw token amount with `decimals` places, when the instruction names them. */
function units(amount, decimals) {
  if (decimals === null || decimals === undefined || decimals === 0) {
    return amount.toLocaleString('en-US');
  }
  const scale = 10n ** BigInt(decimals);
  const frac = (amount % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${(amount / scale).toLocaleString('en-US')}${frac ? `.${frac}` : ''}`;
}

/**
 * Signer and writable flags for each listed account, from the message header:
 * `[signatures required, read-only signed, read-only unsigned]`. Legacy
 * messages begin with it; v0 and v1 put it after their version byte.
 */
export function accountRoles(transaction) {
  const { message, accountKeys, version } = transaction;
  const at = version === 'legacy' ? 0 : 1;
  const [required, readonlySigned, readonlyUnsigned] = message.subarray(at, at + 3);
  return accountKeys.map((_, i) => {
    const signer = i < required;
    const writable = signer
      ? i < required - readonlySigned
      : i < accountKeys.length - readonlyUnsigned;
    return { signer, writable };
  });
}

/**
 * One instruction, readable. Returns the program's address and name, an
 * instruction name when the program is known, and fields as
 * `{ label, value, kind }` where kind is "address", "amount" or "text".
 */
export function describe(transaction, instruction) {
  const keys = transaction.accountKeys.map(encode);
  const listed = (index) => (index < keys.length ? keys[index] : null);
  const program = listed(instruction.programIdIndex);
  const account = (n) => {
    const index = instruction.accounts[n];
    if (index === undefined) return null;
    return listed(index) ?? `lookup table account ${index - keys.length}`;
  };
  const { data } = instruction;
  const out = { program, programName: program ? programName(program) : null, name: null, fields: [] };
  const field = (label, value, kind = 'text') => {
    if (value !== null && value !== undefined) out.fields.push({ label, value, kind });
  };

  if (program === null) {
    out.name = 'program loaded from a lookup table';
    return out;
  }

  if (program === SYSTEM) {
    const tag = u32(data, 0);
    if (tag === 0) {
      out.name = 'Create account';
      field('From', account(0), 'address');
      field('New account', account(1), 'address');
      const lamports = u64(data, 4);
      field('Funded with', lamports === null ? null : sol(lamports), 'amount');
      const space = u64(data, 12);
      field('Space', space === null ? null : `${space.toLocaleString('en-US')} bytes`);
      field('Owner', data.length >= 52 ? encode(data.subarray(20, 52)) : null, 'address');
    } else if (tag === 2) {
      out.name = 'Transfer';
      field('From', account(0), 'address');
      field('To', account(1), 'address');
      const lamports = u64(data, 4);
      field('Amount', lamports === null ? null : sol(lamports), 'amount');
    } else if (tag === 1) {
      out.name = 'Assign';
      field('Account', account(0), 'address');
      field('Owner', data.length >= 36 ? encode(data.subarray(4, 36)) : null, 'address');
    } else if (tag === 4) {
      out.name = 'Advance nonce';
      field('Nonce account', account(0), 'address');
    } else if (tag === 8) {
      out.name = 'Allocate';
      field('Account', account(0), 'address');
    } else if (tag === 3) {
      out.name = 'Create account with seed';
      field('From', account(0), 'address');
      field('New account', account(1), 'address');
    }
    return out;
  }

  if (program === COMPUTE_BUDGET) {
    const tag = u8(data, 0);
    if (tag === 2) {
      out.name = 'Set compute unit limit';
      const limit = u32(data, 1);
      field('Limit', limit === null ? null : `${limit.toLocaleString('en-US')} units`);
    } else if (tag === 3) {
      out.name = 'Set compute unit price';
      const price = u64(data, 1);
      field('Price', price === null ? null : `${price.toLocaleString('en-US')} micro-lamports per unit`);
    } else if (tag === 1) {
      out.name = 'Request heap frame';
      const bytes = u32(data, 1);
      field('Heap', bytes === null ? null : `${bytes.toLocaleString('en-US')} bytes`);
    } else if (tag === 4) {
      out.name = 'Set loaded accounts data size limit';
      const bytes = u32(data, 1);
      field('Limit', bytes === null ? null : `${bytes.toLocaleString('en-US')} bytes`);
    }
    return out;
  }

  if (MEMOS.has(program)) {
    out.name = 'Memo';
    field('Text', new TextDecoder('utf-8', { fatal: false }).decode(data));
    return out;
  }

  if (program === TOKEN || program === TOKEN_2022) {
    const tag = u8(data, 0);
    if (tag === 3) {
      out.name = 'Transfer';
      field('From', account(0), 'address');
      field('To', account(1), 'address');
      field('Authority', account(2), 'address');
      const amount = u64(data, 1);
      field('Amount', amount === null ? null : `${units(amount)} base units`, 'amount');
    } else if (tag === 12) {
      out.name = 'Transfer checked';
      field('From', account(0), 'address');
      field('Mint', account(1), 'address');
      field('To', account(2), 'address');
      field('Authority', account(3), 'address');
      const amount = u64(data, 1);
      const decimals = u8(data, 9);
      field('Amount', amount === null ? null : units(amount, decimals), 'amount');
    } else if (tag === 7 || tag === 14) {
      out.name = tag === 7 ? 'Mint to' : 'Mint to checked';
      field('Mint', account(0), 'address');
      field('To', account(1), 'address');
      const amount = u64(data, 1);
      field('Amount', amount === null ? null : units(amount, tag === 14 ? u8(data, 9) : null), 'amount');
    } else if (tag === 8 || tag === 15) {
      out.name = tag === 8 ? 'Burn' : 'Burn checked';
      field('Account', account(0), 'address');
      field('Mint', account(1), 'address');
      const amount = u64(data, 1);
      field('Amount', amount === null ? null : units(amount, tag === 15 ? u8(data, 9) : null), 'amount');
    } else if (tag === 9) {
      out.name = 'Close account';
      field('Account', account(0), 'address');
      field('Rent to', account(1), 'address');
    } else if (tag === 1 || tag === 16 || tag === 18) {
      out.name = 'Initialize account';
      field('Account', account(0), 'address');
      field('Mint', account(1), 'address');
    } else if (tag === 17) {
      out.name = 'Sync native';
      field('Account', account(0), 'address');
    } else if (tag === 4 || tag === 13) {
      out.name = tag === 4 ? 'Approve' : 'Approve checked';
      field('Account', account(0), 'address');
    }
    return out;
  }

  if (program === ATA) {
    out.name = data.length === 0 || data[0] === 0 ? 'Create' : data[0] === 1 ? 'Create idempotent' : null;
    if (out.name) {
      field('Payer', account(0), 'address');
      field('Token account', account(1), 'address');
      field('Owner', account(2), 'address');
      field('Mint', account(3), 'address');
    }
    return out;
  }

  return out;
}
