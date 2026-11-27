// The explorer: fetch a proof from a prover the reader chose, check it in
// WebAssembly against a validator set held to a pinned hash, and show what
// the proven bytes say. No other code, no server of its own.

import { load, VerifyError } from './solana-thin.mjs';
import { encode, decode } from './base58.js';
import { accountRoles, describe, programName } from './decode.js';

const $ = (id) => document.getElementById(id);
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (text) => Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
const isHash = (text) => /^[0-9a-f]{64}$/.test(text);
const number = (n) => n.toLocaleString('en-US');
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

const DEFAULT_PROVER = 'http://127.0.0.1:8080';
const CLUSTER = 'mainnet-beta';
const STORE_KEY = 'thin-explorer/v1';

// ---------------------------------------------------------------------------
// Settings kept in this browser only: the prover's address and hashes the
// reader pinned. Never the signatures looked up.

function readStore() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY)) ?? {};
  } catch {
    return {};
  }
}

function writeStore(store) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(store));
  } catch {
    // Storage blocked: settings last for this visit only.
  }
}

const store = { prover: DEFAULT_PROVER, pins: {}, ...readStore() };
const prover = () => store.prover.replace(/\/+$/, '');

// ---------------------------------------------------------------------------
// The ledger: every request the page makes. Its own fetches are logged as
// they are made, with their answer; the files the browser loads by itself
// (the page, its stylesheet and scripts) come from the Resource Timing record.

const ledger = $('ledger');
const signatureRequests = new Map();

function ledgerEntry({ url, what, status, carries }) {
  const item = document.createElement('li');
  const parsed = new URL(url, location.href);
  const own = parsed.origin === location.origin;
  item.className = own ? 'own' : 'away';
  if (carries) item.classList.add('carries');
  const where = document.createElement('span');
  where.className = 'where';
  where.textContent = own ? 'this site' : parsed.host;
  const path = document.createElement('code');
  path.className = 'path';
  path.textContent = parsed.pathname + parsed.search;
  const note = document.createElement('span');
  note.className = 'note';
  note.textContent = [what, status, carries ? 'carries your signature' : null]
    .filter(Boolean)
    .join(', ');
  item.append(where, path, note);
  ledger.append(item);
  if (carries) signatureRequests.set(parsed.host, (signatureRequests.get(parsed.host) ?? 0) + 1);
  const count = ledger.childElementCount;
  const destinations = Array.from(signatureRequests, ([host, n]) => `${n} to ${host} carried the signature`);
  $('network-summary').textContent = [`Network: ${count} request${count === 1 ? '' : 's'}`, ...destinations].join(', ');
  return note;
}

function watchResources() {
  const nav = performance.getEntriesByType('navigation')[0];
  ledgerEntry({ url: (nav?.name ?? location.href).split('#')[0], what: 'the page' });
  const seen = (entry) => {
    // Fetches are logged by `request` below, with their outcome.
    if (entry.initiatorType === 'fetch') return;
    ledgerEntry({ url: entry.name, what: entry.initiatorType === 'link' ? 'stylesheet' : 'script' });
  };
  performance.getEntriesByType('resource').forEach(seen);
  new PerformanceObserver((list) => list.getEntries().forEach(seen)).observe({ type: 'resource' });
}

/** A fetch, logged. Never sends cookies or a referrer, never cached. */
async function request(url, what, { carries = false } = {}) {
  const note = ledgerEntry({ url, what, status: 'sent', carries });
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
    note.textContent = [what, `${response.status}`, carries ? 'carries your signature' : null]
      .filter(Boolean)
      .join(', ');
    return response;
  } catch (error) {
    note.textContent = `${what}, no answer`;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Status line.

const statusLine = $('status');
function say(text, tone = '') {
  statusLine.textContent = text;
  statusLine.className = `status ${tone}`;
}

// ---------------------------------------------------------------------------
// Trust: hashes shipped with the page, then hashes the reader pinned.

let trust;
// Set files shipped with the site, all fetched when the page loads. Fetching
// one only when a proof needs it would tell this site the epoch looked up.
const bundled = new Map();
let verifier;
const pinned = new Set();

function trustedHash(epoch) {
  const shipped = trust.clusters[CLUSTER].sets[String(epoch)];
  if (shipped) return { hash: shipped.hash, source: 'shipped with this page' };
  const mine = store.pins[String(epoch)] ?? tentative.get(String(epoch));
  if (mine) return mine;
  return null;
}

// A hash the reader just gave, kept only once a set that matches it is pinned:
// a mistyped hash must not stay to refuse every later lookup.
const tentative = new Map();

class NeedHash extends Error {
  constructor(epoch, claim) {
    super(`no pinned hash for epoch ${epoch}`);
    this.epoch = epoch;
    this.claim = claim;
  }
}

/** A set file (solana-thin/set/v1) for `epoch`: bundled with the page, or from the prover. */
async function setFile(epoch) {
  let file = bundled.get(String(epoch));
  if (!file) {
    if (source() === 'file') throw new Error(`no bundled validator set for epoch ${epoch} in file mode`);
    const response = await request(`${prover()}/set/${epoch}`, `validator set, epoch ${epoch}`);
    if (!response.ok) {
      throw new Error(`the prover has no validator set for epoch ${epoch} (${response.status})`);
    }
    file = await response.json();
  }
  const params = trust.clusters[CLUSTER];
  if (file.format !== 'solana-thin/set/v1' || String(file.epoch) !== String(epoch)) {
    throw new Error(`the set file for epoch ${epoch} is not one this page reads`);
  }
  if (file.cluster !== CLUSTER || file.shred_version !== params.shredVersion) {
    throw new Error(`the set file is for ${file.cluster} at shred version ${file.shred_version}`);
  }
  return file;
}

/** Pins `epoch`'s set, held to the hash this page trusts. */
async function ensureSet(epoch) {
  const trusted = trustedHash(epoch);
  say(`Fetching the validator set for epoch ${number(epoch)}…`);
  let file;
  try {
    file = await setFile(epoch);
  } catch (error) {
    if (!trusted && source() !== 'file') throw new NeedHash(epoch, null);
    throw error;
  }
  if (!trusted) throw new NeedHash(epoch, isHash(file.set_hash) ? file.set_hash : null);
  if (file.set_hash !== trusted.hash) {
    throw new Error(
      `the validator set offered for epoch ${epoch} hashes to ${file.set_hash}, ` +
        `not the pinned ${trusted.hash}; it was refused`,
    );
  }
  // The module hashes the set itself: the file's own claim is only a shortcut.
  verifier.pin(BigInt(epoch), unhex(file.set), unhex(trusted.hash));
  pinned.add(String(epoch));
  if (tentative.has(String(epoch))) {
    store.pins[String(epoch)] = tentative.get(String(epoch));
    tentative.delete(String(epoch));
    writeStore({ prover: store.prover, pins: store.pins });
  }
  renderPins();
}

/** Verifies, pinning sets as the proof needs them. */
async function check(proof, signature) {
  for (let tries = 0; tries < 4; tries++) {
    try {
      const started = performance.now();
      const verified = verifier.verify(proof, signature ?? undefined);
      return { verified, ms: performance.now() - started };
    } catch (error) {
      if (error instanceof VerifyError && error.kind === 'EpochNotPinned' && error.epoch !== null
          && !pinned.has(String(error.epoch))) {
        await ensureSet(Number(error.epoch));
        continue;
      }
      throw error;
    }
  }
  throw new Error('the proof kept asking for another validator set');
}

// ---------------------------------------------------------------------------
// Getting a proof.

async function fetchProof(signature58, slot) {
  const url = `${prover()}/proof/${signature58}${slot ? `?slot=${slot}` : ''}`;
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    say(attempt === 1
      ? `Asking ${new URL(prover()).host} for a proof…`
      : `The prover is fetching the block from validators. Asking again (${attempt})…`);
    let response;
    try {
      response = await request(url, 'proof', { carries: true });
    } catch {
      throw new Error(
        `nothing answered at ${prover()}. Start one with "prover serve", or change the provider`,
      );
    }
    if (response.ok) return new Uint8Array(await response.arrayBuffer());
    const reason = (await response.text()).trim();
    if (response.status === 503 && Date.now() - started < 120_000) {
      await sleep(Math.min(2000 * attempt, 8000));
      continue;
    }
    throw new Error(`the prover could not prove it: ${reason || response.status}`);
  }
}

// ---------------------------------------------------------------------------
// Refusals, in words.

const REFUSALS = {
  ProofRejected: 'The proof does not hold together: its data does not hash up to the block the certificate signs.',
  CertificateRejected: 'The finality certificate does not verify against the pinned validators.',
  WrongTransaction: 'The proof is valid, but for a different transaction.',
  Malformed: 'The proof is not well formed.',
  InvalidValidatorSet: 'The validator set does not match its pinned hash.',
  EpochNotPinned: 'No validator set is pinned for the epoch this proof needs.',
};

function explain(error) {
  if (error instanceof VerifyError) {
    const plain = REFUSALS[error.kind];
    return `Refused. ${plain ? `${plain} ` : ''}(${error.kind}: ${error.message})`;
  }
  return `Not verified: ${error.message}.`;
}

// ---------------------------------------------------------------------------
// The result.

const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === 'class') node.className = value;
    else node.setAttribute(key, value);
  }
  node.append(...children.filter((c) => c !== null && c !== undefined));
  return node;
};
const mono = (text) => el('code', { class: 'value-mono' }, text);
const row = (term, ...value) => [el('dt', {}, term), el('dd', {}, ...value)];
const list = (rows) => el('dl', { class: 'facts' }, ...rows.flat());

let current = null;

function disclosure(label, ...body) {
  return el('details', {}, el('summary', {}, label), ...body);
}

function blockGrid(a) {
  const svg = (tag, attrs) => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
    return node;
  };
  // One row per FEC set, 32 data shreds across; the SVG scales to the column.
  const cell = 12;
  const size = 10;
  const width = 32 * cell;
  const height = a.fecSets * cell;
  const grid = svg('svg', { viewBox: `0 0 ${width} ${height}`, class: 'shred-grid',
    role: 'img', 'aria-label': `${a.fecSets} FEC sets of 32 shreds; the proof opens the highlighted ones` });
  const opened = new Set();
  let count = 0;
  for (const { set, first, shreds } of a.opened) {
    count += shreds;
    for (let pos = first; pos < first + shreds; pos++) opened.add(set * 32 + pos);
  }
  for (let index = 0; index < a.fecSets * 32; index++) {
    grid.append(svg('rect', {
      x: (index % 32) * cell, y: Math.floor(index / 32) * cell, width: size, height: size, rx: 1.5,
      class: opened.has(index) ? 'opened-shred' : 'closed-shred',
    }));
  }
  const labels = [];
  for (const [name, index, kind] of [['Batch start', a.componentStart, 'batch'], ['Footer', a.footerStart, 'footer']]) {
    if (index === null) continue;
    grid.append(svg('rect', {
      x: (index % 32) * cell - 1, y: Math.floor(index / 32) * cell - 1,
      width: size + 2, height: size + 2, rx: 2, class: `shred-marker ${kind}`,
    }));
    labels.push(el('span', { class: `key-${kind}` }, `${name}: shred ${number(index)}`));
  }
  return el('figure', {}, el('h4', {}, 'Block shreds'),
    el('small', {}, `${number(a.fecSets)} FEC sets (rows) of 32 data shreds`),
    el('div', { class: 'grid-scroll' }, grid),
    el('div', { class: 'legend' }, el('span', { class: 'opened-key' }, 'Opened'), ...labels),
    el('figcaption', {}, `Proof opens ${number(count)} of ${number(a.fecSets * 32)} shreds (${(a.proofBytes / 1024).toFixed(1)} KB proof). Their Merkle paths hash up to the transaction’s block id.`));
}

function proofDiagram(v) {
  const a = v.anatomy;
  const chain = [v.finalizedBy, ...a.ancestry];
  const blocks = el('ol', { class: 'chain' }, ...chain.map((block, i) =>
    el('li', {}, el('strong', {}, number(block.slot)), el('small', {},
      chain.length === 1 ? 'Certified transaction block' : i === 0 ? 'Certified block'
        : i === chain.length - 1 ? 'Transaction block' : 'Parent'))));
  const validators = el('figure', {}, el('h4', {}, 'Validator signatures'));
  for (const vote of a.aggregates) {
    const signed = new Set(vote.signers);
    const stake = Number(vote.stakeSigned) / Number(vote.stakeTotal) * 100;
    const dots = el('div', { class: 'dots', 'aria-hidden': 'true' });
    for (let rank = 0; rank < a.validators; rank++) {
      dots.append(el('i', { class: signed.has(rank) ? 'signed' : 'unsigned' }));
    }
    validators.append(el('p', { class: 'vote' }, `${vote.vote} (${v.finality} finality)`), dots,
      el('p', {}, `${number(signed.size)} of ${number(a.validators)} validators, ${stake.toFixed(1)}% of stake (${v.finality === 'fast' ? 80 : 60}% needed).`));
  }
  return el('section', { class: 'diagram' }, blockGrid(a),
    el('figure', {}, el('h4', {}, 'Block ancestry'), blocks), validators);
}

function render({ verified }, proof) {
  const tx = verified.transaction;
  const signature58 = encode(verified.transactionId);
  const time = verified.blockTimeNanos === null
    ? null
    : new Date(Number(verified.blockTimeNanos / 1_000_000n));
  const userAgent = verified.footer
    ? new TextDecoder('utf-8', { fatal: false }).decode(verified.footer.userAgent).trim()
    : '';
  current = { proof, signature58, slot: verified.slot };

  const result = $('result');
  result.replaceChildren();

  result.append(el('h3', { id: 'verdict-title' }, `Proven in finalized slot ${number(verified.slot)}`),
    proofDiagram(verified),
    disclosure('Block facts', list([
      row('Slot', number(verified.slot)), row('Block id', mono(encode(verified.blockId))),
      row('Parent', `Slot ${number(verified.parent.slot)} `, mono(encode(verified.parent.id))),
      row('Epoch', number(verified.epoch)),
      row('Leader clock', time ? time.toISOString() : 'Unavailable'),
      row('Client', userAgent || 'Unavailable'),
    ])));

  // The transaction.
  const roles = accountRoles(tx);
  const keys = tx.accountKeys.map(encode);
  const accounts = el('ol', { class: 'accounts', start: '0' },
    ...keys.map((key, i) => {
      const flags = [roles[i].signer ? 'signer' : null, roles[i].writable ? 'writable' : 'read-only',
        i === 0 ? 'fee payer' : null].filter(Boolean);
      const name = programName(key);
      return el('li', {},
        mono(key),
        el('span', { class: 'flags' }, [name, ...flags].filter(Boolean).join(', ')));
    }));

  const instructions = el('ol', { class: 'instructions' },
    ...tx.instructions.map((ix) => {
      const d = describe(tx, ix);
      const title = d.name ?? 'Instruction';
      const fields = d.fields.map((f) => row(f.label, f.kind === 'address' ? mono(f.value) : f.value));
      const touched = ix.accounts.map((index) =>
        index < keys.length ? keys[index] : `lookup table account ${index - keys.length}`);
      return el('li', {}, disclosure(
        [d.programName, title].filter(Boolean).join(' / '),
        d.program ? mono(d.program) : null,
        fields.length ? list(fields) : null,
        el('details', { class: 'raw' },
          el('summary', {}, `Accounts and data (${ix.accounts.length} accounts, ${ix.data.length} bytes)`),
          el('ol', { class: 'raw-accounts' }, ...touched.map((key) => el('li', {}, mono(key)))),
          el('p', { class: 'raw-data' }, mono(hex(ix.data) || '(no data)')))));
    }));

  const lookups = tx.version === 'v0'
    ? el('p', { class: 'help' }, 'Accounts loaded from address lookup tables are not listed: '
      + 'resolving them needs account state, which a proof of inclusion cannot open.')
    : null;

  result.append(el('section', { class: 'part' },
    el('h3', {}, 'Transaction'),
    list([
      row(tx.signatures.length > 1 ? 'Signatures' : 'Signature',
        ...tx.signatures.flatMap((s, i) => [i ? el('br') : null, mono(encode(s))])),
      row('Fee payer', mono(keys[0])),
      row('Format', tx.version === 'legacy' ? 'legacy message' : `${tx.version} message`),
      row('Recent blockhash', mono(encode(tx.recentBlockhash))),
    ]),
    disclosure(`Accounts (${keys.length})`, accounts, lookups),
    el('h4', {}, `Instructions (${tx.instructions.length})`), instructions,
    el('p', {}, 'Inclusion does not establish whether the transaction succeeded.'),
    el('div', { class: 'actions' },
      el('button', { id: 'save-proof', class: 'quiet' }, 'Save proof'),
      el('button', { id: 'copy-link', class: 'quiet' }, 'Copy link')),
    el('small', { id: 'copy-note', role: 'status' })));

  result.hidden = false;
  $('save-proof').addEventListener('click', saveProof);
  $('copy-link').addEventListener('click', copyLink);
  result.focus();
  say('');
}

function saveProof() {
  const blob = new Blob([current.proof], { type: 'application/octet-stream' });
  const a = el('a', { href: URL.createObjectURL(blob), download: `${current.signature58}.proof` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function copyLink() {
  // The signature goes after '#', which browsers never send to a server.
  const link = `${location.origin}${location.pathname}#tx=${current.signature58}&slot=${current.slot}`;
  const note = $('copy-note');
  try {
    await navigator.clipboard.writeText(link);
    note.textContent = 'Link copied. Whoever opens it learns the signature, and asks their prover for it.';
  } catch {
    note.textContent = link;
  }
}

// ---------------------------------------------------------------------------
// Pins panel.

function renderPins() {
  const epochs = new Set([...Object.keys(trust.clusters[CLUSTER].sets), ...Object.keys(store.pins)]);
  $('pins').replaceChildren(...[...epochs].sort((a, b) => b - a).map((epoch) => {
    const t = trustedHash(epoch);
    const forget = store.pins[epoch] && !trust.clusters[CLUSTER].sets[epoch]
      ? el('button', { type: 'button', class: 'quiet forget', 'data-epoch': epoch }, 'Forget')
      : null;
    return el('li', {},
      el('span', { class: 'pin-epoch' }, `Epoch ${number(Number(epoch))}`),
      mono(t.hash),
      el('span', { class: 'note' }, [t.source, pinned.has(epoch) ? 'loaded' : null].filter(Boolean).join(', ')),
      forget);
  }));
}

// ---------------------------------------------------------------------------
// The flow.

let pending = null; // what to retry once a missing hash is pinned

let busy = false;
let fragmentQueued = false;
const source = () => $('settings').elements.source.value;
const sourceNames = { own: 'Your own prover', other: 'Another prover', file: 'A proof file' };

function syncSource() {
  const mode = source();
  for (const name of ['own', 'other']) {
    $(`${name}-config`).hidden = mode !== name;
    $(`${name}-url`).disabled = mode !== name;
  }
  $('input-title').textContent = mode === 'file' ? 'Proof file' : 'Signature';
  $('lookup').hidden = mode === 'file';
  $('file-input').hidden = mode !== 'file';
}

function step(n) {
  for (let i = 1; i <= 3; i++) {
    $(`step-${i}`).classList.toggle('active', n === i);
    if (n === i) $(`step-${i}`).setAttribute('aria-current', 'step');
    else $(`step-${i}`).removeAttribute('aria-current');
  }
  $('settings').hidden = n !== 1;
  $('input-body').hidden = n !== 2;
  $('change-provider').hidden = n < 2;
  $('change-input').hidden = n < 3;
  $('provider-summary').textContent = n === 1 ? '' : source() === 'file'
    ? sourceNames.file : `${sourceNames[source()]} (${prover()})`;
  if (n !== 3) {
    current = pending = null;
    $('input-summary').textContent = '';
    $('need-hash').hidden = $('result').hidden = true;
    $('pin-hash').value = '';
    say('');
  }
}

function editStep(n) {
  step(n);
  const input = n === 1 ? $('settings').querySelector(':checked')
    : source() === 'file' ? $('proof-file') : $('signature');
  input.focus();
}

async function run(job) {
  $('need-hash').hidden = true;
  if (busy) return;
  busy = true;
  step(3);
  $('input-summary').textContent = job.label;
  $('change-input').setAttribute('aria-label', `Change ${$('input-title').textContent.toLowerCase()}`);
  $('result').hidden = true;
  $('change-provider').disabled = $('change-input').disabled = true;
  try {
    const { proof, signature } = await job.proof();
    say('Verifying…');
    render(await check(proof, signature), proof);
  } catch (error) {
    if (error instanceof NeedHash) {
      pending = job;
      askForHash(error);
      say(`Stopped: no hash is pinned for epoch ${number(error.epoch)}.`, 'bad');
    } else {
      $('result').hidden = true;
      say(explain(error), 'bad');
    }
  } finally {
    busy = false;
    $('change-provider').disabled = $('change-input').disabled = false;
    if (fragmentQueued) {
      fragmentQueued = false;
      fromFragment();
    }
  }
}

function askForHash({ epoch, claim }) {
  const panel = $('need-hash');
  panel.dataset.epoch = String(epoch);
  panel.querySelectorAll('[data-epoch]').forEach((n) => { n.textContent = number(epoch); });
  $('prover-claim').hidden = !claim;
  if (claim) panel.querySelector('[data-claim]').textContent = claim;
  $('take-claim').dataset.claim = claim ?? '';
  $('result').hidden = true;
  panel.hidden = false;
  $('pin-hash').focus();
}

async function pinHash(hash, source) {
  const epoch = $('need-hash').dataset.epoch;
  tentative.set(epoch, { hash, source });
  if (pending) await run(pending);
  tentative.delete(epoch);
  // Refused: keep the panel open for another try.
  if (!pinned.has(epoch)) $('need-hash').hidden = false;
}

function forgetPin(epoch) {
  delete store.pins[epoch];
  writeStore({ prover: store.prover, pins: store.pins });
  // The module keeps a set once pinned; a fresh page starts without it.
  renderPins();
  say(`Forgot your hash for epoch ${number(Number(epoch))}. It stays loaded until the page is reloaded.`);
}

const lookupJob = (signature58, slot) => ({
  label: signature58.length > 18 ? `${signature58.slice(0, 8)}…${signature58.slice(-8)}` : signature58,
  async proof() {
    const signature = decode(signature58);
    if (!signature || signature.length !== 64) {
      throw new Error('that is not a transaction signature: 64 bytes in base58');
    }
    if (slot && !/^\d+$/.test(slot)) throw new Error('a slot is a whole number');
    return { proof: await fetchProof(signature58, slot), signature };
  },
});

const fileJob = (file) => ({
  label: file.name,
  async proof() {
    say(`Reading ${file.name}…`);
    return { proof: new Uint8Array(await file.arrayBuffer()), signature: null };
  },
});

const exampleJob = () => ({
  label: 'Mainnet example',
  async proof() {
    say('Loading the example proof from this site…');
    const response = await request('example/proof.bin', 'example proof');
    if (!response.ok) throw new Error('this build has no example proof');
    return { proof: new Uint8Array(await response.arrayBuffer()), signature: null };
  },
});

function fromFragment() {
  const params = new URLSearchParams(location.hash.slice(1));
  const tx = params.get('tx');
  if (!tx) return;
  if (busy) {
    fragmentQueued = true;
    return;
  }
  selectSavedProvider();
  step(2);
  $('signature').value = tx;
  const slot = params.get('slot') ?? '';
  $('slot').value = slot;
  run(lookupJob(tx, slot));
}

function selectSavedProvider() {
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(new URL(store.prover).hostname);
  const mode = local ? 'own' : 'other';
  $('settings').elements.source.value = mode;
  $(`${mode}-url`).value = store.prover;
  syncSource();
}

async function start() {
  watchResources();
  selectSavedProvider();
  step(1);
  $('settings').addEventListener('change', syncSource);
  say('Loading the verifier…');
  try {
    const [trustResponse, moduleResponse, bundledResponse] = await Promise.all([
      request('trust.json', 'pinned set hashes'),
      request('solana_thin_wasm.wasm', 'the verifier'),
      request('sets/index.json', 'list of bundled sets'),
    ]);
    trust = await trustResponse.json();
    if (bundledResponse.ok) {
      const epochs = (await bundledResponse.json()).map(String);
      const files = await Promise.all(epochs.map(async (epoch) => {
        const response = await request(`sets/${epoch}.json`, `validator set, epoch ${epoch}`);
        return response.ok ? response.json() : null;
      }));
      epochs.forEach((epoch, i) => { if (files[i]) bundled.set(epoch, files[i]); });
    }
    const { Verifier } = await load(new Uint8Array(await moduleResponse.arrayBuffer()));
    const params = trust.clusters[CLUSTER];
    verifier = params.warmup
      ? Verifier.withWarmup(params.shredVersion, BigInt(params.slotsPerEpoch))
      : Verifier.withoutWarmup(params.shredVersion, BigInt(params.slotsPerEpoch));
  } catch (error) {
    say(`The verifier did not load: ${error.message}.`, 'bad');
    return;
  }
  renderPins();
  say('');
  $('continue').disabled = false;
  $('change-provider').addEventListener('click', () => editStep(1));
  $('change-input').addEventListener('click', () => editStep(2));

  $('lookup').addEventListener('submit', (event) => {
    event.preventDefault();
    const signature58 = $('signature').value.trim();
    if (!signature58) {
      say('Paste a transaction signature first.', 'bad');
      $('signature').focus();
      return;
    }
    run(lookupJob(signature58, $('slot').value.trim()));
  });
  $('proof-file').addEventListener('change', (event) => {
    const [file] = event.target.files;
    if (file) run(fileJob(file));
    event.target.value = '';
  });
  $('example').addEventListener('click', () => run(exampleJob()));
  $('settings').addEventListener('submit', (event) => {
    event.preventDefault();
    if (source() === 'file') return editStep(2);
    const value = $(`${source()}-url`).value.trim();
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error();
      store.prover = url.href;
      writeStore({ prover: store.prover, pins: store.pins });
      editStep(2);
    } catch {
      say('A prover is an http or https address.', 'bad');
    }
  });
  $('pin-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const hash = $('pin-hash').value.trim().toLowerCase();
    if (!isHash(hash)) {
      say('A set hash is 64 hexadecimal characters.', 'bad');
      return;
    }
    pinHash(hash, 'pasted by you');
  });
  $('take-claim').addEventListener('click', (event) => {
    pinHash(event.target.dataset.claim, `the word of ${new URL(prover()).host}`);
  });
  document.addEventListener('dragover', (event) => event.preventDefault());
  document.addEventListener('drop', (event) => {
    event.preventDefault();
    const [file] = event.dataTransfer.files;
    if (!file || busy) return;
    $('settings').elements.source.value = 'file';
    syncSource();
    step(2);
    run(fileJob(file));
  });
  $('pins').addEventListener('click', (event) => {
    if (event.target.matches('button.forget')) forgetPin(event.target.dataset.epoch);
  });
  window.addEventListener('hashchange', fromFragment);
  fromFragment();
}

start();
