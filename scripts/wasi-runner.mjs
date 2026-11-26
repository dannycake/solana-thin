// Runs a wasm32-wasip1 program under node's built-in WASI, as cargo's runner
// for that target: node wasi-runner.mjs <program.wasm> [arguments...]
//
// The program sees the whole filesystem at the same paths, as a native test
// binary would: the tests read their vectors from the repository.
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const [program, ...rest] = process.argv.slice(2);
const wasi = new WASI({
  version: 'preview1',
  args: [program, ...rest],
  env: process.env,
  preopens: { '/': '/' },
});
const { instance } = await WebAssembly.instantiate(await readFile(program), wasi.getImportObject());
process.exitCode = wasi.start(instance);
