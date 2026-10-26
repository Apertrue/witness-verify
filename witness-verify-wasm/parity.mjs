// Verdict parity between the native verifier and the wasm one. Every case
// must reach the same verdict in both, that verdict must be the expected
// one, and an accepted receipt must give the same summary in both. All
// cases run through ONE wasm instance, in the corpus's order, as the
// page's worker runs a call's receipts: a module that only fails once it
// has met many receipts (the 17 October 2026 trap, a key cache that grew
// past wasm32's 4 GiB) fails here too. A trap is a failure of the check,
// never a refusal.
//
// A corpus is a directory of <name>.bin and cases.tsv. The tamper corpus
// is in fixtures/tamper-corpus; a shape matrix (every batch size the
// prover makes) is written by the devices repository's prover, and either
// runs here. Build the two verifiers, the wasm one as the page ships it,
// from the repository root:
//   cargo build --release -p witness-verify --bin batch_verify
//   cargo build --profile wasmrel --target wasm32-unknown-unknown -p witness-verify-wasm
//   wasm-bindgen --target no-modules --out-dir <pkg> \
//     target/wasm32-unknown-unknown/wasmrel/witness_verify_wasm.wasm
//   node witness-verify-wasm/parity.mjs <pkg> target/release/batch_verify fixtures/tamper-corpus [max-MiB]
//
// <pkg> may also be a `--target nodejs` build. With max-MiB, the run also
// fails when the module's memory grew past that many MiB.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import vm from 'node:vm';

const [pkg, native, corpus, maxMiB] = process.argv.slice(2);
if (!pkg || !native || !corpus) {
  console.error('usage: node parity.mjs <wasm-pkg> <batch_verify> <corpus> [max-MiB]');
  process.exit(2);
}

// The page's glue (--target no-modules, what verifier.worker.js loads with
// importScripts) defines a global wasm_bindgen; a nodejs build exports.
async function load(dir) {
  const glue = readFileSync(resolve(dir, 'witness_verify_wasm.js'), 'utf8');
  if (!/^let wasm_bindgen\b/m.test(glue)) {
    const m = createRequire(import.meta.url)(resolve(dir, 'witness_verify_wasm.js'));
    return { api: m, memory: () => m.__wasm && m.__wasm.memory };
  }
  globalThis.self = globalThis;
  // The glue's `let wasm_bindgen` is a global binding, not a property.
  const api = vm.runInThisContext(`${glue}\n;wasm_bindgen`);
  const bytes = readFileSync(resolve(dir, 'witness_verify_wasm_bg.wasm'));
  const exports = await api({ module_or_path: await WebAssembly.compile(bytes) });
  return { api, memory: () => exports.memory };
}
const { api: wasm, memory } = await load(pkg);
const mib = () => {
  const m = memory();
  return m ? Math.round(m.buffer.byteLength / 1048576) : null;
};
const canonical = (json) => JSON.stringify(JSON.parse(json));
const verdict = (summary) => (summary === null ? 'refuse' : 'accept');

// The page's own sequence first (verifier.worker.js): warm the usual
// 16-window key and the membership key, then, per receipt, derive the
// key for its size and hash it (the pin check) before verifying. The
// membership key stays held for the page's life, so the memory figure
// counts it.
wasm.vk_digest(16);
wasm.membership_vk_digest();
wasm.warm_membership();
const sizeOf = (bytes) => (bytes.length >= 12
  ? Number(Buffer.from(bytes).readBigUInt64LE(4)) : -1);

let disagreements = 0;
const lines = readFileSync(resolve(corpus, 'cases.tsv'), 'utf8').trim().split('\n');
for (const line of lines) {
  const [name, expected, attack] = line.split('\t');
  const file = resolve(corpus, `${name}.bin`);
  // wasm.verify returns a summary or throws. A throw counts as a refusal
  // only when it is the verifier's own JsError; anything else (a module
  // that failed to load or trapped) is a failure of the check, and its
  // message is printed either way.
  let inWasm = null;
  let wasmError = null;
  try {
    const bytes = readFileSync(file);
    const n = sizeOf(bytes);
    if (n >= 2 && n <= 64) wasm.vk_digest(n);
    inWasm = canonical(wasm.verify(bytes));
  } catch (e) {
    wasmError = e;
  }
  if (wasmError && !(wasmError instanceof Error && wasmError.name === 'Error')) {
    disagreements++;
    console.log(`FAIL ${name}: the wasm verifier could not check it (${wasmError})`);
    continue;
  }
  const run = spawnSync(native, [file], { encoding: 'utf8' });
  if (run.status !== 0 && run.status !== 1) {
    disagreements++;
    console.log(`FAIL ${name}: the native verifier could not check it (exit ${run.status})`);
    continue;
  }
  const inNative = run.status === 0 ? canonical(run.stdout) : null;
  const agree = verdict(inNative) === verdict(inWasm)
    && verdict(inNative) === expected
    && inNative === inWasm;
  if (!agree) disagreements++;
  console.log(`${agree ? 'ok  ' : 'FAIL'} ${name}: native ${verdict(inNative)}, `
    + `wasm ${verdict(inWasm)}, expected ${expected} (${attack})`);
}
const peak = mib();
console.log(`${lines.length} cases, ${disagreements} disagreements`
  + (peak === null ? '' : `, wasm memory ${peak} MiB`));
if (maxMiB && peak !== null && peak > Number(maxMiB)) {
  console.log(`FAIL the wasm module's memory grew to ${peak} MiB, past ${maxMiB}`);
  process.exit(1);
}
process.exit(disagreements ? 1 : 0);
