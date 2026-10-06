// Verdict parity between the native verifier and the wasm one, over the
// tamper corpus (witness-prover/examples/tamper_corpus.rs). Every case must
// reach the same verdict in both, that verdict must be the expected one,
// and an accepted receipt must give the same summary in both.
//
//   cargo run --release -p witness-prover --example tamper_corpus -- <corpus>
//   cargo build --release -p witness-prover --bin batch_verify
//   cargo build --profile wasmrel --target wasm32-unknown-unknown -p witness-verify-wasm
//   wasm-bindgen --target nodejs --out-dir <pkg> \
//     target/wasm32-unknown-unknown/wasmrel/witness_verify_wasm.wasm
//   node witness-verify-wasm/parity.mjs <pkg> target/release/batch_verify <corpus>
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const [pkg, native, corpus] = process.argv.slice(2);
if (!pkg || !native || !corpus) {
  console.error('usage: node parity.mjs <wasm-pkg> <batch_verify> <corpus>');
  process.exit(2);
}
const wasm = createRequire(import.meta.url)(resolve(pkg, 'witness_verify_wasm.js'));
const canonical = (json) => JSON.stringify(JSON.parse(json));
const verdict = (summary) => (summary === null ? 'refuse' : 'accept');

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
    inWasm = canonical(wasm.verify(readFileSync(file)));
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
console.log(`${lines.length} cases, ${disagreements} disagreements`);
process.exit(disagreements ? 1 : 0);
