#!/usr/bin/env bash
# Builds the browser verifier the Witness verify page serves, and prints the
# SHA-256 of each file so it can be compared with the release and the page.
#
#   scripts/build_wasm.sh [out-dir]        # default: target/wasm-out
#
# Needs the toolchain in rust-toolchain.toml (with the wasm32-unknown-unknown
# target) and wasm-bindgen-cli 0.2.127.
#
# rustc writes the source path of every dependency into panic messages, so
# without a remap the file would name the folder it was built in. The two
# remaps below give every builder the same neutral paths. They change strings
# only, never code.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
out="${1:-$repo/target/wasm-out}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

want_bindgen="0.2.127"
have_bindgen="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')"
if [ "$have_bindgen" != "$want_bindgen" ]; then
    echo "build_wasm: needs wasm-bindgen $want_bindgen (found ${have_bindgen:-none}):" >&2
    echo "  cargo install wasm-bindgen-cli --version $want_bindgen --locked" >&2
    exit 2
fi

# Flags from the environment would change the build, so none are carried in.
unset RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTFLAGS
sep=$'\x1f'
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$cargo_home/registry/src=/cargo/registry/src${sep}--remap-path-prefix=$cargo_home/git/checkouts=/cargo/git/checkouts"

cd "$repo"
cargo build --locked --profile wasmrel --target wasm32-unknown-unknown -p witness-verify-wasm
mkdir -p "$out"
wasm-bindgen --target no-modules --out-dir "$out" \
    target/wasm32-unknown-unknown/wasmrel/witness_verify_wasm.wasm

cd "$out"
shasum -a 256 witness_verify_wasm_bg.wasm witness_verify_wasm.js 2>/dev/null \
    || sha256sum witness_verify_wasm_bg.wasm witness_verify_wasm.js
