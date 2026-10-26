# Changelog

## Unreleased

First public release of the Witness receipt verifier, split out of the proving crate so it can be published on its own.

- Decodes and verifies batch receipts (receipt version 5), enrolment proofs (version 2) and membership proofs (version 2).
- Derives verifier keys locally from the circuit shapes and exposes `vk_digest` for pinning.
- Bounded decoding: bincode with fixed-width integers, size caps, 2 to 64 windows per batch, trailing bytes refused, canonical field elements and on-curve points enforced.
- Builds for `wasm32-unknown-unknown`, wrapped for the browser by `witness-verify-wasm`.
- Examples: `verify_call` verifies a receipt and its membership proof; `vk_digests` prints every derived key digest.
- Command-line verifiers: `batch_verify`, `enrol_verify`, `membership_verify` and `registry_hash`.
- The 206-case tamper corpus as fixtures, run by `cargo test`, and every verifier key digest in `PINNED_KEYS.md`, checked by CI.
- Licensed under Apache 2.0.
- The browser verifier's key cache is bounded, so a page that verifies many receipts in one worker no longer grows past wasm32's 4 GiB; `parity.mjs` runs every case through one wasm instance to catch that, and can fail on a memory ceiling.
- `release_if_idle` and `held` let an app drop the verifier's keys between calls, and a key cache left unusable by a failed build recovers on the next use.
