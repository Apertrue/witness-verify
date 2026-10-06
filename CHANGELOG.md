# Changelog

## Unreleased

First public release of the Witness receipt verifier, split out of the proving crate so it can be published on its own.

- Decodes and verifies batch receipts (receipt version 5), enrolment proofs (version 2) and membership proofs (version 2).
- Derives verifier keys locally from the circuit shapes and exposes `vk_digest` for pinning.
- Bounded decoding: bincode with fixed-width integers, size caps, 2 to 64 windows per batch, trailing bytes refused, canonical field elements and on-curve points enforced.
- Builds for `wasm32-unknown-unknown`, wrapped for the browser by `witness-verify-wasm`.
- Examples: `verify_call` verifies a receipt and its membership proof; `vk_digests` prints every derived key digest.
