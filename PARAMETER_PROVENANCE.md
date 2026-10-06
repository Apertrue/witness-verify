# Poseidon2 parameter reference

The Rust table in `witness-verify/src/constants.rs` and the Swift table in the
Apertrue devices repository (`swift/SensorCore/Sources/SensorCore/Poseidon2.swift`) contain identical ordered
values: 256 round constants and four internal diagonal-minus-one values for
Poseidon2 over the BN254 scalar field, width 4, exponent 5, eight external rounds
and 56 internal rounds.

On 2 October 2026, both tables were compared numerically with this immutable
upstream reference:

- Repository: [AztecProtocol/aztec-packages](https://github.com/AztecProtocol/aztec-packages).
- Revision: `8c7eb07b84eda9bcb3951fbacaa3529f6a726ae6`.
- File: [`barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2_params.hpp`](https://github.com/AztecProtocol/aztec-packages/blob/8c7eb07b84eda9bcb3951fbacaa3529f6a726ae6/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2_params.hpp).
- Reference file SHA-256: `b7fe515e7792e6a101737f2aa10f98ae5cbb50addd5c822962ae7dc8adc7988d`.

All 260 values match, in order, across both local tables and that reference.
For a format-independent comparison, encode each scalar as exactly 32 bytes,
unsigned big-endian, concatenate in declaration order and compute SHA-256:

| Table | Values | SHA-256 of concatenated scalar encodings |
| --- | ---: | --- |
| Round constants | 256 | `a113481f5f579ad1e1d61f70257ad90c271993130aadb7318b53147336b1db36` |
| Internal diagonal minus one | 4 | `a89a15f00b1f7244f62e72e519dc36d90f845961d1fcd62bb655fe1935e236b5` |

The upstream header attributes parameter generation to Markus Schofnegger of
Horizen Labs and references a Sage generator. That attribution is preserved
here; the generator revision, execution environment and a reproduced generation
transcript have not been established by this comparison.

## Notice and scope

The complete notice from that revision's
[`barretenberg/LICENSE`](https://github.com/AztecProtocol/aztec-packages/blob/8c7eb07b84eda9bcb3951fbacaa3529f6a726ae6/barretenberg/LICENSE)
is retained byte-for-byte in [third_party/poseidon2/LICENSE](third_party/poseidon2/LICENSE).
It contains the Apache License 2.0 text and the upstream copyright notice.
Its SHA-256 is `677540d945f4d7b296a885c1a08c0af3e53dcfe66f591c88c507d1a8c5cf1ea7`.
This records a notice accompanying the verified reference; it does not assign
a license to first-party code or establish complete historical import rights.

This pinned reference corroborates numerical correspondence. It is **not** a
claim that the original import used this exact upstream revision: that import
revision is not recorded. It also does not establish parameter-generation
correctness, sponge equivalence, cryptographic soundness, source-to-release
reproducibility or an external audit of Witness. Those require their own
evidence. Existing cross-language vectors and circuit tests address separate,
finite behavioral properties.

No constants, arithmetic, circuit constraints, verification-key pins, dependency
revisions or receipt formats were changed when adding this record.
