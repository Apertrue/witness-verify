# Third-party notices

witness-verify is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). It incorporates or depends on the following third-party work, whose notices are kept here.

## Poseidon2 parameters, from Aztec's barretenberg

The Poseidon2 round constants and internal diagonal in `witness-verify/src/constants.rs` (Poseidon2 over the BN254 scalar field, width 4, exponent 5, eight external and 56 internal rounds) match, all 260 values in order, the parameters in Aztec's barretenberg:

- Repository: [AztecProtocol/aztec-packages](https://github.com/AztecProtocol/aztec-packages)
- Revision: `8c7eb07b84eda9bcb3951fbacaa3529f6a726ae6`
- File: `barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2_params.hpp`

barretenberg is licensed under the Apache License 2.0:

```
Copyright 2023 Spilsbury Holdings Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

The complete notice from that revision's `barretenberg/LICENSE` is retained byte for byte in [third_party/poseidon2/LICENSE](third_party/poseidon2/LICENSE) (SHA-256 `677540d945f4d7b296a885c1a08c0af3e53dcfe66f591c88c507d1a8c5cf1ea7`). The upstream header attributes parameter generation to Markus Schofnegger of Horizen Labs. How the comparison was made is recorded in [PARAMETER_PROVENANCE.md](PARAMETER_PROVENANCE.md).

## Spartan2, via the vega-prover fork

The proving backend is [vega-prover](https://github.com/Apertrue/vega-prover), Apertrue's fork of Microsoft's [Spartan2](https://github.com/microsoft/Spartan2), pinned by commit in `witness-verify/Cargo.toml`. Spartan2 is licensed under the MIT License:

```
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
```

The licence file from the pinned revision is kept in [third_party/spartan2/LICENSE](third_party/spartan2/LICENSE).

## Other dependencies

The remaining Rust dependencies are fetched from crates.io under their own licences, which `cargo deny check` (see `deny.toml`) holds to the permissive set the workspace allows.
