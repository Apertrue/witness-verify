# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue or pull request.

Security reports: email security@apertrue.photo. Please do not open a public issue for a vulnerability.

Include what you found, the version or commit, and the receipt bytes or steps that reproduce it, if you have them. We will acknowledge your report, keep you informed while we work on it, and credit you in the fix unless you would rather we did not.

## What is in scope

- A receipt, enrolment proof or membership proof that verifies but states something its circuit does not establish.
- A receipt with more than one accepted encoding, or input that decoding should refuse and does not.
- Input that makes the verifier allocate, derive keys or work beyond the documented bounds.
- A difference in verdict or summary between the native verifier and the WebAssembly build.
- A derived verifier key that differs from the pinned digests on an unchanged circuit.

## What is out of scope

The limits stated in the README under "Limits" are known boundaries, not vulnerabilities: a screen or a mask in front of the enrolled camera, a computer with its protections switched off, hardware spliced into the camera module, and the voice.

Problems in the Witness service, the apps or the website are welcome too, at the same contact.
