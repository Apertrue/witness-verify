//! The batch receipt verifier, for the page.
//!
//! The verifier key is derived, not downloaded: `warm` runs the same
//! deterministic key setup the service runs (the keys depend only on the
//! circuit shape and the batch size), so the page ships about 1.5 MB of
//! wasm and no key material. `verify` returns the verified summary as JSON;
//! everything in it comes from the proof's public IO.
use wasm_bindgen::prelude::*;
use witness_verify::membership::{MembershipReceipt, MembershipVerifier};
use witness_verify::BatchVerifier;

/// The batch sizes whose verifier keys the page holds at once. wasm32 has
/// 4 GiB of memory and one size's keys take hundreds of MiB, so a cache
/// keeping every size it met ran out on a call with many sizes and the
/// module aborted mid-verify (17 October 2026). A size beyond these is
/// derived again when it next comes, a few seconds, never a wrong verdict.
const RETAINED_SIZES: usize = 2;

fn verifier() -> &'static BatchVerifier {
    // One verifier for the page's lifetime: keys for the last few batch
    // sizes, verifier keys only.
    static PROVER: std::sync::OnceLock<BatchVerifier> = std::sync::OnceLock::new();
    PROVER.get_or_init(|| BatchVerifier::for_verifying(RETAINED_SIZES))
}

fn batch_size(batch_size: f64) -> Result<usize, JsError> {
    // A JavaScript number crosses the boundary as it is: only a finite,
    // integral, non-negative size reaches the verifier, which then bounds
    // it itself.
    if !batch_size.is_finite() || batch_size.fract() != 0.0 || batch_size < 0.0 {
        return Err(JsError::new("batch size is not a non-negative integer"));
    }
    Ok(batch_size.min(usize::MAX as f64) as usize)
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

/// Derives the keys for a batch size ahead of the first receipt.
#[wasm_bindgen]
pub fn warm(batch_size: f64) -> Result<(), JsError> {
    let n = self::batch_size(batch_size)?;
    verifier()
        .warm(n)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// SHA-256 of the verifier key derived for a batch size, as hex: the
/// value `prover/witness-prover/tests/keys.rs` pins. The page compares it
/// with the pinned table before it trusts a verdict for that size. The
/// keys are the ones `warm` and `verify` use, made once per size.
#[wasm_bindgen]
pub fn vk_digest(batch_size: f64) -> Result<String, JsError> {
    let n = self::batch_size(batch_size)?;
    verifier()
        .vk_digest(n)
        .map(|d| hex(&d))
        .map_err(|e| JsError::new(&format!("{e}")))
}

fn membership() -> &'static MembershipVerifier {
    static PROVER: std::sync::OnceLock<MembershipVerifier> = std::sync::OnceLock::new();
    PROVER.get_or_init(MembershipVerifier::new)
}

/// SHA-256 of the membership circuit's verifier key, as hex: the value
/// `prover/witness-prover/tests/keys.rs` pins.
#[wasm_bindgen]
pub fn membership_vk_digest() -> Result<String, JsError> {
    membership()
        .vk_digest()
        .map(|d| hex(&d))
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Derives the membership circuit's verifier key ahead of the first
/// proof. One shape, so one key, and it is the same derivation the
/// service runs.
#[wasm_bindgen]
pub fn warm_membership() -> Result<(), JsError> {
    membership()
        .warm()
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Verifies one enrolment membership proof and returns what it
/// establishes as JSON: the registry root it names and the blinded
/// enrolment it opens to. Both come from the proof's public values.
#[wasm_bindgen]
pub fn verify_membership(proof: &[u8]) -> Result<String, JsError> {
    let receipt = MembershipReceipt::decode(proof).map_err(|e| JsError::new(&format!("{e}")))?;
    let summary = membership()
        .verify(&receipt)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Ok(format!(
        "{{\"root\":\"{}\",\"blinded\":\"{}\"}}",
        hex(&summary.root),
        hex(&summary.blinded)
    ))
}

/// Verifies one serialised receipt and returns its summary as JSON.
#[wasm_bindgen]
pub fn verify(receipt: &[u8]) -> Result<String, JsError> {
    let receipt =
        witness_verify::BatchReceipt::decode(receipt).map_err(|e| JsError::new(&format!("{e}")))?;
    let summary = verifier()
        .verify(&receipt)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(summary.to_json())
}

/// Poseidon2 over the given big-endian hex field elements, for the page's
/// registry path check: the caller supplies any domain tag as an input.
#[wasm_bindgen]
pub fn hash_fields(hex_fields: Vec<String>) -> Result<String, JsError> {
    if hex_fields.is_empty() {
        return Err(JsError::new("no inputs"));
    }
    let mut fields = Vec::with_capacity(hex_fields.len());
    for s in &hex_fields {
        let clean = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if clean.is_empty() || clean.len() > 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(JsError::new(&format!("not hex: {s}")));
        }
        let mut be = [0u8; 32];
        let padded = format!("{clean:0>64}");
        for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
            be[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                .map_err(|e| JsError::new(&format!("{e}")))?;
        }
        fields.push(
            witness_verify::chain::try_field_be(&be)
                .ok_or_else(|| JsError::new(&format!("field element >= modulus: {s}")))?,
        );
    }
    let h = witness_verify::poseidon2::hash(&fields);
    let hex: String = witness_verify::chain::field_to_be(&h)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!("0x{hex}"))
}
