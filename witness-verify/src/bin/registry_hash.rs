//! Poseidon2 hashing for the registry, speaking the pedersen helper's
//! line protocol so the service can swap backends without new plumbing:
//!
//!   {"id": 1, "inputs": ["0x01", "0x02"]}    -> {"id": 1, "hash": "0x..."}
//!   {"id": 2, "batch": [["0x01"], ["0x02"]]} -> {"id": 2, "hashes": ["0x..."]}
//!
//! Inputs are hashed exactly as given (the caller supplies any domain
//! tag), with the same strictness as the pedersen helper: non-hex or a
//! value at or above the BN254 modulus is an error, never a reduction.
use std::io::{BufRead, Write};

use witness_verify::chain::{field_to_be, try_field_be};
use witness_verify::poseidon2;

fn parse_field(s: &str) -> Result<halo2curves::bn256::Fr, String> {
    let clean = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if clean.is_empty() || clean.len() > 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("not hex: {s}"));
    }
    let mut be = [0u8; 32];
    let padded = format!("{clean:0>64}");
    for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
        be[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    try_field_be(&be).ok_or_else(|| format!("field element >= modulus: {s}"))
}

fn hash_inputs(inputs: &[serde_json::Value]) -> Result<String, String> {
    let fields = inputs
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| "field must be a hex string".to_string())
                .and_then(parse_field)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fields.is_empty() {
        return Err("no inputs".into());
    }
    let h = poseidon2::hash(&fields);
    Ok(format!(
        "0x{}",
        field_to_be(&h)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(
                    stdout.lock(),
                    "{}",
                    serde_json::json!({"error": format!("bad json: {e}")})
                );
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let reply = if let Some(inputs) = req.get("inputs").and_then(|v| v.as_array()) {
            match hash_inputs(inputs) {
                Ok(h) => serde_json::json!({"id": id, "hash": h}),
                Err(e) => serde_json::json!({"id": id, "error": e}),
            }
        } else if let Some(batch) = req.get("batch").and_then(|v| v.as_array()) {
            let mut hashes = Vec::with_capacity(batch.len());
            let mut failure = None;
            for entry in batch {
                match entry
                    .as_array()
                    .ok_or_else(|| "batch entries must be arrays".to_string())
                    .and_then(|inputs| hash_inputs(inputs))
                {
                    Ok(h) => hashes.push(serde_json::Value::String(h)),
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
            match failure {
                None => serde_json::json!({"id": id, "hashes": hashes}),
                Some(e) => serde_json::json!({"id": id, "error": e}),
            }
        } else {
            serde_json::json!({"id": id, "error": "expected inputs or batch"})
        };
        if writeln!(stdout.lock(), "{reply}").is_err() {
            break;
        }
    }
}
