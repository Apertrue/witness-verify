//! Verifies one Witness receipt file and prints what it establishes.
//!
//! ```text
//! cargo run --release --example verify -- batch      receipt.bin
//! cargo run --release --example verify -- membership membership.bin
//! cargo run --release --example verify -- enrol      enrol.bin
//! ```
//!
//! Exits 0 when the proof verifies and 1 when it is refused. Keys are
//! derived here from the circuit shapes on first use, so the first
//! verification of each batch size takes a few seconds.

use std::process::ExitCode;
use witness_verify::{enrol, membership, BatchReceipt, BatchVerifier};

fn run(kind: &str, bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    match kind {
        "batch" => {
            // Bounded decode first: size cap, fixed-width integers, no
            // trailing bytes. Nothing is derived from a receipt that fails.
            let receipt = BatchReceipt::decode(bytes)?;
            let verifier = BatchVerifier::new();
            let summary = verifier.verify(&receipt)?;
            // The digest of the key this receipt was checked under. A
            // deployment compares it with its pinned value.
            let digest = verifier.vk_digest(receipt.windows)?;
            Ok(format!(
                "key {}\n{}",
                hex::encode(digest),
                summary.to_json()
            ))
        }
        "membership" => {
            let receipt = membership::MembershipReceipt::decode(bytes)?;
            let verifier = membership::MembershipVerifier::new();
            let summary = verifier.verify(&receipt)?;
            // Compare `root` with the registry's published root, and
            // `blinded` with the batch receipts of the same call.
            Ok(format!(
                "key {}\nroot {}\nblinded {}",
                hex::encode(verifier.vk_digest()?),
                hex::encode(summary.root),
                hex::encode(summary.blinded)
            ))
        }
        "enrol" => {
            let receipt = enrol::EnrolReceipt::decode(bytes)?;
            let summary = enrol::verify(&receipt)?;
            Ok(format!(
                "leaf {}\ndomain {}\nweight commitment {}",
                hex::encode(summary.leaf),
                hex::encode(summary.domain),
                hex::encode(summary.weight_commitment)
            ))
        }
        other => Err(format!("unknown kind {other:?}: use batch, membership or enrol").into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [kind, path] = args.as_slice() else {
        eprintln!("usage: verify <batch|membership|enrol> <file>");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    match run(kind, &bytes) {
        Ok(out) => {
            println!("verified\n{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("refused: {e}");
            ExitCode::from(1)
        }
    }
}
