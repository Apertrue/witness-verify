//! Verifies one batch receipt, and optionally the call's membership proof,
//! and prints what they establish.
//!
//!   cargo run --release --example verify_call -- <receipt.bin> [<membership.bin>]
//!
//! Exit code 0 when everything verifies, 1 when anything is refused.
use std::process::ExitCode;
use witness_verify::membership::{MembershipReceipt, MembershipVerifier};
use witness_verify::{BatchReceipt, BatchVerifier};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(receipt_path) = args.first() else {
        eprintln!("usage: verify_call <receipt.bin> [<membership.bin>]");
        return ExitCode::from(2);
    };

    // Decoding is bounded: oversized input, trailing bytes and unknown
    // layouts are refused before any key is derived.
    let bytes = std::fs::read(receipt_path).expect("read the receipt");
    let receipt = match BatchReceipt::decode(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("refused: {e}");
            return ExitCode::from(1);
        }
    };

    // Keys are derived here from the circuit shape for this batch size.
    // Compare this digest with your pinned table before trusting a verdict.
    let batch = BatchVerifier::new();
    match batch.vk_digest(receipt.windows) {
        Ok(d) => println!(
            "batch key ({} windows): {}",
            receipt.windows,
            hex::encode(d)
        ),
        Err(e) => {
            eprintln!("refused: {e}");
            return ExitCode::from(1);
        }
    }
    let summary = match batch.verify(&receipt) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("refused: {e}");
            return ExitCode::from(1);
        }
    };
    println!("{}", summary.to_json());

    if let Some(path) = args.get(1) {
        let bytes = std::fs::read(path).expect("read the membership proof");
        let membership = MembershipVerifier::new();
        let verified = MembershipReceipt::decode(&bytes).and_then(|m| membership.verify(&m));
        match verified {
            // The membership proof and the receipt are joined by the
            // blinded value: both must state the same one.
            Ok(m) if m.blinded == summary.blinded => {
                println!(
                    "membership key: {}",
                    hex::encode(membership.vk_digest().unwrap())
                );
                println!("registry root: {}", hex::encode(m.root));
            }
            Ok(_) => {
                eprintln!("refused: the membership proof is for another call");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("refused: {e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
