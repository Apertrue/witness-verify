//! membership_verify <proof.bin>
//! membership_verify --vk-digest
//!
//! Verifies one enrolment membership proof and prints what it
//! establishes as JSON on stdout. Exit 0: valid. Exit 1: refused, with
//! the reason on stderr. Exit 2: usage or unreadable input. The service
//! runs this once per call; what it then binds the call to comes from
//! the JSON, never from the client's own statement.
//!
//! `--vk-digest` prints, as hex, the SHA-256 of the verifier key this
//! binary derives (exit 0). A deployment compares it with the digest
//! in PINNED_KEYS.md before trusting this binary's verdicts.

use std::process::exit;
use witness_verify::membership::{MembershipReceipt, MembershipVerifier, MAX_MEMBERSHIP_BYTES};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--vk-digest" {
        match MembershipVerifier::new().vk_digest() {
            Ok(digest) => {
                println!("{}", hex::encode(digest));
                exit(0)
            }
            Err(e) => {
                eprintln!("no verifier key: {e}");
                exit(2)
            }
        }
    }
    if args.len() != 2 {
        eprintln!("usage: membership_verify <proof.bin>");
        eprintln!("       membership_verify --vk-digest");
        exit(2);
    }
    // One handle, bounded, as batch_verify reads a receipt: a file that
    // grows between sizing and reading cannot be buffered whole.
    let bytes = {
        use std::io::Read;
        let cap = MAX_MEMBERSHIP_BYTES;
        let file = match std::fs::File::open(&args[1]) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("cannot read {}: {e}", args[1]);
                exit(2);
            }
        };
        let mut bytes = Vec::new();
        if let Err(e) = file.take(cap + 1).read_to_end(&mut bytes) {
            eprintln!("cannot read {}: {e}", args[1]);
            exit(2);
        }
        if bytes.len() as u64 > cap {
            eprintln!("refused: proof is over the {cap} byte cap");
            exit(1);
        }
        bytes
    };
    let receipt = match MembershipReceipt::decode(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("refused: {e}");
            exit(1);
        }
    };
    match MembershipVerifier::new().verify(&receipt) {
        Ok(summary) => {
            println!(
                "{{\"root\":\"{}\",\"blinded\":\"{}\"}}",
                hex::encode(summary.root),
                hex::encode(summary.blinded)
            );
            exit(0)
        }
        Err(e) => {
            eprintln!("refused: {e}");
            exit(1)
        }
    }
}
