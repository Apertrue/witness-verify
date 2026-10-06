//! batch_verify <receipt.bin>
//! batch_verify --vk-digest <windows>
//!
//! Verifies one batch receipt and prints its summary as JSON on stdout.
//! Exit 0: valid (the summary is what the proof establishes). Exit 1:
//! refused, with the reason on stderr. Exit 2: usage or unreadable input.
//! The service runs this per posted batch; what it publishes about a call
//! comes from the JSON, never from the client's own statement.
//!
//! `--vk-digest <windows>` prints, as hex, the SHA-256 of the verifier key
//! this binary derives for a batch of that many windows (exit 0), or exits
//! 2 for a size the verifier does not accept. A deployment compares it with
//! the digests in PINNED_KEYS.md before trusting this binary's verdicts.

use std::process::exit;
use witness_verify::{BatchReceipt, BatchVerifier};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--vk-digest" {
        let n = match args[2].parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("usage: batch_verify --vk-digest <windows>");
                exit(2);
            }
        };
        match BatchVerifier::new().vk_digest(n) {
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
        eprintln!("usage: batch_verify <receipt.bin>");
        eprintln!("       batch_verify --vk-digest <windows>");
        exit(2);
    }
    // One handle, bounded: the file is read through a cap rather than
    // sized first and read second, so a file that grows between the two
    // cannot be buffered whole. A receipt is a few hundred kilobytes.
    let bytes = {
        use std::io::Read;
        let cap = witness_verify::batch::MAX_RECEIPT_BYTES;
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
            eprintln!("refused: receipt is over the {cap} byte cap");
            exit(1);
        }
        bytes
    };
    let receipt = match BatchReceipt::decode(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("refused: {e}");
            exit(1);
        }
    };
    match BatchVerifier::new().verify(&receipt) {
        Ok(summary) => {
            println!("{}", summary.to_json());
            exit(0)
        }
        Err(e) => {
            eprintln!("refused: {e}");
            exit(1)
        }
    }
}
