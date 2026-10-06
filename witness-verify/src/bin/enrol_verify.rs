//! enrol_verify <receipt.bin>
//!
//! Verifies one enrolment-time binding proof (enrol_proof_v1) and
//! prints what it establishes as JSON on stdout. Exit 0: valid. Exit
//! 1: refused, with the reason on stderr. Exit 2: usage or unreadable
//! input. The service runs this once at device approval; what it then
//! records about the leaf comes from the JSON, never from the client's
//! own statement. The shape is rebuilt from the receipt's own seed, so
//! verification takes seconds, once, at a moment nobody is waiting on.

use std::process::exit;
use witness_verify::enrol::{verify, EnrolReceipt, MAX_ENROL_BYTES};

fn main() {
    // args_os, not args: a non-UTF-8 path must reach File::open and the
    // exit-2 path, not panic in argument collection.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: enrol_verify <receipt.bin>");
        exit(2);
    }
    let bytes = {
        use std::io::Read;
        let cap = MAX_ENROL_BYTES;
        let path = std::path::Path::new(&args[1]);
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("cannot read {}: {e}", path.display());
                exit(2);
            }
        };
        let mut bytes = Vec::new();
        if let Err(e) = file.take(cap + 1).read_to_end(&mut bytes) {
            eprintln!(
                "cannot read {}: {e}",
                std::path::Path::new(&args[1]).display()
            );
            exit(2);
        }
        if bytes.len() as u64 > cap {
            eprintln!("refused: receipt is over the {cap} byte cap");
            exit(1);
        }
        bytes
    };
    let receipt = match EnrolReceipt::decode(&bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("refused: {e}");
            exit(1);
        }
    };
    match verify(&receipt) {
        Ok(summary) => {
            println!(
                "{{\"leaf\":\"{}\",\"domain\":\"{}\",\"weightCommitment\":\"{}\"}}",
                hex::encode(summary.leaf),
                hex::encode(summary.domain),
                hex::encode(summary.weight_commitment)
            );
            exit(0)
        }
        Err(e) => {
            eprintln!("refused: {e}");
            exit(1)
        }
    }
}
