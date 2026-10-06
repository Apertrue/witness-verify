//! Derives the verifier keys from the circuit shapes and prints their
//! SHA-256 digests, one per line: `batch <n> <hex>` for every batch size
//! from MIN_BATCH to MAX_BATCH, then `membership <hex>`.
//!
//!   cargo run --release --example vk_digests            # every size
//!   cargo run --release --example vk_digests -- 2 3     # just these sizes
//!
//! Release only in practice: key setup in a debug build is slow.
use witness_verify::batch::{MAX_BATCH, MIN_BATCH};
use witness_verify::membership::MembershipVerifier;
use witness_verify::BatchVerifier;

fn main() {
    let sizes: Vec<usize> = {
        let given: Vec<usize> = std::env::args()
            .skip(1)
            .map(|a| a.parse().expect("a batch size"))
            .collect();
        if given.is_empty() {
            (MIN_BATCH..=MAX_BATCH).collect()
        } else {
            given
        }
    };
    for n in sizes {
        // A fresh verifier per size, so only one key is held at a time.
        match BatchVerifier::new().vk_digest(n) {
            Ok(d) => println!("batch {n} {}", hex::encode(d)),
            Err(e) => println!("batch {n} refused: {e}"),
        }
    }
    let m = MembershipVerifier::new().vk_digest().expect("membership key setup");
    println!("membership {}", hex::encode(m));
}
