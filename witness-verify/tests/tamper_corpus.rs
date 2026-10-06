//! The tamper corpus, run through the native verifier.
//!
//! `fixtures/tamper-corpus/` holds 206 batch receipts written by the
//! devices repository's prover (witness-prover's `tamper_corpus` example,
//! at the commit this repository was extracted from): four untouched
//! receipts and 202 attacks on them, from flipped proof bits and edited
//! public values to instances mixed in from another batch, edited stated
//! fields and non-canonical encodings. `cases.tsv` lists each case with the
//! verdict it must reach and the attack it makes.
//!
//! Each case must reach its verdict here exactly as it did in the source
//! repository's verifier: an accepted receipt must give byte for byte the
//! summary that verifier printed (`<case>.summary.json`), and a refused
//! one must be refused for the same reason (`reasons.tsv`). So the
//! extraction is checked against the code it was extracted from, not only
//! against itself.
//!
//! Release only in practice: key setup in a debug build is slow.
//!   cargo test --release --test tamper_corpus

use std::collections::BTreeMap;
use std::path::PathBuf;

use witness_verify::{BatchReceipt, BatchVerifier};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/tamper-corpus")
}

fn read(name: &str) -> String {
    let path = corpus().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Decodes and verifies, as `batch_verify` does: the summary JSON on
/// acceptance, the refusal's message otherwise.
fn check(verifier: &BatchVerifier, bytes: &[u8]) -> Result<String, String> {
    let receipt = BatchReceipt::decode(bytes).map_err(|e| e.to_string())?;
    verifier
        .verify(&receipt)
        .map(|s| s.to_json())
        .map_err(|e| e.to_string())
}

#[test]
fn every_case_reaches_the_verdict_the_source_verifier_reached() {
    let reasons: BTreeMap<String, String> = read("reasons.tsv")
        .lines()
        .map(|l| {
            let (name, reason) = l.split_once('\t').expect("name<TAB>reason");
            (name.to_string(), reason.to_string())
        })
        .collect();

    let verifier = BatchVerifier::new();
    let (mut accepted, mut refused) = (0, 0);
    let mut failures = Vec::new();
    for line in read("cases.tsv").lines() {
        let mut cols = line.split('\t');
        let (name, expected, attack) = (
            cols.next().expect("name"),
            cols.next().expect("verdict"),
            cols.next().expect("attack"),
        );
        let bytes = std::fs::read(corpus().join(format!("{name}.bin"))).expect("case bytes");
        match (expected, check(&verifier, &bytes)) {
            ("accept", Ok(json)) => {
                let pinned = read(&format!("{name}.summary.json"));
                if json != pinned.trim_end() {
                    failures.push(format!("{name}: accepted with a different summary"));
                }
                accepted += 1;
            }
            ("refuse", Err(reason)) => {
                match reasons.get(name) {
                    Some(pinned) if *pinned == reason => {}
                    Some(pinned) => failures.push(format!(
                        "{name}: refused for {reason:?}, the source refused for {pinned:?}"
                    )),
                    None => failures.push(format!("{name}: no recorded reason")),
                }
                refused += 1;
            }
            ("accept", Err(reason)) => failures.push(format!(
                "{name}: refused ({reason}), must accept ({attack})"
            )),
            ("refuse", Ok(_)) => failures.push(format!("{name}: accepted, must refuse ({attack})")),
            (other, _) => failures.push(format!("{name}: unknown verdict {other:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        (accepted, refused),
        (4, 202),
        "the corpus is 4 accepted and 202 refused"
    );
    assert_eq!(reasons.len(), 202, "one recorded reason per refused case");
}
