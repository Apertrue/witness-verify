//! Verifying one batch of windows.
//!
//! The keys depend only on the batch size, so they are made once per size
//! and reused. A receipt carries the proof, the batch size and
//! the public values the verifier needs to pin it: the chain it continues,
//! the head it starts from and the blinded enrolment it compares
//! against. The verifier re-derives all of those from the proof's own
//! public IO and refuses anything that does not line up.

use crate::chain::{field_to_be, try_field_be, Window, NCHUNK};
use crate::circuits::{core_io, step_io, CoreCircuit, StepCircuit};
use ff::Field;
use halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use vega_prover::{
    errors::VegaError,
    provider::Bn254Engine,
    vega_mc_zkp::{VegaMcProverKey, VegaMcVerifierKey, VegaMcZkSNARK},
};

pub type E = Bn254Engine;

/// The smallest batch NeutronNova folds.
pub const MIN_BATCH: usize = 2;
/// The largest batch a receipt may claim: bounds the keys a verifier will
/// make and the memory a receipt can ask for. A call batches far below it.
pub const MAX_BATCH: usize = 64;
/// The most bytes a receipt may be. A 64-window receipt is well under 1 MB.
pub const MAX_RECEIPT_BYTES: u64 = 4 << 20;

/// One window's public verdict, as the receipt states it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowVerdict {
    pub window_index: u64,
    pub frames: u64,
    pub degenerate: bool,
    pub passed: bool,
    /// The window's picture root, from the proof's public IO.
    pub picture_root: [u8; 32],
    pub head_in: [u8; 32],
    pub head_out: [u8; 32],
}

/// A batch receipt: what leaves the machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchReceipt {
    /// The receipt format; bump when the circuit or the prover changes.
    pub version: u32,
    pub windows: usize,
    pub chain_id: [u8; 16],
    pub blinded: [u8; 32],
    pub genesis: [u8; 32],
    pub head_in: [u8; 32],
    pub head_out: [u8; 32],
    pub verdicts: Vec<WindowVerdict>,
    pub proof: Vec<u8>,
}

/// Bumped on every change to what the core circuit proves, so a receipt
/// of another version is refused as a version rather than failing later
/// as a proof that does not verify. 2: the commitment became blinded.
/// 3: the commitment gained its tag, the registry domain and the
/// enrolment nonce, which is what lets it match a v3 registry leaf.
/// 4: the link carries the window's picture root, made public, and the
/// chain tags moved to v3 (spec/COMMIT_AND_DELIVER.md).
/// 5: every window is judged against the camera's committed limit, which
/// joins the commitment, and a degenerate window never passes
/// (spec/PER_CAMERA_THRESHOLD.md).
pub const RECEIPT_VERSION: u32 = 5;

impl BatchReceipt {
    /// Parses receipt bytes under the size cap, before anything is
    /// allocated or derived from them. Bytes past the end of the receipt
    /// are refused, so one receipt has one encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, VerifyError> {
        use bincode::Options;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(VerifyError::Malformed);
        }
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_RECEIPT_BYTES)
            .deserialize(bytes)
            .map_err(|_| VerifyError::Malformed)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("a receipt serialises")
    }
}

/// What a verified receipt establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSummary {
    pub chain_id: [u8; 16],
    pub blinded: [u8; 32],
    pub genesis: [u8; 32],
    pub head_in: [u8; 32],
    pub head_out: [u8; 32],
    pub verdicts: Vec<WindowVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Version(u32),
    TooSmall(usize),
    TooLarge(usize),
    Proof(String),
    Malformed,
    Chain(usize),
    Link(usize),
    Header(usize),
    Stated,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Version(v) => write!(f, "unsupported receipt version {v}"),
            VerifyError::TooSmall(n) => {
                write!(
                    f,
                    "a batch holds at least {MIN_BATCH} windows, this one claims {n}"
                )
            }
            VerifyError::TooLarge(n) => {
                write!(
                    f,
                    "a batch holds at most {MAX_BATCH} windows, this one claims {n}"
                )
            }
            VerifyError::Proof(s) => write!(f, "the proof does not verify: {s}"),
            VerifyError::Malformed => write!(f, "proof bytes do not parse"),
            VerifyError::Chain(i) => write!(f, "window {i} names a different chain"),
            VerifyError::Link(i) => {
                write!(f, "window {i} does not continue from the previous head")
            }
            VerifyError::Header(i) => write!(f, "window {i} carries an out-of-range header field"),
            VerifyError::Stated => write!(f, "the receipt's stated values differ from the proof's"),
        }
    }
}
impl std::error::Error for VerifyError {}

/// Keys per batch size, made on first use. Setup is deterministic: the
/// same size gives the same keys on every machine, so a verifier needs no
/// key file, only the size.
type KeyPair = (VegaMcProverKey<E>, VegaMcVerifierKey<E>);

/// The batch verifier: the key cache per batch size and the checks a
/// receipt must pass. The prover in witness-prover wraps one, so both
/// sides share the cache and derive their keys the same way.
pub struct BatchVerifier {
    keys: Mutex<HashMap<usize, KeyPair>>,
    /// How many key setups have run: the observable a test needs to show
    /// that a refused receipt asked for none.
    setups: std::sync::atomic::AtomicUsize,
}

/// A batch size keys are made for.
pub fn batch_size_ok(n: usize) -> bool {
    (MIN_BATCH..=MAX_BATCH).contains(&n)
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// A fixed shape to derive keys from: the keys depend on the circuit
/// shape and the batch size, not on the values.
fn shape_circuits(n: usize) -> (StepCircuit<E>, CoreCircuit<E>) {
    let enrolled = vec![[0u8; 28]; NCHUNK];
    let window = Window {
        chain_id: [0u8; 16],
        window_index: 0,
        frames: 0,
        degenerate: false,
        picture_root: [0u8; 32],
        fresh: vec![[0u8; 28]; NCHUNK],
    };
    let _ = n;
    (
        StepCircuit::new(window, enrolled.clone(), crate::chain::TAU, Fr::ZERO),
        CoreCircuit::new(
            enrolled,
            crate::chain::TAU,
            [0u8; 16],
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
        ),
    )
}

impl BatchVerifier {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            setups: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Key setups run so far.
    pub fn setups(&self) -> usize {
        self.setups.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Runs `f` with the keys for batch size `n`, making them on first
    /// use. Public for the prover, which proves under the prover key of
    /// the same setup; verification reads only the verifier key.
    #[doc(hidden)]
    pub fn with_keys<T>(
        &self,
        n: usize,
        f: impl FnOnce(&VegaMcProverKey<E>, &VegaMcVerifierKey<E>) -> T,
    ) -> T {
        assert!(batch_size_ok(n), "batch size checked by every caller");
        let mut keys = self.keys.lock().unwrap();
        let (pk, vk) = keys.entry(n).or_insert_with(|| {
            self.setups
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (step, core) = shape_circuits(n);
            VegaMcZkSNARK::<E>::setup(&step, &core, n).expect("key setup")
        });
        f(pk, vk)
    }

    /// Drops the keys for a batch size, if made; the next use makes them
    /// again. The opening batch's keys are used once per stream and are the
    /// largest single allocation the app holds for the rest of a call.
    pub fn forget(&self, n: usize) {
        self.keys.lock().unwrap().remove(&n);
    }

    /// Makes the keys for a batch size now rather than on first use.
    pub fn warm(&self, n: usize) -> Result<(), VerifyError> {
        if n < MIN_BATCH {
            return Err(VerifyError::TooSmall(n));
        }
        if n > MAX_BATCH {
            return Err(VerifyError::TooLarge(n));
        }
        self.with_keys(n, |_, _| ());
        Ok(())
    }

    /// SHA-256 over the verifier key for a batch size, as bincode. The key
    /// is derived from the circuits on both sides and never read from a
    /// receipt, so this is the value that moves when the circuits do: a
    /// test pins it, and a deployment can pin it too.
    pub fn vk_digest(&self, n: usize) -> Result<[u8; 32], VerifyError> {
        use sha2::Digest;
        if n < MIN_BATCH {
            return Err(VerifyError::TooSmall(n));
        }
        if n > MAX_BATCH {
            return Err(VerifyError::TooLarge(n));
        }
        Ok(self.with_keys(n, |_, vk| {
            let bytes = bincode::serialize(vk).expect("a verifier key serialises");
            sha2::Sha256::digest(bytes).into()
        }))
    }

    /// Verifies a receipt and returns what it establishes. Everything in
    /// the summary comes from the proof's public IO; the receipt's own
    /// stated fields are checked against it, never trusted.
    pub fn verify(&self, receipt: &BatchReceipt) -> Result<BatchSummary, VerifyError> {
        if receipt.version != RECEIPT_VERSION {
            return Err(VerifyError::Version(receipt.version));
        }
        let n = receipt.windows;
        if n < MIN_BATCH {
            return Err(VerifyError::TooSmall(n));
        }
        // Bound the claimed size before any key is made for it and before
        // the proof is parsed: a receipt must not be able to ask for work.
        if n > MAX_BATCH || receipt.verdicts.len() != n {
            return Err(VerifyError::TooLarge(n));
        }
        if receipt.proof.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(VerifyError::Malformed);
        }
        // The proof parses under the same rules: no bytes past its end.
        let proof: VegaMcZkSNARK<E> = {
            use bincode::Options;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(MAX_RECEIPT_BYTES)
                .deserialize(&receipt.proof)
                .map_err(|_| VerifyError::Malformed)?
        };
        let (step_io, core_io) =
            self.with_keys(n, |_, vk| proof.verify(vk, n))
                .map_err(|e| match e {
                    // The prover writes the shared commitment once and vega's
                    // verifier copies it into every instance, so vega refuses a
                    // proof whose instances carry their own copy, or which lacks
                    // its one copy. Bytes in those places would give a valid
                    // proof a second encoding: malformed, not a failed check.
                    VegaError::InvalidSharedCommitment { .. } => VerifyError::Malformed,
                    e => VerifyError::Proof(format!("{e:?}")),
                })?;
        if core_io.len() != core_io::LEN || step_io.len() != n {
            return Err(VerifyError::Proof("unexpected public IO shape".into()));
        }

        let chain_id = core_io[core_io::CHAIN_ID];
        let mut prev = step_io[0][step_io::HEAD_IN];
        let mut verdicts = Vec::with_capacity(n);
        for (i, io) in step_io.iter().enumerate() {
            if io.len() != step_io::LEN {
                return Err(VerifyError::Proof("unexpected step IO shape".into()));
            }
            if io[step_io::CHAIN_ID] != chain_id {
                return Err(VerifyError::Chain(i));
            }
            if io[step_io::HEAD_IN] != prev {
                return Err(VerifyError::Link(i));
            }
            prev = io[step_io::HEAD_OUT];
            let window_index =
                small(io[step_io::WINDOW_INDEX], 48).ok_or(VerifyError::Header(i))?;
            let frames = small(io[step_io::FRAMES], 48).ok_or(VerifyError::Header(i))?;
            let degenerate = small(io[step_io::DEGENERATE], 1).ok_or(VerifyError::Header(i))?;
            let passed = small(io[step_io::PASSED], 1).ok_or(VerifyError::Header(i))?;
            verdicts.push(WindowVerdict {
                window_index,
                frames,
                degenerate: degenerate == 1,
                passed: passed == 1,
                picture_root: field_to_be(&io[step_io::PICTURE_ROOT]),
                head_in: field_to_be(&io[step_io::HEAD_IN]),
                head_out: field_to_be(&io[step_io::HEAD_OUT]),
            });
        }

        let summary = BatchSummary {
            chain_id: chain_id_bytes(chain_id)
                .ok_or(VerifyError::Proof("chain id too wide".into()))?,
            blinded: field_to_be(&core_io[core_io::BLINDED]),
            genesis: field_to_be(&core_io[core_io::GENESIS]),
            head_in: field_to_be(&step_io[0][step_io::HEAD_IN]),
            head_out: field_to_be(&prev),
            verdicts,
        };

        // The receipt may state what it proves, but only exactly.
        if summary.chain_id != receipt.chain_id
            || summary.blinded != receipt.blinded
            || summary.genesis != receipt.genesis
            || summary.head_in != receipt.head_in
            || summary.head_out != receipt.head_out
            || summary.verdicts != receipt.verdicts
        {
            return Err(VerifyError::Stated);
        }
        Ok(summary)
    }
}

/// A field element that is a non-negative integer below 2^bits.
fn small(f: Fr, bits: u32) -> Option<u64> {
    let be = field_to_be(&f);
    if be[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let v = u64::from_be_bytes(be[24..].try_into().unwrap());
    if bits < 64 && v >= 1u64 << bits {
        return None;
    }
    Some(v)
}

fn chain_id_bytes(f: Fr) -> Option<[u8; 16]> {
    let be = field_to_be(&f);
    if be[..16].iter().any(|b| *b != 0) {
        return None;
    }
    Some(be[16..].try_into().unwrap())
}

/// Parses a stated head back into a field element (for callers chaining
/// receipts natively); None when the bytes are not a canonical element.
pub fn head_field(head: &[u8; 32]) -> Option<Fr> {
    try_field_be(head)
}
