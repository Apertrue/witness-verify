//! Enrolment membership, blinded per call.
//!
//! One Vega single-circuit proof, made once at the start of a call:
//! I hold a registry leaf under this signed root, and the value this
//! call's receipts publish opens to the commitment that leaf embeds.
//!
//! The leaf is `P2(leaf_tag, template.., C)`, so this circuit works over
//! the CANCELABLE TEMPLATE and takes `C` as a single witness field. It
//! never sees raw bits and never computes the transform, which would be
//! ~490k random-index lookups. It does not need to: what makes `C`
//! well-formed is the batch receipt, which proves the same `B` opens to
//! a commitment of the bits its windows were matched against. Equal `B`
//! across the two proofs forces equal `C`, so the registry entry and the
//! measurements are joined by collision resistance rather than by
//! anyone's word. That is a stronger statement than this circuit could
//! make alone: not "C commits to some bits" but "C commits to the bits
//! these windows were matched against".
//!
//! Neither the template nor `C` appears in public, so two calls from one
//! camera publish unrelated values. What the verifier learns is the
//! registry root, public anyway, and a number fresh every call.
//!
//! Public: `[root, blinded]`.
//! Private: the 146 template chunks, `C`, the Merkle path, the blind.
use crate::batch::E;
use crate::chain::{chunk_field, field_to_be, tag, Chunk, NCHUNK};
use crate::circuits::{alloc_public, enforce_boolean, pin};
use crate::poseidon2::{self, hash_gadget, Lc};
use crate::registry::{node_tag, root_from_path, DEPTH};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use vega_prover::traits::{circuit::VegaCircuit, snark::R1CSSNARKTrait, Engine};
use vega_prover::vega_sc_zkp::VegaZkSNARK;

/// The blinding tag, so a blinded commitment can never be read as a
/// chain digest, a registry node, or the commitment itself.
pub fn blind_tag() -> Fr {
    tag("witness-enrolment-v3:blind")
}

/// What a call publishes in place of the enrolment commitment.
pub fn blinded(commitment: Fr, blind: Fr) -> Fr {
    poseidon2::hash(&[blind_tag(), commitment, blind])
}

/// Public value positions.
pub mod membership_io {
    pub const ROOT: usize = 0;
    pub const BLINDED: usize = 1;
    pub const LEN: usize = 2;
}

#[derive(Clone, Debug)]
pub struct MembershipCircuit<E: Engine> {
    /// The cancelable template, packed as the raw chunks are.
    pub template: Vec<Chunk>,
    /// `C`, the enrolment commitment over the RAW bits: one field, taken
    /// as a witness rather than recomputed, because the transform
    /// between the two is not something a circuit can afford.
    pub commitment: Fr,
    pub siblings: [Fr; DEPTH],
    pub index: u64,
    pub blind: Fr,
    pub leaf: Fr,
    pub root: Fr,
    pub blinded: Fr,
    _p: PhantomData<E>,
}

impl<E: Engine<Scalar = Fr>> MembershipCircuit<E> {
    /// None when the index is outside the tree's address space, which the
    /// path walk cannot represent.
    pub fn new(
        template: Vec<Chunk>,
        commitment: Fr,
        siblings: [Fr; DEPTH],
        index: u64,
        blind: Fr,
    ) -> Option<Self> {
        assert_eq!(template.len(), NCHUNK);
        let leaf = crate::registry::leaf(&template, commitment);
        let root = root_from_path(leaf, index, &siblings)?;
        Some(Self {
            template,
            commitment,
            siblings,
            index,
            blind,
            leaf,
            root,
            blinded: blinded(commitment, blind),
            _p: PhantomData,
        })
    }
}

impl<E: Engine<Scalar = Fr>> VegaCircuit<E> for MembershipCircuit<E> {
    fn public_values(&self) -> Result<Vec<Fr>, SynthesisError> {
        Ok(vec![self.root, self.blinded])
    }

    fn shared<CS: ConstraintSystem<Fr>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Fr>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Fr>],
        _precommitted: &[AllocatedNum<Fr>],
        _challenges: Option<&[Fr]>,
    ) -> Result<(), SynthesisError> {
        // The template chunks enter as field elements rather than bits:
        // nothing here needs their bits, and the leaf binds them.
        let mut fields = Vec::with_capacity(NCHUNK);
        for (c, chunk) in self.template.iter().enumerate() {
            let v = AllocatedNum::alloc(cs.namespace(|| format!("template {c}")), || {
                Ok(chunk_field(chunk))
            })?;
            fields.push(Lc::var(v.get_variable(), v.get_value()));
        }
        // `C` as one witness field. Its well-formedness is established
        // by the batch receipt through the shared blinded value, not
        // here: see the module doc.
        let commitment =
            AllocatedNum::alloc(cs.namespace(|| "commitment"), || Ok(self.commitment))?;
        let commitment_lc = Lc::var(commitment.get_variable(), commitment.get_value());
        let blind = AllocatedNum::alloc(cs.namespace(|| "blind"), || Ok(self.blind))?;

        // leaf = P2(leaf_tag, template.., C)
        let mut leaf_inputs = Vec::with_capacity(2 + NCHUNK);
        leaf_inputs.push(Lc::constant(crate::registry::leaf_tag()));
        leaf_inputs.extend(fields);
        leaf_inputs.push(commitment_lc.clone());
        let leaf = hash_gadget(&mut cs.namespace(|| "leaf"), &leaf_inputs)?;
        let leaf = leaf.materialise(&mut cs.namespace(|| "leaf"), "pin")?;

        // The published value opens to that same C.
        let blinded_form = hash_gadget(
            &mut cs.namespace(|| "blinded"),
            &[
                Lc::constant(blind_tag()),
                commitment_lc,
                Lc::var(blind.get_variable(), blind.get_value()),
            ],
        )?;
        // And the leaf sits under the root, by the published path.
        let minus_one = Fr::ZERO - Fr::ONE;
        let mut node = leaf;
        for i in 0..DEPTH {
            let right = (self.index >> i) & 1 == 1;
            let b = AllocatedNum::alloc(cs.namespace(|| format!("bit {i}")), || {
                Ok(if right { Fr::ONE } else { Fr::ZERO })
            })?;
            enforce_boolean(cs, &format!("bit {i} bool"), b.get_variable());
            let sib =
                AllocatedNum::alloc(cs.namespace(|| format!("sib {i}")), || Ok(self.siblings[i]))?;
            let sib_lc = Lc::var(sib.get_variable(), sib.get_value());
            // d = b * (sib - node), so the pair is (node + d, sib - d):
            // the identity when b is zero, the swap when it is one.
            let diff = sib_lc.add(&node.scale(minus_one));
            let d = AllocatedNum::alloc(cs.namespace(|| format!("d {i}")), || {
                let bv = b.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let dv = diff.value.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(bv * dv)
            })?;
            cs.enforce(
                || format!("swap {i}"),
                |lc| lc + b.get_variable(),
                |_| diff.lc::<CS>(),
                |lc| lc + d.get_variable(),
            );
            let d_lc = Lc::var(d.get_variable(), d.get_value());
            let left_in = node.add(&d_lc);
            let right_in = sib_lc.add(&d_lc.scale(minus_one));
            let out = hash_gadget(
                &mut cs.namespace(|| format!("level {i}")),
                &[Lc::constant(node_tag()), left_in, right_in],
            )?;
            node = out.materialise(&mut cs.namespace(|| format!("level {i}")), "pin")?;
        }
        // Inputized LAST, after every witness allocation, and in IO
        // order. Interleaving `inputize` with witness allocation makes
        // the single-circuit prover and its verifier disagree on the
        // round-0 challenges, so a genuine proof fails to verify. Cost
        // an hour to find; do not move these up.
        let root_pub = alloc_public(cs, "root", self.root)?;
        pin(cs, "root", &node, &root_pub);
        let blinded_pub = alloc_public(cs, "blinded", self.blinded)?;
        pin(cs, "blinded", &blinded_form, &blinded_pub);
        Ok(())
    }
}

/// A membership proof as it leaves the machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipReceipt {
    pub version: u32,
    pub root: [u8; 32],
    pub blinded: [u8; 32],
    pub proof: Vec<u8>,
}

/// Bumped to 2 with the v3 leaf: a version-1 proof proves membership of
/// a leaf this registry does not hold, and must read as the wrong
/// version rather than as a proof that fails to verify.
pub const MEMBERSHIP_VERSION: u32 = 2;

/// The size cap on a membership proof, as the receipt has one: bytes are
/// bounded before anything is parsed out of them.
pub const MAX_MEMBERSHIP_BYTES: u64 = 4 << 20;

impl MembershipReceipt {
    pub fn decode(bytes: &[u8]) -> Result<Self, MembershipError> {
        use bincode::Options;
        if bytes.len() as u64 > MAX_MEMBERSHIP_BYTES {
            return Err(MembershipError::Malformed);
        }
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_MEMBERSHIP_BYTES)
            .deserialize(bytes)
            .map_err(|_| MembershipError::Malformed)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("a membership receipt serialises")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipError {
    Version(u32),
    Malformed,
    Proof(String),
    Setup(String),
}

impl std::fmt::Display for MembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MembershipError::Version(v) => write!(f, "unknown membership version {v}"),
            MembershipError::Malformed => write!(f, "the membership proof did not parse"),
            MembershipError::Proof(s) => write!(f, "the membership proof does not verify: {s}"),
            MembershipError::Setup(s) => write!(f, "key setup failed: {s}"),
        }
    }
}

impl std::error::Error for MembershipError {}

/// What a verified membership proof establishes, taken from the proof's
/// own public values and never from the receipt's stated fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSummary {
    pub root: [u8; 32],
    pub blinded: [u8; 32],
}

type Snark = VegaZkSNARK<E>;
type Pk = <Snark as R1CSSNARKTrait<E>>::ProverKey;
type Vk = <Snark as R1CSSNARKTrait<E>>::VerifierKey;

/// The membership verifier. Keys depend only on the circuit's shape,
/// which is fixed, so there is one pair and it is made on first use
/// (about a second) and reused for the life of the process. The prover in
/// witness-prover wraps one and shares its keys.
#[derive(Default)]
pub struct MembershipVerifier {
    keys: Mutex<Option<(Pk, Vk)>>,
    setups: AtomicUsize,
}

/// The shape the keys are derived from: values do not matter, only the
/// circuit's structure, so a zero enrolment at index zero will do.
fn shape_circuit() -> MembershipCircuit<E> {
    MembershipCircuit::new(
        vec![[0u8; 28]; NCHUNK],
        Fr::ZERO,
        [Fr::ZERO; DEPTH],
        0,
        Fr::ZERO,
    )
    .expect("index zero is inside every tree")
}

impl MembershipVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Key setups run so far: the observable a test needs to show that a
    /// refused proof asked for none.
    pub fn setups(&self) -> usize {
        self.setups.load(Ordering::SeqCst)
    }

    /// Runs `f` with the key pair, making it on first use. Public for the
    /// prover, which proves under the prover key of the same setup;
    /// verification reads only the verifier key.
    #[doc(hidden)]
    pub fn with_keys<T>(&self, f: impl FnOnce(&Pk, &Vk) -> T) -> Result<T, MembershipError> {
        let mut keys = self.keys.lock().unwrap();
        if keys.is_none() {
            self.setups.fetch_add(1, Ordering::SeqCst);
            let made = Snark::setup(shape_circuit())
                .map_err(|e| MembershipError::Setup(format!("{e:?}")))?;
            *keys = Some(made);
        }
        let (pk, vk) = keys.as_ref().expect("just set");
        Ok(f(pk, vk))
    }

    /// Makes the keys now rather than on the first proof.
    pub fn warm(&self) -> Result<(), MembershipError> {
        self.with_keys(|_, _| ())
    }

    /// SHA-256 over the verifier key as bincode: the value to pin, as
    /// `BatchVerifier::vk_digest` is for a batch size.
    pub fn vk_digest(&self) -> Result<[u8; 32], MembershipError> {
        use sha2::Digest;
        self.with_keys(|_, vk| {
            let bytes = bincode::serialize(vk).expect("a verifier key serialises");
            sha2::Sha256::digest(bytes).into()
        })
    }

    /// Verifies one, returning what it establishes. The summary comes
    /// from the proof's public values; the receipt's stated root and
    /// blinded value are checked against them, never trusted.
    pub fn verify(
        &self,
        receipt: &MembershipReceipt,
    ) -> Result<MembershipSummary, MembershipError> {
        if receipt.version != MEMBERSHIP_VERSION {
            return Err(MembershipError::Version(receipt.version));
        }
        if receipt.proof.len() as u64 > MAX_MEMBERSHIP_BYTES {
            return Err(MembershipError::Malformed);
        }
        let proof: Snark = {
            use bincode::Options;
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(MAX_MEMBERSHIP_BYTES)
                .deserialize(&receipt.proof)
                .map_err(|_| MembershipError::Malformed)?
        };
        let io = self
            .with_keys(|_, vk| proof.verify(vk))?
            .map_err(|e| MembershipError::Proof(format!("{e:?}")))?;
        if io.len() != membership_io::LEN {
            return Err(MembershipError::Proof("unexpected public IO shape".into()));
        }
        let root = field_to_be(&io[membership_io::ROOT]);
        let blinded_value = field_to_be(&io[membership_io::BLINDED]);
        if root != receipt.root || blinded_value != receipt.blinded {
            return Err(MembershipError::Proof(
                "the receipt does not state what the proof establishes".into(),
            ));
        }
        Ok(MembershipSummary {
            root,
            blinded: blinded_value,
        })
    }
}

/// The root a receipt names, read without verifying.
pub fn stated_root(bytes: &[u8]) -> Result<[u8; 32], MembershipError> {
    Ok(MembershipReceipt::decode(bytes)?.root)
}
