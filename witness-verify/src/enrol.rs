//! The enrolment-time binding proof (enrol_proof_v1).
//!
//! Proves, from ONE witness of the raw stability bits, that the registry
//! leaf's template and commitment describe the same sensor:
//!
//! ```text
//! template[m] = majority_15( raw[taps(seed)[m,s]] agrees with weights[m,s] )
//! C           = P2(commit_tag, domain, raw_chunks.., limit, nonce)
//! 1 <= limit <= TAU  (the camera's own line; spec/PER_CAMERA_THRESHOLD.md)
//! leaf        = P2(leaf_tag, template_chunks.., C)
//! wc          = P2(weights_tag, weight_chunks..)
//! public: [leaf, domain, wc]
//! ```
//!
//! Deployment decisions (spec/ENROL_PROOF_NOTE.md, approved 31 Aug):
//! taps expand from a PUBLISHED 32-byte seed by a fixed stream, so the
//! selection is circuit wiring rather than a lookup problem — the proof's
//! R1CS shape is per-enrolment and both sides derive it from the seed.
//! Weights stay secret and enter as witness, fixed forever by the
//! published commitment; no in-circuit PRF, because at enrolment the
//! enroller chooses the key freely either way and a PRF check would
//! constrain nobody. Monolithic on purpose: it proves the transform
//! EXACTLY as shipped (global taps); the folded variant is a locality
//! change whose statistics are unmeasured. One-time at enrolment, no
//! latency budget.

use crate::batch::E;
use crate::chain::{self, field_to_be, try_field_be, Chunk, NBITS, NCHUNK, PACK};
use crate::circuits::{alloc_public, enforce_boolean, pin};
use crate::poseidon2::{hash_gadget, Lc};
use crate::registry;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use halo2curves::bn256::Fr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use vega_prover::traits::{circuit::VegaCircuit, snark::R1CSSNARKTrait, Engine};
use vega_prover::vega_sc_zkp::VegaZkSNARK;

type Snark = VegaZkSNARK<E>;
type Pk = <Snark as R1CSSNARKTrait<E>>::ProverKey;
type Vk = <Snark as R1CSSNARKTrait<E>>::VerifierKey;

/// Taps per template bit, as the shipped transform has always had.
pub const S: usize = 15;
/// Template width: the bind tier is full-width.
pub const M: usize = NBITS;
/// 490,560 weight bits pack into exactly this many 224-bit chunks.
pub const WCHUNK: usize = (M * S) / PACK;

pub fn weights_tag() -> Fr {
    chain::tag("witness-enrol-proof-v1:weights")
}

/// Expand the published seed into M*S tap indices in [0, NBITS).
///
/// Fixed and public: SHA-256("witness-enrol-taps-v1" ‖ seed ‖ i_be32)
/// per block, each digest read as eight big-endian u32s reduced mod
/// NBITS. The Swift enrolment path must mirror this byte for byte.
pub fn taps_from_seed(seed: &[u8; 32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(M * S);
    let mut i: u32 = 0;
    while out.len() < M * S {
        let mut h = Sha256::new();
        h.update(b"witness-enrol-taps-v1");
        h.update(seed);
        h.update(i.to_be_bytes());
        let d = h.finalize();
        for w in d.as_chunks::<4>().0 {
            if out.len() == M * S {
                break;
            }
            let v = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
            out.push(v % NBITS as u32);
        }
        i += 1;
    }
    out
}

/// Pack bits into chunks EXACTLY as denoise.c does it.
///
/// `out[j >> 3] |= 1 << (j & 7)`: bit j lives in byte j/8 at position
/// j%8. That C function is the single source of truth for this format —
/// it packs on the phone, on the Mac and in ApertrueDesk, and the bytes
/// it produces are what the client sends and what the registry stores.
///
/// This used to write byte `27 - j/8` instead, giving the byte-reversed
/// chunk. Self-consistent with chunk_bit and denoise_chunk_lc, and wrong against
/// everything outside this file: the circuit proved a leaf over one byte
/// layout while the client sent fields in the other, so every enrolment
/// proof was refused as "for a different enrolment". It cost 5 September.
/// Nothing else calls this, so nothing else moves.
pub fn pack_bits(bits: &[bool]) -> Vec<Chunk> {
    assert!(bits.len().is_multiple_of(PACK));
    bits.as_chunks::<PACK>()
        .0
        .iter()
        .map(|window| {
            let mut c: Chunk = [0u8; 28];
            for (j, b) in window.iter().enumerate() {
                if *b {
                    c[j / 8] |= 1 << (j % 8);
                }
            }
            c
        })
        .collect()
}

/// The template exactly as the app computes it: majority of S signed
/// agreements per output bit.
pub fn template_bits(raw: &[bool], weights: &[bool], taps: &[u32]) -> Vec<bool> {
    assert_eq!(raw.len(), NBITS);
    assert_eq!(weights.len(), M * S);
    assert_eq!(taps.len(), M * S);
    (0..M)
        .map(|m| {
            let agree = (0..S)
                .filter(|s| raw[taps[m * S + s] as usize] == weights[m * S + s])
                .count();
            agree > S / 2
        })
        .collect()
}

#[derive(Clone)]
pub struct EnrolCircuit<En: Engine> {
    raw: Vec<bool>,
    weights: Vec<bool>,
    taps: Vec<u32>,
    domain: Fr,
    nonce: Fr,
    limit: u64,
    pub leaf: Fr,
    pub weight_commitment: Fr,
    _p: PhantomData<En>,
}

impl<En: Engine<Scalar = Fr>> EnrolCircuit<En> {
    pub fn new(
        raw: Vec<bool>,
        weights: Vec<bool>,
        seed: &[u8; 32],
        limit: u64,
        domain: Fr,
        nonce: Fr,
    ) -> Self {
        assert_eq!(raw.len(), NBITS);
        assert_eq!(weights.len(), M * S);
        let taps = taps_from_seed(seed);
        let template = template_bits(&raw, &weights, &taps);
        let template_chunks = pack_bits(&template);
        let raw_chunks = pack_bits(&raw);
        let commitment = chain::enrolment_commitment(&raw_chunks, limit, domain, nonce);
        let leaf = registry::leaf(&template_chunks, commitment);
        let mut wc_inputs = Vec::with_capacity(1 + WCHUNK);
        wc_inputs.push(weights_tag());
        wc_inputs.extend(pack_bits(&weights).iter().map(chain::chunk_field));
        let weight_commitment = crate::poseidon2::hash(&wc_inputs);
        Self {
            raw,
            weights,
            taps,
            domain,
            nonce,
            limit,
            leaf,
            weight_commitment,
            _p: PhantomData,
        }
    }
}

/// Public value positions.
pub mod enrol_io {
    pub const LEAF: usize = 0;
    pub const DOMAIN: usize = 1;
    pub const WEIGHT_COMMITMENT: usize = 2;
    pub const LEN: usize = 3;
}

/// A chunk in denoise byte order, read as a big-endian field element:
/// source bit j has weight 2^(8*(27 - j/8) + j%8).
fn denoise_chunk_lc(bits: &[&AllocatedNum<Fr>]) -> Lc {
    // Named for the order it uses, not for what it returns: circuits.rs
    // has a chunk_lc too, and that one weights bit j by 2^j because it
    // recomposes a chunk's INTEGER VALUE. This one recomposes bytes in
    // denoise.c's order. Two functions of the same name meaning different
    // things is how an indexing gets swapped for the other by accident,
    // which is the bug this file is fixing.
    //
    // The same layout pack_bits writes, recomposed in-circuit. Bit j sits
    // in byte j/8 at position j%8, and chunk_field reads the 28 bytes
    // BIG-ENDIAN, so byte b carries 2^(8*(27-b)) and bit j therefore
    // carries 2^(8*(27 - j/8) + j%8).
    //
    // The two have to move together: the form must recompose exactly what
    // chunk_field reads off the bytes, or the circuit constrains a value
    // nobody outside it computes.
    let mut lc = Lc::zero();
    for (j, b) in bits.iter().enumerate() {
        let mut w = Fr::ONE;
        for _ in 0..(8 * (27 - j / 8) + (j % 8)) {
            w = w.double();
        }
        lc.push_term(b.get_variable(), w, b.get_value());
    }
    lc
}

impl<En: Engine<Scalar = Fr>> VegaCircuit<En> for EnrolCircuit<En> {
    fn public_values(&self) -> Result<Vec<Fr>, SynthesisError> {
        Ok(vec![self.leaf, self.domain, self.weight_commitment])
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
        // The raw witness, once, with booleanity.
        let mut raw = Vec::with_capacity(NBITS);
        for (i, b) in self.raw.iter().enumerate() {
            let v = AllocatedNum::alloc(cs.namespace(|| format!("raw {i}")), || {
                Ok(if *b { Fr::ONE } else { Fr::ZERO })
            })?;
            enforce_boolean(cs, &format!("raw {i} bool"), v.get_variable());
            raw.push(v);
        }
        // The transform: per template bit, S weight bits, S products, a
        // majority. Taps are WIRING — constants chosen by the public
        // seed — which is the whole reason this is provable here.
        let mut weight_vars = Vec::with_capacity(M * S);
        let mut template_vars = Vec::with_capacity(M);
        for m in 0..M {
            let mut agree_native = 0u64;
            let mut agree = Lc::constant(Fr::from(S as u64));
            for s_i in 0..S {
                let idx = m * S + s_i;
                let w_bit = self.weights[idx];
                let b = &raw[self.taps[idx] as usize];
                let w = AllocatedNum::alloc(cs.namespace(|| format!("w {idx}")), || {
                    Ok(if w_bit { Fr::ONE } else { Fr::ZERO })
                })?;
                enforce_boolean(cs, &format!("w {idx} bool"), w.get_variable());
                let b_bit = self.raw[self.taps[idx] as usize];
                let bw = AllocatedNum::alloc(cs.namespace(|| format!("bw {idx}")), || {
                    Ok(if b_bit && w_bit { Fr::ONE } else { Fr::ZERO })
                })?;
                cs.enforce(
                    || format!("b*w {idx}"),
                    |lc| lc + b.get_variable(),
                    |lc| lc + w.get_variable(),
                    |lc| lc + bw.get_variable(),
                );
                // XNOR contribution: agreement = 1 - b - w + 2bw.
                let minus_one = Fr::ZERO - Fr::ONE;
                agree.push_term(b.get_variable(), minus_one, b.get_value());
                agree.push_term(w.get_variable(), minus_one, w.get_value());
                agree.push_term(bw.get_variable(), Fr::from(2), bw.get_value());
                if b_bit == w_bit {
                    agree_native += 1;
                }
                weight_vars.push(w);
            }
            // t <=> agree > 7, the shipped TAU gap pattern at 8-of-15:
            // diff = (7 - agree) + t * (2*agree - 15), diff in [0, 7].
            let t_bit = agree_native > (S / 2) as u64;
            let t = AllocatedNum::alloc(cs.namespace(|| format!("t {m}")), || {
                Ok(if t_bit { Fr::ONE } else { Fr::ZERO })
            })?;
            enforce_boolean(cs, &format!("t {m} bool"), t.get_variable());
            let diff_val = if t_bit {
                agree_native - 8
            } else {
                7 - agree_native
            };
            let diff = AllocatedNum::alloc(cs.namespace(|| format!("diff {m}")), || {
                Ok(Fr::from(diff_val))
            })?;
            let gap = agree
                .scale(Fr::from(2))
                .add(&Lc::constant(Fr::ZERO - Fr::from(15)));
            let seven_minus_agree = agree
                .scale(Fr::ZERO - Fr::ONE)
                .add(&Lc::constant(Fr::from(7)));
            cs.enforce(
                || format!("diff def {m}"),
                |lc| lc + t.get_variable(),
                |_| gap.lc::<CS>(),
                |lc| lc + diff.get_variable() - &seven_minus_agree.lc::<CS>(),
            );
            let mut recomposed = Lc::zero();
            let mut p = Fr::ONE;
            for j in 0..3 {
                let db = AllocatedNum::alloc(cs.namespace(|| format!("diff {m} bit {j}")), || {
                    Ok(Fr::from((diff_val >> j) & 1))
                })?;
                enforce_boolean(cs, &format!("diff {m} bit {j} bool"), db.get_variable());
                recomposed.push_term(db.get_variable(), p, db.get_value());
                p = p.double();
            }
            pin(cs, &format!("diff {m} bits"), &recomposed, &diff);
            template_vars.push(t);
        }

        // The three hashes, over chunk linear forms.
        let raw_refs: Vec<&AllocatedNum<Fr>> = raw.iter().collect();
        let raw_chunk_lcs: Vec<Lc> = raw_refs
            .as_chunks::<PACK>()
            .0
            .iter()
            .map(|w| denoise_chunk_lc(w))
            .collect();
        let template_refs: Vec<&AllocatedNum<Fr>> = template_vars.iter().collect();
        let template_chunk_lcs: Vec<Lc> = template_refs
            .as_chunks::<PACK>()
            .0
            .iter()
            .map(|w| denoise_chunk_lc(w))
            .collect();
        let weight_refs: Vec<&AllocatedNum<Fr>> = weight_vars.iter().collect();
        let weight_chunk_lcs: Vec<Lc> = weight_refs
            .as_chunks::<PACK>()
            .0
            .iter()
            .map(|w| denoise_chunk_lc(w))
            .collect();

        let domain_w = AllocatedNum::alloc(cs.namespace(|| "domain"), || Ok(self.domain))?;
        let nonce_w = AllocatedNum::alloc(cs.namespace(|| "nonce"), || Ok(self.nonce))?;
        let limit_w = AllocatedNum::alloc(cs.namespace(|| "limit"), || Ok(Fr::from(self.limit)))?;
        // MIN_LIMIT <= limit <= TAU: an enrolment can tighten on TAU, never
        // loosen it.
        let l = Lc::var(limit_w.get_variable(), limit_w.get_value());
        crate::circuits::range_check(
            cs,
            "limit above min",
            &l.add_const(-Fr::from(chain::MIN_LIMIT)),
            self.limit.wrapping_sub(chain::MIN_LIMIT),
            14,
        )?;
        crate::circuits::range_check(
            cs,
            "limit under tau",
            &l.scale(-Fr::ONE).add_const(Fr::from(chain::TAU)),
            chain::TAU.wrapping_sub(self.limit),
            14,
        )?;

        let mut c_inputs = Vec::with_capacity(4 + NCHUNK);
        c_inputs.push(Lc::constant(chain::commit_tag()));
        c_inputs.push(Lc::var(domain_w.get_variable(), domain_w.get_value()));
        c_inputs.extend(raw_chunk_lcs);
        c_inputs.push(l);
        c_inputs.push(Lc::var(nonce_w.get_variable(), nonce_w.get_value()));
        let c = hash_gadget(&mut cs.namespace(|| "commitment"), &c_inputs)?;
        let c = c.materialise(&mut cs.namespace(|| "commitment"), "pin")?;

        let mut leaf_inputs = Vec::with_capacity(2 + NCHUNK);
        leaf_inputs.push(Lc::constant(registry::leaf_tag()));
        leaf_inputs.extend(template_chunk_lcs);
        leaf_inputs.push(c);
        let leaf_form = hash_gadget(&mut cs.namespace(|| "leaf"), &leaf_inputs)?;

        let mut wc_inputs = Vec::with_capacity(1 + WCHUNK);
        wc_inputs.push(Lc::constant(weights_tag()));
        wc_inputs.extend(weight_chunk_lcs);
        let wc_form = hash_gadget(&mut cs.namespace(|| "weights"), &wc_inputs)?;

        // Inputized LAST, in IO order, exactly as membership.rs warns.
        let leaf_pub = alloc_public(cs, "leaf", self.leaf)?;
        pin(cs, "leaf", &leaf_form, &leaf_pub);
        let domain_pub = alloc_public(cs, "domain pub", self.domain)?;
        pin(
            cs,
            "domain",
            &Lc::var(domain_w.get_variable(), domain_w.get_value()),
            &domain_pub,
        );
        let wc_pub = alloc_public(cs, "weight commitment", self.weight_commitment)?;
        pin(cs, "weight commitment", &wc_form, &wc_pub);
        Ok(())
    }
}

/// The proof as it travels: 32-byte fields plus the seed the verifier
/// rebuilds the shape from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrolReceipt {
    pub version: u32,
    pub seed: [u8; 32],
    pub leaf: [u8; 32],
    pub domain: [u8; 32],
    pub weight_commitment: [u8; 32],
    pub proof: Vec<u8>,
}

/// 2: the commitment carries the camera's limit (spec/PER_CAMERA_THRESHOLD.md).
pub const ENROL_PROOF_VERSION: u32 = 2;
pub const MAX_ENROL_BYTES: u64 = 8 << 20;

impl EnrolReceipt {
    pub fn decode(bytes: &[u8]) -> Result<Self, EnrolError> {
        use bincode::Options;
        if bytes.len() as u64 > MAX_ENROL_BYTES {
            return Err(EnrolError::Malformed);
        }
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_ENROL_BYTES)
            .deserialize(bytes)
            .map_err(|_| EnrolError::Malformed)
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("an enrol receipt serialises")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrolError {
    Version(u32),
    Malformed,
    Proof(String),
    Setup(String),
}

impl std::fmt::Display for EnrolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrolError::Version(v) => write!(f, "unknown enrol proof version {v}"),
            EnrolError::Malformed => write!(f, "the enrol proof did not parse"),
            EnrolError::Proof(s) => write!(f, "the enrol proof does not verify: {s}"),
            EnrolError::Setup(s) => write!(f, "key setup failed: {s}"),
        }
    }
}

impl std::error::Error for EnrolError {}

/// What a verified proof establishes, from its own public values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolSummary {
    pub leaf: [u8; 32],
    pub domain: [u8; 32],
    pub weight_commitment: [u8; 32],
}

/// The key pair for an enrolment's seed. Public for the prover, which
/// proves under the prover key of the same setup; verification reads only
/// the verifier key.
#[doc(hidden)]
pub fn keys_for(seed: &[u8; 32]) -> Result<(Pk, Vk), EnrolError> {
    // The shape depends on the seed (taps are wiring), so keys are made
    // per enrolment on both sides — a one-time cost at a moment nobody
    // is waiting on.
    let shape = EnrolCircuit::<E>::new(
        vec![false; NBITS],
        vec![false; M * S],
        seed,
        chain::TAU,
        Fr::ZERO,
        Fr::ZERO,
    );
    Snark::setup(shape).map_err(|e| EnrolError::Setup(format!("{e:?}")))
}

/// Verify one, rebuilding the shape from the receipt's own seed. The
/// summary comes from the proof's public values; the receipt's stated
/// fields are checked against them, never trusted.
pub fn verify(receipt: &EnrolReceipt) -> Result<EnrolSummary, EnrolError> {
    if receipt.version != ENROL_PROOF_VERSION {
        return Err(EnrolError::Version(receipt.version));
    }
    if receipt.proof.len() as u64 > MAX_ENROL_BYTES {
        return Err(EnrolError::Malformed);
    }
    for be in [&receipt.leaf, &receipt.domain, &receipt.weight_commitment] {
        if try_field_be(be).is_none() {
            return Err(EnrolError::Malformed);
        }
    }
    let proof: Snark = {
        use bincode::Options;
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_ENROL_BYTES)
            .deserialize(&receipt.proof)
            .map_err(|_| EnrolError::Malformed)?
    };
    let (_, vk) = keys_for(&receipt.seed)?;
    let io = proof
        .verify(&vk)
        .map_err(|e| EnrolError::Proof(format!("{e:?}")))?;
    if io.len() != enrol_io::LEN {
        return Err(EnrolError::Proof("unexpected public IO shape".into()));
    }
    let leaf = field_to_be(&io[enrol_io::LEAF]);
    let domain = field_to_be(&io[enrol_io::DOMAIN]);
    let wc = field_to_be(&io[enrol_io::WEIGHT_COMMITMENT]);
    if leaf != receipt.leaf || domain != receipt.domain || wc != receipt.weight_commitment {
        return Err(EnrolError::Proof(
            "the receipt does not state what the proof establishes".into(),
        ));
    }
    Ok(EnrolSummary {
        leaf,
        domain,
        weight_commitment: wc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taps_are_deterministic_and_bounded() {
        let a = taps_from_seed(&[7u8; 32]);
        let b = taps_from_seed(&[7u8; 32]);
        assert_eq!(a, b);
        assert_eq!(a.len(), M * S);
        assert!(a.iter().all(|t| (*t as usize) < NBITS));
        assert_ne!(a, taps_from_seed(&[8u8; 32]));
    }

    /// The packing against denoise.c, which is the format's only source
    /// of truth. This vector was produced by compiling that C and running
    /// zkprnu_pack224 over the pattern below — not by restating the rule
    /// here, which is how the two came to disagree in the first place.
    ///
    /// The gap this closes: every other test either hands both languages
    /// the same BYTES (the pinned V3_LEAF registry vector) or compares
    /// BITS before packing (the seed-tap parity tests). Nothing started
    /// from the same bits and compared the bytes, so a byte-reversed
    /// chunk passed everything and refused every real enrolment.
    #[test]
    fn packing_matches_the_c_that_defines_it() {
        // bits[i] = (i * 7 + 1) % 3 == 0, 224 of them.
        const FROM_DENOISE_C: &str = "24499224499224499224499224499224499224499224499224499224";
        let bits: Vec<bool> = (0..PACK).map(|i| (i * 7 + 1) % 3 == 0).collect();
        let packed = pack_bits(&bits);
        assert_eq!(packed.len(), 1);
        assert_eq!(hex::encode(packed[0]), FROM_DENOISE_C);
    }

    /// A chunk's field element is the big-endian reading of those bytes,
    /// which is what the service computes from the hex the client sends.
    /// pack_bits and chunk_field have to agree on that or the leaf the
    /// circuit proves is one nobody else computes.
    #[test]
    fn a_packed_chunk_reads_back_as_the_service_reads_it() {
        let bits: Vec<bool> = (0..PACK).map(|i| (i * 7 + 1) % 3 == 0).collect();
        let chunk = pack_bits(&bits)[0];
        let mut be = [0u8; 32];
        be[4..].copy_from_slice(&chunk);
        assert_eq!(chain::chunk_field(&chunk), chain::field_be(&be));
    }

    /// Packing round-trips under ITS OWN indexing, which is the C one:
    /// bit j in byte j/8 at position j%8.
    ///
    /// Not chunk_bits. That reads bit j of the chunk's INTEGER VALUE,
    /// which is the indexing batch and membership use because they are
    /// handed chunks already packed and only ever decompose and recompose
    /// them consistently. Enrol packs raw sensor bits itself, so it has to
    /// use the layout denoise.c defines. Two legitimate indexings of the
    /// same 28 bytes; this test used to assert they were one, which is the
    /// assumption the byte-reversed packing hid behind.
    #[test]
    fn packing_round_trips_under_the_c_indexing() {
        let bits: Vec<bool> = (0..NBITS).map(|i| i % 3 == 0).collect();
        let chunks = pack_bits(&bits);
        let back: Vec<bool> = chunks
            .iter()
            .flat_map(|c| (0..PACK).map(move |j| (c[j / 8] >> (j % 8)) & 1 == 1))
            .collect();
        assert_eq!(bits, back);
    }

    /// The two indexings really are different, so nothing may quietly
    /// swap one for the other again.
    #[test]
    fn the_two_chunk_indexings_are_not_the_same() {
        let bits: Vec<bool> = (0..PACK).map(|i| (i * 7 + 1) % 3 == 0).collect();
        let chunk = pack_bits(&bits)[0];
        let as_value: Vec<bool> = chain::chunk_bits(&chunk).collect();
        assert_ne!(bits, as_value);
    }

    #[test]
    fn template_matches_the_shipped_transform_shape() {
        let raw: Vec<bool> = (0..NBITS).map(|i| i % 2 == 0).collect();
        let weights: Vec<bool> = (0..M * S).map(|i| i % 5 != 0).collect();
        let taps = taps_from_seed(&[1u8; 32]);
        let t = template_bits(&raw, &weights, &taps);
        assert_eq!(t.len(), M);
        // Majority of 15 is never a tie; every bit is decided.
        let flipped = template_bits(&raw.iter().map(|b| !b).collect::<Vec<_>>(), &weights, &taps);
        assert_ne!(t, flipped);
    }
}
