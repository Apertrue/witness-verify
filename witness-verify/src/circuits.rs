//! The fold step as a Vega multi-circuit batch: one step circuit per
//! window, one core circuit per batch, the enrolment bits SHARED across
//! them (committed once, rerandomised per batch).
//!
//! Step, per window (the product_step statement, same constants):
//!   mismatch = sum_c popcount(fresh_c xor enrolled_c)
//!   passed   = (mismatch < limit) AND NOT degenerate, where limit is this
//!              camera's enrolled line, shared with the core, which checks
//!              1 <= limit <= TAU (spec/PER_CAMERA_THRESHOLD.md)
//!   header   = window_index * 2^80 + frames * 2^16 + passed * 256 + degenerate
//!   digest   = P2([TAG_LINK, chain_id, header, picture_root, fresh_0..145])
//!   head_out = P2([TAG_FOLD, head_in, digest])
//! Public: [chain_id, window_index, frames, degenerate, passed, head_in,
//!          picture_root, head_out]. The picture root is the window's
//!          running fold of its face pictures' hashes, zero when none.
//!
//! Core, per batch: every enrolled bit is boolean, 1 <= limit <= TAU, the
//! enrolment commitment C = P2(commit_tag, registry_domain, enrolled,
//! limit, nonce) and
//! the chain's genesis head
//! P2([TAG_INIT, chain_id, enrolled]) are both computed from the shared
//! bits. The commitment is not published; what is published is that
//! commitment blinded by a per-call factor, so a camera's receipts carry
//! a fresh number every call and nothing links two calls together.
//! Public: [blinded, chain_id, genesis].
//!
//! The verifier checks on the public values what the circuits leave to it:
//! every window names the core's chain id, head_out chains into the next
//! head_in, the header fields are small integers, degenerate is a bit.

use crate::chain::{
    self, chain_id_field, enrolment_commitment, Chunk, Derived, Window, MIN_LIMIT, NBITS, NCHUNK,
    PACK, TAU,
};
use crate::poseidon2::{hash_gadget, Lc, WitnessOnly};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError, Variable};
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use std::marker::PhantomData;
use vega_prover::traits::{circuit::VegaCircuit, Engine};

fn alloc_bits<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    label: &str,
    chunks: &[Chunk],
) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
    let mut out = Vec::with_capacity(NBITS);
    for (c, chunk) in chunks.iter().enumerate() {
        for (j, bit) in chain::chunk_bits(chunk).enumerate() {
            out.push(AllocatedNum::alloc(
                cs.namespace(|| format!("{label} {c} {j}")),
                || Ok(if bit { Fr::ONE } else { Fr::ZERO }),
            )?);
        }
    }
    Ok(out)
}

pub(crate) fn enforce_boolean<CS: ConstraintSystem<Fr>>(cs: &mut CS, label: &str, v: Variable) {
    cs.enforce(
        || label.to_string(),
        |lc| lc + v,
        |lc| lc + CS::one() - v,
        |lc| lc,
    );
}

/// The chunk as a linear form over its 224 bits: sum_j b_j 2^j.
fn chunk_lc(bits: &[AllocatedNum<Fr>]) -> Lc {
    let mut lc = Lc::zero();
    let mut pow = Fr::ONE;
    for b in bits {
        lc.push_term(b.get_variable(), pow, b.get_value());
        pow = pow.double();
    }
    lc
}

pub(crate) fn alloc_public<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    label: &str,
    value: Fr,
) -> Result<AllocatedNum<Fr>, SynthesisError> {
    let n = AllocatedNum::alloc(cs.namespace(|| label.to_string()), || Ok(value))?;
    n.inputize(cs.namespace(|| format!("inputize {label}")))?;
    Ok(n)
}

pub(crate) fn pin<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    label: &str,
    form: &Lc,
    to: &AllocatedNum<Fr>,
) {
    cs.enforce(
        || label.to_string(),
        |_| form.lc::<CS>(),
        |lc| lc + CS::one(),
        |lc| lc + to.get_variable(),
    );
}

/// The shared witness: the enrolled bits, then the camera's limit. Every
/// circuit of a batch allocates it in this order, so all of them read the
/// one committed value.
fn alloc_shared<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    enrolled: &[Chunk],
    limit: u64,
) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
    let mut out = alloc_bits(cs, "enrolled", enrolled)?;
    out.push(AllocatedNum::alloc(cs.namespace(|| "limit"), || {
        Ok(Fr::from(limit))
    })?);
    Ok(out)
}

/// `form` equals an `n`-bit value `value`: the bits are allocated, each
/// boolean, and their sum pinned to the form.
pub(crate) fn range_check<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    label: &str,
    form: &Lc,
    value: u64,
    n: usize,
) -> Result<(), SynthesisError> {
    let mut recomposed = Lc::zero();
    let mut pow = Fr::ONE;
    for j in 0..n {
        let bit = AllocatedNum::alloc(cs.namespace(|| format!("{label} bit {j}")), || {
            Ok(Fr::from((value >> j) & 1))
        })?;
        enforce_boolean(cs, &format!("{label} bit bool {j}"), bit.get_variable());
        recomposed.push_term(bit.get_variable(), pow, bit.get_value());
        pow = pow.double();
    }
    cs.enforce(
        || format!("{label} range"),
        |_| recomposed.lc::<CS>(),
        |lc| lc + CS::one(),
        |_| form.lc::<CS>(),
    );
    Ok(())
}

/// Public value positions of the step circuit.
pub mod step_io {
    pub const CHAIN_ID: usize = 0;
    pub const WINDOW_INDEX: usize = 1;
    pub const FRAMES: usize = 2;
    pub const DEGENERATE: usize = 3;
    pub const PASSED: usize = 4;
    pub const HEAD_IN: usize = 5;
    pub const PICTURE_ROOT: usize = 6;
    pub const HEAD_OUT: usize = 7;
    pub const LEN: usize = 8;
}

/// Public value positions of the core circuit.
pub mod core_io {
    pub const BLINDED: usize = 0;
    pub const CHAIN_ID: usize = 1;
    pub const GENESIS: usize = 2;
    pub const LEN: usize = 3;
}

// ------------------------------------------------------------------ step

#[derive(Clone, Debug)]
pub struct StepCircuit<E: Engine> {
    pub window: Window,
    pub enrolled: Vec<Chunk>,
    pub limit: u64,
    pub head_in: Fr,
    pub derived: Derived,
    _p: PhantomData<E>,
}

impl<E: Engine<Scalar = Fr>> StepCircuit<E> {
    pub fn new(window: Window, enrolled: Vec<Chunk>, limit: u64, head_in: Fr) -> Self {
        let derived = chain::derive(&window, &enrolled, limit, head_in);
        Self {
            window,
            enrolled,
            limit,
            head_in,
            derived,
            _p: PhantomData,
        }
    }
}

impl<E: Engine<Scalar = Fr>> VegaCircuit<E> for StepCircuit<E> {
    fn public_values(&self) -> Result<Vec<Fr>, SynthesisError> {
        Ok(vec![
            chain_id_field(&self.window.chain_id),
            Fr::from(self.window.window_index),
            Fr::from(self.window.frames),
            Fr::from(self.window.degenerate as u64),
            Fr::from(self.derived.passed as u64),
            self.head_in,
            chain::field_be(&self.window.picture_root),
            self.derived.head_out,
        ])
    }

    /// The enrolment, bit by bit, and the camera's limit, shared with every
    /// other window and the core circuit. Booleanity and the limit's range
    /// are enforced once, in the core.
    fn shared<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        alloc_shared(cs, &self.enrolled, self.limit)
    }

    /// This window's chunks, bit by bit, boolean.
    fn precommitted<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        let bits = alloc_bits(cs, "fresh", &self.window.fresh)?;
        for (i, b) in bits.iter().enumerate() {
            enforce_boolean(cs, &format!("fresh bool {i}"), b.get_variable());
        }
        Ok(bits)
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Fr>],
        precommitted: &[AllocatedNum<Fr>],
        _challenges: Option<&[Fr]>,
    ) -> Result<(), SynthesisError> {
        // Witness generation needs only values: see WitnessOnly.
        let _witness_only = WitnessOnly::enter(cs);
        assert_eq!(shared.len(), NBITS + 1);
        assert_eq!(precommitted.len(), NBITS);
        let d = &self.derived;
        let limit = &shared[NBITS];
        let shared = &shared[..NBITS];

        // mismatch = sum (a + b - 2ab), one multiplication per bit pair,
        // summed per chunk into a pinned variable so no row is huge.
        let mut mismatch = Lc::zero();
        for c in 0..NCHUNK {
            let mut chunk_sum = Lc::zero();
            for j in 0..PACK {
                let i = c * PACK + j;
                let a = &precommitted[i];
                let b = &shared[i];
                let ab = AllocatedNum::alloc(cs.namespace(|| format!("ab {i}")), || {
                    Ok(a.get_value().unwrap() * b.get_value().unwrap())
                })?;
                cs.enforce(
                    || format!("a*b {i}"),
                    |lc| lc + a.get_variable(),
                    |lc| lc + b.get_variable(),
                    |lc| lc + ab.get_variable(),
                );
                chunk_sum.push_term(a.get_variable(), Fr::ONE, a.get_value());
                chunk_sum.push_term(b.get_variable(), Fr::ONE, b.get_value());
                chunk_sum.push_term(ab.get_variable(), -Fr::from(2), ab.get_value());
            }
            let pinned = chunk_sum.materialise(cs, &format!("mismatch chunk {c}"))?;
            mismatch = mismatch.add(&pinned);
        }
        let mismatch = mismatch.materialise(cs, "mismatch")?;

        // Public inputs, in public_values order.
        let chain_id = alloc_public(cs, "chain_id", chain_id_field(&self.window.chain_id))?;
        let window_index = alloc_public(cs, "window_index", Fr::from(self.window.window_index))?;
        let frames = alloc_public(cs, "frames", Fr::from(self.window.frames))?;
        let degenerate = alloc_public(cs, "degenerate", Fr::from(self.window.degenerate as u64))?;
        let passed = alloc_public(cs, "passed", Fr::from(d.passed as u64))?;
        let head_in = alloc_public(cs, "head_in", self.head_in)?;
        let picture_root = alloc_public(
            cs,
            "picture_root",
            chain::field_be(&self.window.picture_root),
        )?;
        enforce_boolean(cs, "passed bool", passed.get_variable());

        // below <=> mismatch < limit, limit the shared committed line:
        //   diff = (m - L) + below * ((L - 1 - m) - (m - L)), diff in [0, 2^15)
        // mismatch <= NBITS < 2^15 and limit <= TAU (the core's range check),
        // so neither side can wrap.
        let below_val = d.mismatch < self.limit;
        let below = AllocatedNum::alloc(cs.namespace(|| "below"), || {
            Ok(if below_val { Fr::ONE } else { Fr::ZERO })
        })?;
        enforce_boolean(cs, "below bool", below.get_variable());
        let l = Lc::var(limit.get_variable(), limit.get_value());
        let m_minus_l = mismatch.add(&l.scale(-Fr::ONE));
        let l1_minus_m = l.add(&mismatch.scale(-Fr::ONE)).add_const(-Fr::ONE);
        let gap = l1_minus_m.add(&m_minus_l.scale(-Fr::ONE));
        let diff_val = if below_val {
            self.limit - 1 - d.mismatch
        } else {
            d.mismatch - self.limit
        };
        let diff = AllocatedNum::alloc(cs.namespace(|| "diff"), || Ok(Fr::from(diff_val)))?;
        cs.enforce(
            || "diff = (m-L) + below*gap",
            |lc| lc + below.get_variable(),
            |_| gap.lc::<CS>(),
            |lc| lc + diff.get_variable() - &m_minus_l.lc::<CS>(),
        );
        range_check(
            cs,
            "diff",
            &Lc::var(diff.get_variable(), diff.get_value()),
            diff_val,
            15,
        )?;

        // passed = below AND NOT degenerate = below - below * degenerate:
        // one verdict, the camera's own.
        let both = AllocatedNum::alloc(cs.namespace(|| "below and degenerate"), || {
            Ok(Fr::from((below_val && self.window.degenerate) as u64))
        })?;
        cs.enforce(
            || "below * degenerate",
            |lc| lc + below.get_variable(),
            |lc| lc + degenerate.get_variable(),
            |lc| lc + both.get_variable(),
        );
        cs.enforce(
            || "passed = below - both",
            |lc| lc + below.get_variable() - both.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + passed.get_variable(),
        );

        // header = window_index * 2^80 + frames * 2^16 + passed * 256 + degenerate
        let header = Lc::var(window_index.get_variable(), window_index.get_value())
            .scale(Fr::from_u128(1u128 << 80))
            .add(&Lc::var(frames.get_variable(), frames.get_value()).scale(Fr::from(1u64 << 16)))
            .add(&Lc::var(passed.get_variable(), passed.get_value()).scale(Fr::from(256)))
            .add(&Lc::var(degenerate.get_variable(), degenerate.get_value()));

        // digest = P2([TAG_LINK, chain_id, header, picture_root, fresh_0..145])
        let mut link = Vec::with_capacity(4 + NCHUNK);
        link.push(Lc::constant(chain::link_tag()));
        link.push(Lc::var(chain_id.get_variable(), chain_id.get_value()));
        link.push(header);
        link.push(Lc::var(
            picture_root.get_variable(),
            picture_root.get_value(),
        ));
        for c in 0..NCHUNK {
            link.push(chunk_lc(&precommitted[c * PACK..(c + 1) * PACK]));
        }
        let digest = hash_gadget(&mut cs.namespace(|| "link"), &link)?;

        // head_out = P2([TAG_FOLD, head_in, digest]), made public.
        let head = hash_gadget(
            &mut cs.namespace(|| "fold"),
            &[
                Lc::constant(chain::fold_tag()),
                Lc::var(head_in.get_variable(), head_in.get_value()),
                digest,
            ],
        )?;
        let head_out = alloc_public(cs, "head_out", d.head_out)?;
        pin(cs, "head_out", &head, &head_out);
        Ok(())
    }
}

// ------------------------------------------------------------------ core

#[derive(Clone, Debug)]
pub struct CoreCircuit<E: Engine> {
    pub enrolled: Vec<Chunk>,
    /// This camera's enrolled line, inside `C` and never public.
    pub limit: u64,
    pub chain_id: [u8; 16],
    /// This enrolment's registry domain and nonce: private, and what
    /// make `C` differ between registries and die on rotation. Both are
    /// fixed at enrolment and stored beside the bits.
    pub registry_domain: Fr,
    pub nonce: Fr,
    /// This call's blinding factor. Constant across the call, so the
    /// service can tell a call's batches compare against one enrolment,
    /// and fresh per call, so no one else can tell which enrolment.
    pub blind: Fr,
    pub commitment: Fr,
    pub blinded: Fr,
    pub genesis: Fr,
    _p: PhantomData<E>,
}

impl<E: Engine<Scalar = Fr>> CoreCircuit<E> {
    pub fn new(
        enrolled: Vec<Chunk>,
        limit: u64,
        chain_id: [u8; 16],
        registry_domain: Fr,
        nonce: Fr,
        blind: Fr,
    ) -> Self {
        assert_eq!(enrolled.len(), NCHUNK);
        let commitment = enrolment_commitment(&enrolled, limit, registry_domain, nonce);
        let genesis = chain::genesis(chain_id_field(&chain_id), &enrolled);
        Self {
            enrolled,
            limit,
            chain_id,
            registry_domain,
            nonce,
            blind,
            commitment,
            blinded: crate::membership::blinded(commitment, blind),
            genesis,
            _p: PhantomData,
        }
    }
}

impl<E: Engine<Scalar = Fr>> VegaCircuit<E> for CoreCircuit<E> {
    fn public_values(&self) -> Result<Vec<Fr>, SynthesisError> {
        Ok(vec![
            self.blinded,
            chain_id_field(&self.chain_id),
            self.genesis,
        ])
    }

    fn shared<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        alloc_shared(cs, &self.enrolled, self.limit)
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
        shared: &[AllocatedNum<Fr>],
        _precommitted: &[AllocatedNum<Fr>],
        _challenges: Option<&[Fr]>,
    ) -> Result<(), SynthesisError> {
        // Witness generation needs only values: see WitnessOnly.
        let _witness_only = WitnessOnly::enter(cs);
        assert_eq!(shared.len(), NBITS + 1);
        let limit = &shared[NBITS];
        let shared = &shared[..NBITS];
        for (i, b) in shared.iter().enumerate() {
            enforce_boolean(cs, &format!("enrolled bool {i}"), b.get_variable());
        }
        // MIN_LIMIT <= limit <= TAU, as two 14-bit ranges (TAU < 2^14): the
        // line a camera commits can tighten on TAU, never loosen it.
        let l = Lc::var(limit.get_variable(), limit.get_value());
        range_check(
            cs,
            "limit above min",
            &l.add_const(-Fr::from(MIN_LIMIT)),
            self.limit.wrapping_sub(MIN_LIMIT),
            14,
        )?;
        range_check(
            cs,
            "limit under tau",
            &l.scale(-Fr::ONE).add_const(Fr::from(TAU)),
            TAU.wrapping_sub(self.limit),
            14,
        )?;
        let fields: Vec<Lc> = (0..NCHUNK)
            .map(|c| chunk_lc(&shared[c * PACK..(c + 1) * PACK]))
            .collect();

        // Every private input is allocated before any public value:
        // interleaving inputize with witness allocation makes the
        // prover and verifier disagree on the round-0 challenges.
        let domain = AllocatedNum::alloc(cs.namespace(|| "registry domain"), || {
            Ok(self.registry_domain)
        })?;
        let nonce = AllocatedNum::alloc(cs.namespace(|| "nonce"), || Ok(self.nonce))?;
        let blind = AllocatedNum::alloc(cs.namespace(|| "blind"), || Ok(self.blind))?;

        // C = P2(commit_tag, registry_domain, chunks.., limit, nonce): the same
        // value the registry leaf embeds, computed here from the bits
        // every window of this batch was matched against. That identity
        // is the whole binding: nothing else has to be trusted.
        let mut commit_inputs = Vec::with_capacity(4 + NCHUNK);
        commit_inputs.push(Lc::constant(chain::commit_tag()));
        commit_inputs.push(Lc::var(domain.get_variable(), domain.get_value()));
        commit_inputs.extend(fields.iter().cloned());
        commit_inputs.push(Lc::var(limit.get_variable(), limit.get_value()));
        commit_inputs.push(Lc::var(nonce.get_variable(), nonce.get_value()));
        let commitment = hash_gadget(&mut cs.namespace(|| "enrolment"), &commit_inputs)?;
        let commitment = commitment.materialise(&mut cs.namespace(|| "enrolment"), "pin")?;
        let blinded = hash_gadget(
            &mut cs.namespace(|| "blinded"),
            &[
                Lc::constant(crate::membership::blind_tag()),
                commitment,
                Lc::var(blind.get_variable(), blind.get_value()),
            ],
        )?;
        let blinded_pub = alloc_public(cs, "blinded", self.blinded)?;
        pin(cs, "blinded", &blinded, &blinded_pub);

        let chain_id = alloc_public(cs, "chain_id", chain_id_field(&self.chain_id))?;
        let mut init = Vec::with_capacity(2 + NCHUNK);
        init.push(Lc::constant(chain::init_tag()));
        init.push(Lc::var(chain_id.get_variable(), chain_id.get_value()));
        init.extend(fields);
        let genesis = hash_gadget(&mut cs.namespace(|| "genesis"), &init)?;
        let genesis_pub = alloc_public(cs, "genesis", self.genesis)?;
        pin(cs, "genesis", &genesis, &genesis_pub);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! The constraints themselves, not the native helpers: a verdict that
    //! disagrees with the committed limit, or a limit outside 1..=TAU,
    //! must leave the circuit unsatisfied (spec/PER_CAMERA_THRESHOLD.md).
    use super::*;
    use crate::batch::E;
    use bellpepper_core::{Index, LinearCombination};

    /// A constraint system that keeps every value and checks every
    /// constraint as it is added. Names are ignored: these circuits reuse
    /// labels, which the proving system never reads.
    struct SatCs {
        inputs: Vec<Fr>,
        aux: Vec<Fr>,
        broken: Vec<String>,
    }

    impl SatCs {
        fn new() -> Self {
            Self {
                inputs: vec![Fr::ONE],
                aux: vec![],
                broken: vec![],
            }
        }
        fn eval(&self, lc: &LinearCombination<Fr>) -> Fr {
            let mut acc = Fr::ZERO;
            for (v, coeff) in lc.iter() {
                let x = match v.get_unchecked() {
                    Index::Input(i) => self.inputs[i],
                    Index::Aux(i) => self.aux[i],
                };
                acc += x * coeff;
            }
            acc
        }
        fn is_satisfied(&self) -> bool {
            self.broken.is_empty()
        }
    }

    impl ConstraintSystem<Fr> for SatCs {
        type Root = Self;
        fn alloc<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
        where
            F: FnOnce() -> Result<Fr, SynthesisError>,
            A: FnOnce() -> AR,
            AR: Into<String>,
        {
            self.aux.push(f()?);
            Ok(Variable::new_unchecked(Index::Aux(self.aux.len() - 1)))
        }
        fn alloc_input<F, A, AR>(&mut self, _: A, f: F) -> Result<Variable, SynthesisError>
        where
            F: FnOnce() -> Result<Fr, SynthesisError>,
            A: FnOnce() -> AR,
            AR: Into<String>,
        {
            self.inputs.push(f()?);
            Ok(Variable::new_unchecked(Index::Input(self.inputs.len() - 1)))
        }
        fn enforce<A, AR, LA, LB, LC>(&mut self, name: A, a: LA, b: LB, c: LC)
        where
            A: FnOnce() -> AR,
            AR: Into<String>,
            LA: FnOnce(LinearCombination<Fr>) -> LinearCombination<Fr>,
            LB: FnOnce(LinearCombination<Fr>) -> LinearCombination<Fr>,
            LC: FnOnce(LinearCombination<Fr>) -> LinearCombination<Fr>,
        {
            let (a, b, c) = (
                a(LinearCombination::zero()),
                b(LinearCombination::zero()),
                c(LinearCombination::zero()),
            );
            if self.eval(&a) * self.eval(&b) != self.eval(&c) {
                self.broken.push(name().into());
            }
        }
        fn push_namespace<NR, N>(&mut self, _: N)
        where
            NR: Into<String>,
            N: FnOnce() -> NR,
        {
        }
        fn pop_namespace(&mut self) {}
        fn get_root(&mut self) -> &mut Self::Root {
            self
        }
    }

    fn enrolled() -> Vec<Chunk> {
        (0..NCHUNK)
            .map(|c| std::array::from_fn(|j| ((c * 11 + j * 5 + 3) % 256) as u8))
            .collect()
    }

    /// The enrolment with exactly `k` bits flipped, the first `k` in order.
    fn with_mismatch(enrolled: &[Chunk], k: usize) -> Vec<Chunk> {
        let mut out = enrolled.to_vec();
        for i in 0..k {
            let (c, j) = (i / PACK, i % PACK);
            out[c][27 - j / 8] ^= 1 << (j % 8);
        }
        out
    }

    fn window(fresh: Vec<Chunk>, degenerate: bool) -> Window {
        Window {
            chain_id: [5u8; 16],
            window_index: 3,
            frames: 24,
            degenerate,
            picture_root: [0u8; 32],
            fresh,
        }
    }

    fn step_satisfied(s: &StepCircuit<E>) -> bool {
        let mut cs = SatCs::new();
        let shared = s.shared(&mut cs).unwrap();
        let pre = s.precommitted(&mut cs, &shared).unwrap();
        s.synthesize(&mut cs, &shared, &pre, None).unwrap();
        cs.is_satisfied()
    }

    fn core_satisfied(c: &CoreCircuit<E>) -> bool {
        let mut cs = SatCs::new();
        let shared = c.shared(&mut cs).unwrap();
        c.synthesize(&mut cs, &shared, &[], None).unwrap();
        cs.is_satisfied()
    }

    const LIMIT: u64 = 13_200;

    #[test]
    fn a_window_passes_one_under_the_limit_and_fails_at_it() {
        let e = enrolled();
        for (k, expect) in [(LIMIT as usize - 1, true), (LIMIT as usize, false)] {
            let s = StepCircuit::<E>::new(
                window(with_mismatch(&e, k), false),
                e.clone(),
                LIMIT,
                Fr::ONE,
            );
            assert_eq!(s.derived.mismatch, k as u64);
            assert_eq!(s.derived.passed, expect, "mismatch {k}");
            assert!(step_satisfied(&s), "honest verdict at mismatch {k}");
        }
    }

    #[test]
    fn a_verdict_against_the_limit_cannot_be_flipped() {
        let e = enrolled();
        for k in [LIMIT as usize - 1, LIMIT as usize, TAU as usize - 1] {
            let mut s = StepCircuit::<E>::new(
                window(with_mismatch(&e, k), false),
                e.clone(),
                LIMIT,
                Fr::ONE,
            );
            s.derived.passed = !s.derived.passed;
            assert!(!step_satisfied(&s), "flipped verdict at mismatch {k}");
        }
    }

    #[test]
    fn a_window_between_the_limit_and_tau_fails() {
        // The case that left batches unproven: under TAU, over the limit.
        let e = enrolled();
        let s = StepCircuit::<E>::new(
            window(with_mismatch(&e, 14_000), false),
            e.clone(),
            LIMIT,
            Fr::ONE,
        );
        assert!(!s.derived.passed);
        assert!(step_satisfied(&s));
        let at_tau =
            StepCircuit::<E>::new(window(with_mismatch(&e, 14_000), false), e, TAU, Fr::ONE);
        assert!(at_tau.derived.passed);
        assert!(step_satisfied(&at_tau));
    }

    #[test]
    fn a_degenerate_window_never_passes() {
        let e = enrolled();
        let mut s = StepCircuit::<E>::new(window(with_mismatch(&e, 10), true), e, LIMIT, Fr::ONE);
        assert!(!s.derived.passed);
        assert!(step_satisfied(&s));
        s.derived.passed = true;
        assert!(!step_satisfied(&s));
    }

    #[test]
    fn the_core_accepts_limits_from_one_to_tau_only() {
        let e = enrolled();
        for (limit, ok) in [
            (0, false),
            (1, true),
            (LIMIT, true),
            (TAU, true),
            (TAU + 1, false),
            (1 << 14, false),
        ] {
            let c = CoreCircuit::<E>::new(
                e.clone(),
                limit,
                [5u8; 16],
                Fr::from(42u64),
                Fr::from(7u64),
                Fr::from(9u64),
            );
            assert_eq!(core_satisfied(&c), ok, "limit {limit}");
        }
    }

    /// Every value a circuit allocates, in order, synthesised into vega's
    /// witness generator (witness-only linear forms) and into `SatCs` (full
    /// forms). Were a witness-only form to take another `materialise`
    /// decision, the allocations would shift and differ here.
    fn assignments<C: VegaCircuit<E>>(c: &C) -> [(Vec<Fr>, Vec<Fr>); 2] {
        use vega_prover::bellpepper::solver::SatisfyingAssignment;
        let mut w = SatisfyingAssignment::<E>::new();
        assert!(w.is_witness_generator());
        let shared = c.shared(&mut w).unwrap();
        let pre = c.precommitted(&mut w, &shared).unwrap();
        c.synthesize(&mut w, &shared, &pre, None).unwrap();
        let mut full = SatCs::new();
        let shared = c.shared(&mut full).unwrap();
        let pre = c.precommitted(&mut full, &shared).unwrap();
        c.synthesize(&mut full, &shared, &pre, None).unwrap();
        assert!(full.is_satisfied());
        [
            (w.inputs_slice().to_vec(), w.aux_slice().to_vec()),
            (full.inputs, full.aux),
        ]
    }

    #[test]
    fn witness_only_forms_allocate_exactly_what_full_forms_do() {
        let e = enrolled();
        for (k, degenerate, limit) in [
            (0, false, LIMIT),
            (10, true, LIMIT),
            (LIMIT as usize - 1, false, LIMIT),
            (LIMIT as usize, false, LIMIT),
            (14_000, false, TAU),
            (NBITS, false, 1),
        ] {
            let s = StepCircuit::<E>::new(
                window(with_mismatch(&e, k), degenerate),
                e.clone(),
                limit,
                Fr::from(99u64),
            );
            let [w, full] = assignments(&s);
            assert!(w == full, "step at mismatch {k}");
        }
        for limit in [1, LIMIT, TAU] {
            let c = CoreCircuit::<E>::new(
                e.clone(),
                limit,
                [5u8; 16],
                Fr::from(42u64),
                Fr::from(7u64),
                Fr::from(9u64),
            );
            let [w, full] = assignments(&c);
            assert!(w == full, "core at limit {limit}");
        }
    }

    #[test]
    fn the_limit_is_inside_the_commitment() {
        let e = enrolled();
        let a = CoreCircuit::<E>::new(
            e.clone(),
            LIMIT,
            [5u8; 16],
            Fr::from(42u64),
            Fr::from(7u64),
            Fr::from(9u64),
        );
        let b = CoreCircuit::<E>::new(
            e,
            LIMIT - 1,
            [5u8; 16],
            Fr::from(42u64),
            Fr::from(7u64),
            Fr::from(9u64),
        );
        assert_ne!(a.commitment, b.commitment);
        assert_ne!(a.blinded, b.blinded);
        assert_eq!(a.genesis, b.genesis);
    }
}
