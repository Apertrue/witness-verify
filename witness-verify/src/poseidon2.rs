//! Poseidon2 over BN254 Fr (t = 4, x^5, 8 external + 56 internal rounds),
//! natively and in-circuit. Mirrors the app's Poseidon2.swift and the Noir
//! stdlib sponge (iv = len << 64 in the capacity slot, rate 3), so the
//! circuit's digests are the chain's digests.

use crate::constants::{DIAG_MINUS_ONE, ROUND_CONSTANTS};
use bellpepper_core::{ConstraintSystem, LinearCombination, SynthesisError, Variable};
use ff::{Field, PrimeField};
use halo2curves::bn256::Fr;
use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::OnceLock;

pub fn fr_from_hex(h: &str) -> Fr {
    let bytes = hex::decode(h).expect("hex");
    let mut le = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        le[31 - i] = *b;
    }
    Option::from(Fr::from_bytes(&le)).expect("canonical field element")
}

struct Consts {
    rc: Vec<Fr>,
    diag: [Fr; 4],
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| Consts {
        rc: ROUND_CONSTANTS.iter().map(|h| fr_from_hex(h)).collect(),
        diag: [
            fr_from_hex(DIAG_MINUS_ONE[0]),
            fr_from_hex(DIAG_MINUS_ONE[1]),
            fr_from_hex(DIAG_MINUS_ONE[2]),
            fr_from_hex(DIAG_MINUS_ONE[3]),
        ],
    })
}

// ---------------------------------------------------------------- native

fn external(s: [Fr; 4]) -> [Fr; 4] {
    let t0 = s[0] + s[1];
    let t1 = s[2] + s[3];
    let t2 = s[1].double() + t1;
    let t3 = s[3].double() + t0;
    let t4 = t1.double().double() + t3;
    let t5 = t0.double().double() + t2;
    [t3 + t5, t5, t2 + t4, t4]
}

fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    x2.square() * x
}

pub fn permutation(input: [Fr; 4]) -> [Fr; 4] {
    let c = consts();
    let mut s = external(input);
    for r in 0..4 {
        for (i, x) in s.iter_mut().enumerate() {
            *x = sbox(*x + c.rc[r * 4 + i]);
        }
        s = external(s);
    }
    for r in 4..60 {
        s[0] = sbox(s[0] + c.rc[r * 4]);
        let sum = s[0] + s[1] + s[2] + s[3];
        for (x, d) in s.iter_mut().zip(c.diag.iter()) {
            *x = *x * d + sum;
        }
    }
    for r in 60..64 {
        for (i, x) in s.iter_mut().enumerate() {
            *x = sbox(*x + c.rc[r * 4 + i]);
        }
        s = external(s);
    }
    s
}

/// The Noir-stdlib sponge: iv = len << 64, rate 3, squeeze the first element.
pub fn hash(inputs: &[Fr]) -> Fr {
    let iv = Fr::from(inputs.len() as u64) * Fr::from_u128(1u128 << 64);
    let mut state = [Fr::ZERO, Fr::ZERO, Fr::ZERO, iv];
    let full = inputs.len() / 3;
    for c in 0..full {
        for j in 0..3 {
            state[j] += inputs[c * 3 + j];
        }
        state = permutation(state);
    }
    for j in 0..(inputs.len() - full * 3) {
        state[j] += inputs[full * 3 + j];
    }
    permutation(state)[0]
}

// ---------------------------------------------------------------- circuit

thread_local! {
    /// Set while this thread synthesises a circuit into a witness generator:
    /// see `WitnessOnly`.
    static WITNESS_ONLY: Cell<bool> = const { Cell::new(false) };
}

fn witness_only() -> bool {
    WITNESS_ONLY.with(Cell::get)
}

/// Switches linear forms on this thread to witness-only bookkeeping for as
/// long as it lives, when `cs` is a witness generator; otherwise it switches
/// them explicitly to the full path.
///
/// A witness generator drops every constraint unread, so a form there needs
/// only its value and the one structural fact `materialise` asks of it:
/// whether it holds more than one variable. Witness-only forms keep at most
/// two of their variables and leave coefficients unmaintained, which saves
/// the term bookkeeping of a full form (long forms merged and rescaled every
/// Poseidon2 round) without changing a single allocated value. Key setup
/// and every other constraint system keep the full forms.
///
/// The previous setting comes back on drop, on every exit path including
/// `?` and unwinding. The guard is not `Send`, so it is dropped on the
/// thread that made it, and the setting is per thread, so another thread,
/// rayon workers included, never sees it. Synthesis under the guard starts
/// no parallel work, so no other job can run on this thread meanwhile.
pub(crate) struct WitnessOnly {
    previous: bool,
    _not_send: PhantomData<*const ()>,
}

impl WitnessOnly {
    pub(crate) fn enter<CS: ConstraintSystem<Fr>>(cs: &CS) -> Self {
        let previous = WITNESS_ONLY.with(|f| f.replace(cs.is_witness_generator()));
        WitnessOnly {
            previous,
            _not_send: PhantomData,
        }
    }
}

impl Drop for WitnessOnly {
    fn drop(&mut self) {
        WITNESS_ONLY.with(|f| f.set(self.previous));
    }
}

/// A linear form over allocated variables plus a constant, with its value.
/// Poseidon2's linear layers stay linear combinations; only the S-box
/// allocates, so a permutation costs 88 S-boxes x 3 constraints.
///
/// The full path never drops a term: a variable whose coefficient cancels
/// to zero stays in the form and still counts towards `materialise`'s
/// decision. Under `WitnessOnly`, `terms` holds `min(2, n)` of the full
/// form's `n` distinct variables with unmaintained coefficients, which is
/// enough for that decision to come out the same; nothing else reads them.
#[derive(Clone)]
pub struct Lc {
    pub terms: Vec<(Variable, Fr)>,
    pub constant: Fr,
    pub value: Option<Fr>,
}

/// How many variables a witness-only form keeps.
const WITNESS_TERMS: usize = 2;

impl Lc {
    pub fn constant(c: Fr) -> Self {
        Lc {
            terms: vec![],
            constant: c,
            value: Some(c),
        }
    }
    pub fn var(v: Variable, value: Option<Fr>) -> Self {
        Lc {
            terms: vec![(v, Fr::ONE)],
            constant: Fr::ZERO,
            value,
        }
    }
    pub fn zero() -> Self {
        Self::constant(Fr::ZERO)
    }
    /// Adds, merging coefficients of shared variables so a form never
    /// carries a variable twice (the internal rounds would otherwise double
    /// the term count every round).
    pub fn add(&self, o: &Lc) -> Lc {
        let witness = witness_only();
        let mut terms: Vec<(Variable, Fr)> = if witness {
            let mut t = Vec::with_capacity(WITNESS_TERMS);
            t.extend(self.terms.iter().take(WITNESS_TERMS).copied());
            t
        } else {
            self.terms.clone()
        };
        for (v, c) in &o.terms {
            if witness && terms.len() >= WITNESS_TERMS {
                break;
            }
            if let Some(t) = terms.iter_mut().find(|(w, _)| w == v) {
                t.1 += *c;
            } else {
                terms.push((*v, *c));
            }
        }
        Lc {
            terms,
            constant: self.constant + o.constant,
            value: self.value.and_then(|a| o.value.map(|b| a + b)),
        }
    }

    /// Pins the form to one fresh variable (one constraint), so what follows
    /// works on a single term rather than a long linear form.
    pub fn materialise<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        label: &str,
    ) -> Result<Lc, SynthesisError> {
        if self.terms.len() <= 1 {
            return Ok(self.clone());
        }
        let v = cs.alloc(
            || label.to_string(),
            || self.value.ok_or(SynthesisError::AssignmentMissing),
        )?;
        cs.enforce(
            || format!("{label} pin"),
            |_| self.lc::<CS>(),
            |lc| lc + CS::one(),
            |lc| lc + v,
        );
        Ok(Lc::var(v, self.value))
    }
    pub fn add_const(&self, c: Fr) -> Lc {
        Lc {
            terms: self.terms.clone(),
            constant: self.constant + c,
            value: self.value.map(|v| v + c),
        }
    }
    pub fn scale(&self, k: Fr) -> Lc {
        let terms = if witness_only() {
            // Coefficients are not maintained here: the variables are.
            self.terms.clone()
        } else {
            self.terms.iter().map(|(v, c)| (*v, *c * k)).collect()
        };
        Lc {
            terms,
            constant: self.constant * k,
            value: self.value.map(|v| v * k),
        }
    }
    /// Appends a term for a variable KNOWN not to be in the form yet
    /// (fresh allocations): no merge scan, so long accumulations stay linear.
    pub fn push_term(&mut self, v: Variable, coeff: Fr, value: Option<Fr>) {
        if self.terms.len() < WITNESS_TERMS || !witness_only() {
            self.terms.push((v, coeff));
        }
        self.value = self.value.and_then(|a| value.map(|b| a + coeff * b));
    }
    pub fn double(&self) -> Lc {
        self.add(self)
    }
    pub fn lc<CS: ConstraintSystem<Fr>>(&self) -> LinearCombination<Fr> {
        // A witness-only form is not the form: it must never reach a
        // constraint system that reads its constraints.
        assert!(!witness_only(), "a linear form read under WitnessOnly");
        let mut lc = LinearCombination::zero();
        for (v, c) in &self.terms {
            lc = lc + (*c, *v);
        }
        if self.constant != Fr::ZERO {
            lc = lc + (self.constant, CS::one());
        }
        lc
    }
}

/// x^5 with three multiplications.
pub fn sbox_gadget<CS: ConstraintSystem<Fr>>(cs: &mut CS, x: &Lc) -> Result<Lc, SynthesisError> {
    let x2v = x.value.map(|v| v.square());
    let x2 = cs.alloc(|| "x2", || x2v.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce(|| "x*x", |_| x.lc::<CS>(), |_| x.lc::<CS>(), |lc| lc + x2);
    let x4v = x2v.map(|v| v.square());
    let x4 = cs.alloc(|| "x4", || x4v.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce(|| "x2*x2", |lc| lc + x2, |lc| lc + x2, |lc| lc + x4);
    let x5v = x4v.and_then(|a| x.value.map(|b| a * b));
    let x5 = cs.alloc(|| "x5", || x5v.ok_or(SynthesisError::AssignmentMissing))?;
    cs.enforce(|| "x4*x", |lc| lc + x4, |_| x.lc::<CS>(), |lc| lc + x5);
    Ok(Lc::var(x5, x5v))
}

fn external_gadget(s: [Lc; 4]) -> [Lc; 4] {
    let t0 = s[0].add(&s[1]);
    let t1 = s[2].add(&s[3]);
    let t2 = s[1].double().add(&t1);
    let t3 = s[3].double().add(&t0);
    let t4 = t1.double().double().add(&t3);
    let t5 = t0.double().double().add(&t2);
    [t3.add(&t5), t5, t2.add(&t4), t4]
}

pub fn permutation_gadget<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    input: [Lc; 4],
) -> Result<[Lc; 4], SynthesisError> {
    let c = consts();
    let mut input = input;
    for (i, x) in input.iter_mut().enumerate() {
        *x = x.materialise(cs, &format!("state in {i}"))?;
    }
    let mut s = external_gadget(input);
    for r in 0..4 {
        for (i, x) in s.iter_mut().enumerate() {
            *x = sbox_gadget(
                &mut cs.namespace(|| format!("ext {r} {i}")),
                &x.add_const(c.rc[r * 4 + i]),
            )?;
        }
        s = external_gadget(s);
    }
    for r in 4..60 {
        s[0] = sbox_gadget(
            &mut cs.namespace(|| format!("int {r}")),
            &s[0].add_const(c.rc[r * 4]),
        )?;
        let sum = s[0].add(&s[1]).add(&s[2]).add(&s[3]);
        for (x, d) in s.iter_mut().zip(c.diag.iter()) {
            *x = x.scale(*d).add(&sum);
        }
    }
    for r in 60..64 {
        for (i, x) in s.iter_mut().enumerate() {
            *x = sbox_gadget(
                &mut cs.namespace(|| format!("ext {r} {i}")),
                &x.add_const(c.rc[r * 4 + i]),
            )?;
        }
        s = external_gadget(s);
    }
    Ok(s)
}

/// The sponge, in-circuit; inputs are linear forms.
pub fn hash_gadget<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    inputs: &[Lc],
) -> Result<Lc, SynthesisError> {
    let iv = Fr::from(inputs.len() as u64) * Fr::from_u128(1u128 << 64);
    let mut state = [Lc::zero(), Lc::zero(), Lc::zero(), Lc::constant(iv)];
    let full = inputs.len() / 3;
    for c in 0..full {
        for j in 0..3 {
            state[j] = state[j].add(&inputs[c * 3 + j]);
        }
        state = permutation_gadget(&mut cs.namespace(|| format!("block {c}")), state)?;
    }
    for j in 0..(inputs.len() - full * 3) {
        state[j] = state[j].add(&inputs[full * 3 + j]);
    }
    let out = permutation_gadget(&mut cs.namespace(|| "final"), state)?;
    Ok(out[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use vega_prover::bellpepper::solver::SatisfyingAssignment;

    #[test]
    fn witness_only_is_restored_on_every_exit() {
        let w = SatisfyingAssignment::<crate::batch::E>::new();
        let full = TestConstraintSystem::<Fr>::new();
        assert!(!witness_only());
        {
            let _outer = WitnessOnly::enter(&w);
            assert!(witness_only());
            {
                // A full constraint system inside switches it off again.
                let _inner = WitnessOnly::enter(&full);
                assert!(!witness_only());
            }
            assert!(witness_only());
        }
        assert!(!witness_only());
        let unwound = std::panic::catch_unwind(|| {
            let _g = WitnessOnly::enter(&SatisfyingAssignment::<crate::batch::E>::new());
            panic!("synthesis failed");
        });
        assert!(unwound.is_err());
        assert!(!witness_only(), "restored when a synthesis unwinds");
        // Per thread: another thread never sees this one's setting.
        let _g = WitnessOnly::enter(&w);
        assert!(!std::thread::spawn(witness_only).join().unwrap());
    }

    /// The sponge's output value and materialise decisions are the same
    /// under both paths, on forms with cancelling and repeated variables.
    #[test]
    fn witness_only_forms_keep_values_and_the_many_terms_question() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let vars: Vec<Lc> = (0..4)
            .map(|i| {
                let v = cs
                    .alloc(|| format!("v{i}"), || Ok(Fr::from(i as u64 + 3)))
                    .unwrap();
                Lc::var(v, Some(Fr::from(i as u64 + 3)))
            })
            .collect();
        let forms = |vars: &[Lc]| -> Vec<Lc> {
            let a = &vars[0];
            let b = &vars[1];
            let cancel = a.add(&a.scale(-Fr::ONE)); // one variable, zero coefficient
            let mut long = Lc::zero();
            for (i, v) in vars.iter().enumerate() {
                long = long.add(&v.scale(Fr::from(i as u64 + 1)));
            }
            let mut pushed = Lc::constant(Fr::from(5u64));
            for v in vars {
                pushed.push_term(v.terms[0].0, Fr::from(7u64), v.value);
            }
            vec![
                Lc::zero(),
                a.clone(),
                a.double().double(),
                cancel.clone(),
                cancel.add(b),
                a.add(b).add(&a.scale(-Fr::ONE)),
                long.clone(),
                long.add(&long.scale(-Fr::ONE)),
                Lc::zero().add(&long),
                pushed.add(a),
                b.add(&pushed).add_const(Fr::ONE),
            ]
        };
        let full = forms(&vars);
        let w = SatisfyingAssignment::<crate::batch::E>::new();
        let _g = WitnessOnly::enter(&w);
        let fast = forms(&vars);
        for (i, (f, q)) in full.iter().zip(&fast).enumerate() {
            assert_eq!(f.value, q.value, "form {i}");
            assert_eq!(f.terms.len() <= 1, q.terms.len() <= 1, "form {i}");
            assert!(q.terms.len() <= WITNESS_TERMS, "form {i}");
        }
    }

    #[test]
    fn matches_noirs_known_digest() {
        // The vector the app pins its Swift implementation to.
        let h = hash(&[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
        ]);
        let mut be = h.to_bytes();
        be.reverse();
        assert_eq!(
            hex::encode(be),
            "2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db"
        );
    }
}
