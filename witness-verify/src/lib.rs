//! Witness receipt verification.
//!
//! Everything needed to decode and verify a Witness batch receipt, an
//! enrolment proof and a membership proof, and nothing of the proving
//! side. The proving crate, witness-prover, depends on this one for the
//! shared definitions, so the two cannot drift apart.

pub mod batch;
pub mod chain;
pub mod circuits;
mod constants;
pub mod enrol;
pub mod membership;
pub mod poseidon2;
pub mod registry;
pub mod summary;

pub use batch::{BatchReceipt, BatchSummary, BatchVerifier, VerifyError, WindowVerdict};
pub use chain::{Chunk, Window, NCHUNK, PACK, TAU};
