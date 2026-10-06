//! The verified summary as JSON, for the service and the page: every
//! byte string hex, every number plain.

use crate::batch::{BatchSummary, WindowVerdict};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerdictJson {
    pub window_index: u64,
    pub frames: u64,
    pub degenerate: bool,
    pub passed: bool,
    pub picture_root: String,
    pub head_in: String,
    pub head_out: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryJson {
    pub chain_id: String,
    pub blinded: String,
    pub genesis: String,
    pub head_in: String,
    pub head_out: String,
    pub windows: usize,
    pub passed: usize,
    pub failed: usize,
    pub verdicts: Vec<VerdictJson>,
}

impl From<&WindowVerdict> for VerdictJson {
    fn from(v: &WindowVerdict) -> Self {
        VerdictJson {
            window_index: v.window_index,
            frames: v.frames,
            degenerate: v.degenerate,
            passed: v.passed,
            picture_root: hex::encode(v.picture_root),
            head_in: hex::encode(v.head_in),
            head_out: hex::encode(v.head_out),
        }
    }
}

impl From<&BatchSummary> for SummaryJson {
    fn from(s: &BatchSummary) -> Self {
        let passed = s.verdicts.iter().filter(|v| v.passed).count();
        SummaryJson {
            chain_id: hex::encode(s.chain_id),
            blinded: hex::encode(s.blinded),
            genesis: hex::encode(s.genesis),
            head_in: hex::encode(s.head_in),
            head_out: hex::encode(s.head_out),
            windows: s.verdicts.len(),
            passed,
            failed: s.verdicts.len() - passed,
            verdicts: s.verdicts.iter().map(VerdictJson::from).collect(),
        }
    }
}

impl BatchSummary {
    pub fn to_json(&self) -> String {
        serde_json::to_string(&SummaryJson::from(self)).expect("summary serialises")
    }
}
