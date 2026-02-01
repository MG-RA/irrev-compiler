use serde::{Deserialize, Serialize};

/// Top-level plan witness artifact.
/// Identity = SHA256(canonical_cbor(this struct)).
/// Projection = serde_json serialization of this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanWitness {
    pub schema_id: String,
    pub created_at: String,
    pub producer: PlanProducer,
    pub inputs: PlanInputs,
    pub template: PlanTemplate,
    pub answers: Vec<PlanAnswer>,
    pub derived: DerivedRisks,
    pub repro: PlanRepro,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanProducer {
    pub surface: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanInputs {
    pub template_id: String,
    pub scope: String,
    pub target: String,
}

/// The template's questions, frozen into the witness at creation time.
/// Prompts and answers are separate so that template evolution does not
/// retroactively change what questions were actually asked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanTemplate {
    pub template_id: String,
    pub template_hash: String,
    pub prompts: Vec<PlanPrompt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanPrompt {
    pub prompt_id: String,
    pub section: u32,
    pub title: String,
    pub guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanAnswer {
    pub prompt_id: String,
    pub answer: String,
}

/// Risk classification derived deterministically from the answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedRisks {
    pub erasure_grade: ErasureGrade,
    pub risk_label: String,
    pub invariants_touched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ErasureGrade {
    Grade0,
    Grade1,
    Grade2,
    Grade3,
}

/// Reproducibility hashes for verification and re-derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanRepro {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    pub template_hash: String,
    pub answers_file_hash: String,
}
