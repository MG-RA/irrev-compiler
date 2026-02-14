use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::artifact::{default_artifacts_dir, store_artifact};
use super::internal::{
    artifact_disk_path, decode_cbor_to_value, payload_hash, sha256_hex, PLAN_TEMPLATE_ID,
    PLAN_WITNESS_SCHEMA_ID, PLAN_WITNESS_SCHEMA_ID_V1,
};
use super::registry::{registry_allows_schema, resolve_meta_registry};
use super::types::{
    DeclareCostError, MetaRegistryV0, PlanCreatedEvent, PlanCreatedPayload, PlanNewInput,
    PlanProducerRef, PlanReproRef,
};

// ---------------------------------------------------------------------------
// Diagnostic prompt template
// ---------------------------------------------------------------------------

pub fn diagnostic_prompts() -> Vec<admit_core::PlanPrompt> {
    vec![
        admit_core::PlanPrompt {
            prompt_id: "action_definition".into(),
            section: 1,
            title: "Action Definition".into(),
            guidance: "What specific action is being performed? What system(s) or substrate(s) does it touch? What is the minimal description that distinguishes this action from similar ones?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "boundary_declaration".into(),
            section: 2,
            title: "Boundary Declaration".into(),
            guidance: "What is allowed to change? What must not change? What files, records, artifacts, schemas, or external systems are in scope? What explicit paths/resources are out of bounds?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "persistence_analysis".into(),
            section: 3,
            title: "Persistence Analysis".into(),
            guidance: "After the action completes, what differences remain even if no one uses the result? Which changes persist by default? Which changes would require active effort to undo?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "erasure_cost".into(),
            section: 4,
            title: "Erasure Cost".into(),
            guidance: "If you attempted to undo this action, what would be lost? Classify the erasure cost: Grade 0 (fully reversible, no loss), Grade 1 (reversible with routine effort), Grade 2 (costly or lossy to reverse), Grade 3 (irreversible or externally irreversible). Describe the cost in concrete terms.".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "displacement_ownership".into(),
            section: 5,
            title: "Displacement & Ownership".into(),
            guidance: "Who absorbs the cost if reversal is required? Is the cost borne by the actor, future maintainers, users, or external systems or people? Is this displacement explicit and accepted?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "preconditions".into(),
            section: 6,
            title: "Preconditions".into(),
            guidance: "What facts must be true before execution? What evidence is required to prove those facts? How are those facts snapshotted or attested? If a precondition cannot be witnessed, it must not be assumed.".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "execution_constraints".into(),
            section: 7,
            title: "Execution Constraints".into(),
            guidance: "What constraints must hold during execution? What failure modes are acceptable? What failures must abort the action immediately?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "postconditions".into(),
            section: 8,
            title: "Postconditions".into(),
            guidance: "What evidence will prove what actually happened? How will success be distinguished from partial or failed execution? What artifacts or records must be produced?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "accountability".into(),
            section: 9,
            title: "Accountability".into(),
            guidance: "Who is the acting entity? Under what authority is the action performed? What identifier ties this action to a responsible actor or system?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "acceptance_criteria".into(),
            section: 10,
            title: "Acceptance Criteria".into(),
            guidance: "Under what conditions is the action considered done? What would count as unacceptable even if execution technically succeeded?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "refusal_conditions".into(),
            section: 11,
            title: "Refusal Conditions".into(),
            guidance: "List conditions under which the plan must not be executed. What missing evidence or ambiguity should cause a hard stop?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "final_check".into(),
            section: 12,
            title: "Final Check".into(),
            guidance: "Answer yes/no: Are all irreversible effects bounded? Is erasure cost explicitly declared and accepted? Is responsibility assigned without ambiguity? Could a future reader reconstruct why this action happened? If any answer is no, the plan is not admissible.".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Public: prompt template + markdown answer parsing
// ---------------------------------------------------------------------------

pub fn render_plan_prompt_template(include_guidance: bool) -> String {
    let prompts = diagnostic_prompts();
    let mut out = String::new();
    out.push_str("## Irreversibility-First Plan Design Prompt (Template)\n\n");
    out.push_str(
        "Fill each section, then convert to JSON with:\n\n`admit-cli plan answers-from-md --in plan.md --out answers.json`\n\n",
    );

    for prompt in prompts {
        out.push_str(&format!("### {}. {}\n\n", prompt.section, prompt.title));
        out.push_str(&format!("Prompt ID: `{}`\n\n", prompt.prompt_id));
        if include_guidance {
            out.push_str(&format!("Guidance: {}\n\n", prompt.guidance));
        }
        out.push_str("Answer:\n\n");
        out.push_str("---\n\n");
    }
    out
}

pub fn parse_plan_answers_markdown(
    markdown: &str,
) -> Result<Vec<admit_core::PlanAnswer>, DeclareCostError> {
    let prompts = diagnostic_prompts();
    let prompts_by_section: std::collections::BTreeMap<u32, &admit_core::PlanPrompt> =
        prompts.iter().map(|p| (p.section, p)).collect();

    let mut current_section: Option<u32> = None;
    let mut section_lines: std::collections::BTreeMap<u32, Vec<String>> =
        std::collections::BTreeMap::new();

    for line in markdown.lines() {
        if let Some(section) = parse_section_heading(line) {
            if !prompts_by_section.contains_key(&section) {
                current_section = None;
                continue;
            }
            if section_lines.contains_key(&section) {
                return Err(DeclareCostError::PlanMarkdownParse(format!(
                    "duplicate section heading for section {}",
                    section
                )));
            }
            section_lines.insert(section, Vec::new());
            current_section = Some(section);
            continue;
        }
        if let Some(section) = current_section {
            section_lines
                .entry(section)
                .or_default()
                .push(line.to_string());
        }
    }

    let mut answers = Vec::with_capacity(prompts.len());
    for prompt in prompts {
        let lines = section_lines.get(&prompt.section).ok_or_else(|| {
            DeclareCostError::PlanMarkdownParse(format!(
                "missing section {} ({})",
                prompt.section, prompt.prompt_id
            ))
        })?;
        let answer = extract_section_answer(lines).ok_or_else(|| {
            DeclareCostError::PlanMarkdownParse(format!(
                "empty answer in section {} ({})",
                prompt.section, prompt.prompt_id
            ))
        })?;
        answers.push(admit_core::PlanAnswer {
            prompt_id: prompt.prompt_id,
            answer,
        });
    }

    Ok(answers)
}

fn parse_section_heading(line: &str) -> Option<u32> {
    let trimmed = line.trim().trim_start_matches('\u{feff}');
    if !trimmed.starts_with("###") {
        return None;
    }
    let heading = trimmed.trim_start_matches('#').trim();
    let (num, _) = heading.split_once('.')?;
    num.trim().parse::<u32>().ok()
}

fn extract_section_answer(lines: &[String]) -> Option<String> {
    let mut start = 0usize;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower == "answer:" || lower == "**answer:**" || lower == "answer" {
            start = idx + 1;
            break;
        }
        if lower.starts_with("answer:") {
            let inline = trimmed[7..].trim();
            if inline.is_empty() {
                start = idx + 1;
            } else {
                return Some(inline.to_string());
            }
            break;
        }
    }

    let mut filtered = Vec::new();
    for line in &lines[start..] {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if trimmed == "---" {
            break;
        }
        if trimmed.starts_with("<!--") && trimmed.ends_with("-->") {
            continue;
        }
        if lower.starts_with("prompt id:") || lower.starts_with("guidance:") {
            continue;
        }
        filtered.push(line.as_str());
    }

    let answer = filtered.join("\n").trim().to_string();
    if answer.is_empty() {
        None
    } else {
        Some(answer)
    }
}

// ---------------------------------------------------------------------------
// Risk derivation from answers
// ---------------------------------------------------------------------------

fn derive_risks(answers: &[admit_core::PlanAnswer]) -> admit_core::DerivedRisks {
    let erasure_answer = answers
        .iter()
        .find(|a| a.prompt_id == "erasure_cost")
        .map(|a| a.answer.to_lowercase())
        .unwrap_or_default();

    let erasure_grade = match max_erasure_grade(&erasure_answer) {
        3 => admit_core::ErasureGrade::Grade3,
        2 => admit_core::ErasureGrade::Grade2,
        1 => admit_core::ErasureGrade::Grade1,
        _ => admit_core::ErasureGrade::Grade0,
    };

    let risk_label = match &erasure_grade {
        admit_core::ErasureGrade::Grade3 => "mutation_destructive",
        admit_core::ErasureGrade::Grade1 | admit_core::ErasureGrade::Grade2 => {
            "mutation_non_destructive"
        }
        admit_core::ErasureGrade::Grade0 => "none",
    }
    .to_string();

    let keywords = [
        "governance",
        "irreversibility",
        "decomposition",
        "attribution",
    ];
    let mut invariants_touched: Vec<String> = keywords
        .iter()
        .filter(|kw| {
            answers
                .iter()
                .any(|a| a.answer.to_lowercase().contains(*kw))
        })
        .map(|kw| kw.to_string())
        .collect();
    invariants_touched.sort();

    admit_core::DerivedRisks {
        erasure_grade,
        risk_label,
        invariants_touched,
    }
}

fn max_erasure_grade(answer: &str) -> u8 {
    let bytes = answer.as_bytes();
    let mut max_grade = 0u8;
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] == b"grade" {
            let left_ok = i == 0 || !is_word_char(bytes[i - 1]);
            let mut j = i + 5;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if left_ok && j < bytes.len() && bytes[j].is_ascii_digit() {
                let digit = bytes[j] - b'0';
                let right_ok = j + 1 == bytes.len() || !is_word_char(bytes[j + 1]);
                if right_ok && digit <= 3 && digit > max_grade {
                    max_grade = digit;
                }
            }
        }
        i += 1;
    }
    max_grade
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn select_plan_witness_schema_id(registry: Option<&MetaRegistryV0>) -> &'static str {
    if let Some(registry) = registry {
        if registry_allows_schema(registry, PLAN_WITNESS_SCHEMA_ID) {
            return PLAN_WITNESS_SCHEMA_ID;
        }
        if registry_allows_schema(registry, PLAN_WITNESS_SCHEMA_ID_V1) {
            return PLAN_WITNESS_SCHEMA_ID_V1;
        }
    }
    PLAN_WITNESS_SCHEMA_ID
}

// ---------------------------------------------------------------------------
// Plan contract validation (typed planner/implementer artifacts)
// ---------------------------------------------------------------------------

pub const PLAN_ARTIFACT_SCHEMA_ID: &str = "plan-artifact/0";
pub const PROPOSAL_MANIFEST_SCHEMA_ID: &str = "proposal-manifest/0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassification {
    None,
    Mechanical,
    Semantic,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanCheckSchemaIds {
    pub plan: Option<String>,
    pub manifest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanCheckOutput {
    pub schema_id: String,
    pub plan_present: bool,
    pub plan_valid: bool,
    pub manifest_present: bool,
    pub manifest_valid: bool,
    pub schema_ids: PlanCheckSchemaIds,
    pub plan_id: Option<String>,
    pub plan_hash: Option<String>,
    pub manifest_id: Option<String>,
    pub manifest_hash: Option<String>,
    pub changed_paths_observed: Vec<String>,
    pub changed_paths_claimed: Vec<String>,
    pub changed_paths_unexpected: Vec<String>,
    pub changed_paths_missing_from_claim: Vec<String>,
    pub changed_paths_extra_in_claim: Vec<String>,
    pub changed_paths_missing_from_expected: Vec<String>,
    pub stop_reasons: Vec<String>,
    pub requires_manual_approval: bool,
    pub failure_classification: FailureClassification,
    pub confidence: Option<f64>,
    pub unknowns: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub exit_code: i32,
}

impl PlanCheckOutput {
    pub fn apply_semantic_failure(&mut self, reason: &str) {
        if !self.stop_reasons.iter().any(|r| r == reason) {
            self.stop_reasons.push(reason.to_string());
        }
        self.requires_manual_approval = true;
        self.failure_classification = FailureClassification::Semantic;
        if !self
            .warnings
            .iter()
            .any(|w| w == "semantic failure observed during CI")
        {
            self.warnings
                .push("semantic failure observed during CI".to_string());
        }
    }
}

pub struct PlanCheckInput {
    pub plan_path: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
    pub changed_paths_observed: Vec<String>,
    pub enforce: bool,
}

#[derive(Debug, Clone)]
pub struct PlanAutogenInput {
    pub out_plan_path: PathBuf,
    pub out_manifest_path: PathBuf,
    pub intent: String,
    pub scope_targets: Vec<String>,
    pub expected_changed_paths: Vec<String>,
    pub commands_run: Vec<String>,
    pub artifacts_produced: Vec<String>,
    pub base_sha: String,
    pub head_sha: String,
    pub surface: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanAutogenOutput {
    pub plan_path: PathBuf,
    pub manifest_path: PathBuf,
    pub plan_id: String,
    pub manifest_id: String,
    pub changed_paths: Vec<String>,
    pub base_sha: String,
    pub head_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanArtifact {
    schema_id: String,
    plan_id: String,
    intent: String,
    scope_targets: Vec<String>,
    #[serde(default)]
    expected_changed_paths: Vec<String>,
    assumptions: Vec<String>,
    constraints_expected: Vec<String>,
    allowed_exceptions: Vec<String>,
    validation_steps: Vec<PlanValidationStep>,
    stop_conditions: Vec<String>,
    risk_routes: Vec<PlanRiskRoute>,
    #[serde(default)]
    unknowns: Vec<String>,
    confidence: f64,
    generated_by: PlanGeneratedBy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanValidationStep {
    id: String,
    command: String,
    required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRiskRoute {
    bucket: String,
    cost_estimate: f64,
    unit: String,
    rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanGeneratedBy {
    provider: String,
    model: String,
    surface: String,
    timestamp: String,
    #[serde(default)]
    planner_prompt_hash: Option<String>,
    #[serde(default)]
    implementer_prompt_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalManifest {
    schema_id: String,
    manifest_id: String,
    plan_id: String,
    base_sha: String,
    head_sha: String,
    changed_paths: Vec<String>,
    commands_run: Vec<String>,
    artifacts_produced: Vec<String>,
    #[serde(default)]
    test_results: Vec<ManifestTestResult>,
    #[serde(default)]
    exceptions_requested: Vec<String>,
    status: ManifestStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestTestResult {
    command: String,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestStatus {
    Proposed,
    Revised,
    Halted,
    ReadyForReview,
}

pub fn autogen_plan_artifacts(input: PlanAutogenInput) -> Result<PlanAutogenOutput, DeclareCostError> {
    if input.intent.trim().is_empty() {
        return Err(DeclareCostError::Json(
            "autogen intent cannot be empty".to_string(),
        ));
    }
    if input.base_sha.trim().is_empty() || input.head_sha.trim().is_empty() {
        return Err(DeclareCostError::Json(
            "autogen base/head sha must be non-empty".to_string(),
        ));
    }

    let scope_targets = {
        let normalized = normalize_paths(input.scope_targets);
        if normalized.is_empty() {
            vec![".".to_string()]
        } else {
            normalized
        }
    };
    let expected_changed_paths = normalize_paths(input.expected_changed_paths);
    let commands_run = if input.commands_run.is_empty() {
        vec!["admit ci --mode enforce".to_string()]
    } else {
        input.commands_run
    };
    let artifacts_produced = if input.artifacts_produced.is_empty() {
        vec!["out/ci-witness.json".to_string()]
    } else {
        normalize_paths(input.artifacts_produced)
    };

    let mut plan = PlanArtifact {
        schema_id: PLAN_ARTIFACT_SCHEMA_ID.to_string(),
        plan_id: String::new(),
        intent: input.intent,
        scope_targets,
        expected_changed_paths: expected_changed_paths.clone(),
        assumptions: vec!["auto-generated scaffold; refine before merge".to_string()],
        constraints_expected: vec![],
        allowed_exceptions: vec![],
        validation_steps: commands_run
            .iter()
            .enumerate()
            .map(|(idx, command)| PlanValidationStep {
                id: format!("cmd_{}", idx + 1),
                command: command.clone(),
                required: true,
            })
            .collect(),
        stop_conditions: vec![
            "touches_github_workflows".to_string(),
            "meta_schema_change".to_string(),
            "secrets_detected".to_string(),
        ],
        risk_routes: vec![PlanRiskRoute {
            bucket: "bucket:trust_debt".to_string(),
            cost_estimate: 1.0,
            unit: "risk_points".to_string(),
            rationale: "auto-generated scaffold route".to_string(),
        }],
        unknowns: vec![],
        confidence: 0.0,
        generated_by: PlanGeneratedBy {
            provider: "admit_cli".to_string(),
            model: "autogen/v1".to_string(),
            surface: input.surface,
            timestamp: input.timestamp,
            planner_prompt_hash: None,
            implementer_prompt_hash: None,
        },
    };
    let plan_hash = canonical_hash_without_field(&plan, "plan_id")
        .map_err(DeclareCostError::Json)?;
    plan.plan_id = format!("plan:{}", plan_hash);

    let mut manifest = ProposalManifest {
        schema_id: PROPOSAL_MANIFEST_SCHEMA_ID.to_string(),
        manifest_id: String::new(),
        plan_id: plan.plan_id.clone(),
        base_sha: input.base_sha.clone(),
        head_sha: input.head_sha.clone(),
        changed_paths: expected_changed_paths,
        commands_run,
        artifacts_produced,
        test_results: vec![],
        exceptions_requested: vec![],
        status: ManifestStatus::ReadyForReview,
    };
    let manifest_hash = canonical_hash_without_field(&manifest, "manifest_id")
        .map_err(DeclareCostError::Json)?;
    manifest.manifest_id = format!("manifest:{}", manifest_hash);

    if let Some(parent) = input.out_plan_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }
    if let Some(parent) = input.out_manifest_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    let plan_json =
        serde_json::to_string_pretty(&plan).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(&input.out_plan_path, plan_json).map_err(|err| DeclareCostError::Io(err.to_string()))?;

    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(&input.out_manifest_path, manifest_json)
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(PlanAutogenOutput {
        plan_path: input.out_plan_path,
        manifest_path: input.out_manifest_path,
        plan_id: plan.plan_id,
        manifest_id: manifest.manifest_id,
        changed_paths: manifest.changed_paths,
        base_sha: input.base_sha,
        head_sha: input.head_sha,
    })
}

pub fn read_changed_paths_file(path: &Path) -> Result<Vec<String>, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("read changed paths '{}': {}", path.display(), err))?;
    parse_changed_paths_text(&raw)
}

pub fn check_plan_contract(input: PlanCheckInput) -> PlanCheckOutput {
    let mut out = PlanCheckOutput {
        schema_id: "plan-contract-check/0".to_string(),
        plan_present: false,
        plan_valid: false,
        manifest_present: false,
        manifest_valid: false,
        schema_ids: PlanCheckSchemaIds {
            plan: None,
            manifest: None,
        },
        plan_id: None,
        plan_hash: None,
        manifest_id: None,
        manifest_hash: None,
        changed_paths_observed: normalize_paths(input.changed_paths_observed),
        changed_paths_claimed: Vec::new(),
        changed_paths_unexpected: Vec::new(),
        changed_paths_missing_from_claim: Vec::new(),
        changed_paths_extra_in_claim: Vec::new(),
        changed_paths_missing_from_expected: Vec::new(),
        stop_reasons: Vec::new(),
        requires_manual_approval: false,
        failure_classification: FailureClassification::None,
        confidence: None,
        unknowns: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
        exit_code: 0,
    };

    let mut parsed_plan: Option<PlanArtifact> = None;
    if let Some(path) = input.plan_path.as_ref() {
        if path.exists() {
            out.plan_present = true;
            match fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<PlanArtifact>(&bytes) {
                    Ok(plan) => {
                        out.schema_ids.plan = Some(plan.schema_id.clone());
                        out.plan_id = Some(plan.plan_id.clone());
                        validate_plan_artifact(&plan, &mut out);
                        parsed_plan = Some(plan);
                    }
                    Err(err) => out.errors.push(format!(
                        "plan decode '{}': {}",
                        path.display(),
                        err
                    )),
                },
                Err(err) => out
                    .errors
                    .push(format!("read plan '{}': {}", path.display(), err)),
            }
        } else {
            out.warnings
                .push(format!("plan artifact not found: {}", path.display()));
            if input.enforce {
                out.errors
                    .push(format!("plan artifact required in enforce mode: {}", path.display()));
            }
        }
    }

    let mut parsed_manifest: Option<ProposalManifest> = None;
    if let Some(path) = input.manifest_path.as_ref() {
        if path.exists() {
            out.manifest_present = true;
            match fs::read(path) {
                Ok(bytes) => match serde_json::from_slice::<ProposalManifest>(&bytes) {
                    Ok(manifest) => {
                        out.schema_ids.manifest = Some(manifest.schema_id.clone());
                        out.manifest_id = Some(manifest.manifest_id.clone());
                        out.changed_paths_claimed = normalize_paths(manifest.changed_paths.clone());
                        validate_manifest(&manifest, &mut out);
                        parsed_manifest = Some(manifest);
                    }
                    Err(err) => out.errors.push(format!(
                        "manifest decode '{}': {}",
                        path.display(),
                        err
                    )),
                },
                Err(err) => out
                    .errors
                    .push(format!("read manifest '{}': {}", path.display(), err)),
            }
        } else {
            out.warnings
                .push(format!("proposal manifest not found: {}", path.display()));
            if input.enforce {
                out.errors.push(format!(
                    "proposal manifest required in enforce mode: {}",
                    path.display()
                ));
            }
        }
    }

    if let (Some(plan), Some(manifest)) = (parsed_plan.as_ref(), parsed_manifest.as_ref()) {
        if plan.plan_id != manifest.plan_id {
            out.errors.push(format!(
                "manifest plan_id mismatch: plan={} manifest={}",
                plan.plan_id, manifest.plan_id
            ));
        }
    }

    apply_changed_path_checks(parsed_plan.as_ref(), parsed_manifest.as_ref(), &mut out);
    apply_hard_stop_checks(input.enforce, &mut out);
    classify_failures(&mut out);

    let contract_violation = !out.errors.is_empty() || out.requires_manual_approval;
    if input.enforce && contract_violation {
        out.exit_code = 2;
    }
    out
}

fn validate_plan_artifact(plan: &PlanArtifact, out: &mut PlanCheckOutput) {
    let before = out.errors.len();
    if plan.schema_id != PLAN_ARTIFACT_SCHEMA_ID {
        out.errors.push(format!(
            "plan schema_id mismatch: expected '{}' found '{}'",
            PLAN_ARTIFACT_SCHEMA_ID, plan.schema_id
        ));
    }

    let plan_hash = match canonical_hash_without_field(plan, "plan_id") {
        Ok(v) => v,
        Err(err) => {
            out.errors
                .push(format!("plan canonical hash computation failed: {}", err));
            return;
        }
    };
    let expected_plan_id = format!("plan:{}", plan_hash);
    out.plan_hash = Some(plan_hash);
    if plan.plan_id != expected_plan_id {
        out.errors.push(format!(
            "plan_id mismatch: expected '{}' found '{}'",
            expected_plan_id, plan.plan_id
        ));
    }
    if plan.intent.trim().is_empty() {
        out.errors.push("plan intent must be non-empty".to_string());
    }
    let _assumptions_count = plan.assumptions.len();
    let _constraints_expected_count = plan.constraints_expected.len();
    let _allowed_exceptions_count = plan.allowed_exceptions.len();
    if plan.scope_targets.is_empty() {
        out.errors
            .push("plan scope_targets must include at least one path/glob".to_string());
    }
    if plan.stop_conditions.is_empty() {
        out.warnings
            .push("plan stop_conditions is empty; no explicit hard-stop policy declared".to_string());
    }
    for step in &plan.validation_steps {
        let _required = step.required;
        if step.id.trim().is_empty() || step.command.trim().is_empty() {
            out.errors.push(
                "plan validation_steps entries require non-empty id and command".to_string(),
            );
            break;
        }
    }
    for route in &plan.risk_routes {
        if route.bucket.trim().is_empty()
            || route.unit.trim().is_empty()
            || route.rationale.trim().is_empty()
            || !route.cost_estimate.is_finite()
        {
            out.errors.push(
                "plan risk_routes entries require finite cost and bucket/unit/rationale".to_string(),
            );
            break;
        }
    }
    if plan.generated_by.provider.trim().is_empty()
        || plan.generated_by.model.trim().is_empty()
        || plan.generated_by.surface.trim().is_empty()
        || plan.generated_by.timestamp.trim().is_empty()
    {
        out.errors
            .push("plan generated_by requires provider/model/surface/timestamp".to_string());
    }
    out.plan_valid = out.errors.len() == before;

    if !(0.0..=1.0).contains(&plan.confidence) {
        out.errors.push(format!(
            "plan confidence out of range [0,1]: {}",
            plan.confidence
        ));
    } else {
        out.confidence = Some(plan.confidence);
    }
    out.unknowns = plan.unknowns.clone();
    if plan.generated_by.planner_prompt_hash.is_none() {
        out.warnings.push("planner_prompt_hash missing".to_string());
    }
    if plan.generated_by.implementer_prompt_hash.is_none() {
        out.warnings.push("implementer_prompt_hash missing".to_string());
    }
}

fn validate_manifest(manifest: &ProposalManifest, out: &mut PlanCheckOutput) {
    let before = out.errors.len();
    if manifest.schema_id != PROPOSAL_MANIFEST_SCHEMA_ID {
        out.errors.push(format!(
            "manifest schema_id mismatch: expected '{}' found '{}'",
            PROPOSAL_MANIFEST_SCHEMA_ID, manifest.schema_id
        ));
    }
    let manifest_hash = match canonical_hash_without_field(manifest, "manifest_id") {
        Ok(v) => v,
        Err(err) => {
            out.errors
                .push(format!("manifest canonical hash computation failed: {}", err));
            return;
        }
    };
    let expected_manifest_id = format!("manifest:{}", manifest_hash);
    out.manifest_hash = Some(manifest_hash);
    if manifest.manifest_id != expected_manifest_id {
        out.errors.push(format!(
            "manifest_id mismatch: expected '{}' found '{}'",
            expected_manifest_id, manifest.manifest_id
        ));
    }
    if manifest.base_sha.trim().is_empty() {
        out.errors.push("manifest base_sha must be non-empty".to_string());
    }
    if manifest.head_sha.trim().is_empty() {
        out.errors.push("manifest head_sha must be non-empty".to_string());
    }
    if manifest.commands_run.is_empty() {
        out.errors
            .push("manifest commands_run must include at least one command".to_string());
    }
    let _artifact_count = manifest.artifacts_produced.len();
    for row in &manifest.test_results {
        if row.command.trim().is_empty() || row.status.trim().is_empty() {
            out.errors
                .push("manifest test_results entries require command and status".to_string());
            break;
        }
    }
    let _exceptions_count = manifest.exceptions_requested.len();
    let _status = &manifest.status;
    out.manifest_valid = out.errors.len() == before;
}

fn apply_changed_path_checks(
    plan: Option<&PlanArtifact>,
    manifest: Option<&ProposalManifest>,
    out: &mut PlanCheckOutput,
) {
    let observed: std::collections::BTreeSet<String> =
        out.changed_paths_observed.iter().cloned().collect();
    let claimed: std::collections::BTreeSet<String> =
        out.changed_paths_claimed.iter().cloned().collect();
    let expected = plan
        .map(|p| normalize_paths(p.expected_changed_paths.clone()))
        .unwrap_or_default();
    let expected_set: std::collections::BTreeSet<String> = expected.into_iter().collect();

    out.changed_paths_missing_from_claim = observed.difference(&claimed).cloned().collect();
    out.changed_paths_extra_in_claim = claimed.difference(&observed).cloned().collect();

    if !out.changed_paths_missing_from_claim.is_empty() {
        out.warnings.push(format!(
            "changed path claim mismatch: {} observed path(s) missing from manifest claim",
            out.changed_paths_missing_from_claim.len()
        ));
    }
    if !out.changed_paths_extra_in_claim.is_empty() {
        out.warnings.push(format!(
            "changed path claim mismatch: {} claimed path(s) not observed",
            out.changed_paths_extra_in_claim.len()
        ));
    }

    if !expected_set.is_empty() {
        out.changed_paths_unexpected = observed.difference(&expected_set).cloned().collect();
        out.changed_paths_missing_from_expected =
            expected_set.difference(&observed).cloned().collect();

        if !out.changed_paths_unexpected.is_empty() {
            out.warnings.push(format!(
                "expected_changed_paths mismatch: {} unexpected observed path(s)",
                out.changed_paths_unexpected.len()
            ));
        }
    }

    if manifest.is_none() && !out.changed_paths_observed.is_empty() {
        out.warnings
            .push("manifest missing while observed changed paths are present".to_string());
    }
}

fn apply_hard_stop_checks(enforce: bool, out: &mut PlanCheckOutput) {
    let observed_paths = out.changed_paths_observed.clone();
    let claimed_paths = out.changed_paths_claimed.clone();

    if enforce && observed_paths.is_empty() {
        add_stop_reason(out, "changed_paths_unavailable");
        if !out
            .warnings
            .iter()
            .any(|w| w == "changed paths unavailable in enforce mode")
        {
            out.warnings
                .push("changed paths unavailable in enforce mode".to_string());
        }
    }

    for path in &observed_paths {
        apply_path_stop_policies(path, out);
    }

    if enforce {
        let observed_set: std::collections::BTreeSet<String> =
            observed_paths.iter().cloned().collect();
        for path in &claimed_paths {
            if observed_set.contains(path) {
                continue;
            }
            if is_sensitive_control_path(path) || is_secret_like_path(path) {
                add_stop_reason(out, "claimed_sensitive_path_unverified");
                // Preserve category-specific stop reasons for governance routing.
                apply_path_stop_policies(path, out);
            }
        }
    }

    out.requires_manual_approval = !out.stop_reasons.is_empty();
}

fn apply_path_stop_policies(path: &str, out: &mut PlanCheckOutput) {
    if path.starts_with(".github/workflows/") {
        add_stop_reason(out, "touches_github_workflows");
    }
    if path == "action.yml" {
        add_stop_reason(out, "touches_action_definition");
    }
    if path.starts_with(".admit/schemas/") {
        add_stop_reason(out, "meta_schema_change");
    } else if path.starts_with(".admit/prompts/") {
        add_stop_reason(out, "meta_prompt_change");
    } else if path.starts_with(".admit/") {
        add_stop_reason(out, "meta_registry_change");
    }
    if is_secret_like_path(path) {
        add_stop_reason(out, "secrets_detected");
    }
}

fn is_sensitive_control_path(path: &str) -> bool {
    path.starts_with(".github/workflows/")
        || path == "action.yml"
        || path.starts_with(".admit/")
}

fn classify_failures(out: &mut PlanCheckOutput) {
    if out.stop_reasons.iter().any(|r| r == "semantic_ci_failure") {
        out.failure_classification = FailureClassification::Semantic;
        return;
    }
    if out.errors.is_empty() && out.stop_reasons.is_empty() {
        out.failure_classification = FailureClassification::None;
        return;
    }
    if out
        .errors
        .iter()
        .any(|e| e.contains("schema_id") || e.contains("decode") || e.contains("mismatch"))
    {
        out.failure_classification = FailureClassification::Mechanical;
        return;
    }
    if !out.stop_reasons.is_empty() {
        out.failure_classification = FailureClassification::Unknown;
        return;
    }
    out.failure_classification = FailureClassification::Unknown;
}

fn add_stop_reason(out: &mut PlanCheckOutput, reason: &str) {
    if !out.stop_reasons.iter().any(|r| r == reason) {
        out.stop_reasons.push(reason.to_string());
    }
}

fn is_secret_like_path(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    low.ends_with(".pem")
        || low.ends_with(".key")
        || low.ends_with(".env")
        || low.contains("/.env.")
        || low.contains("/secrets/")
}

fn canonical_hash_without_field<T: Serialize>(value: &T, remove_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|err| err.to_string())?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| "expected object value for canonical hash".to_string())?;
    map.remove(remove_field);
    canonicalize_identity_numbers(&mut value);
    canonical_sha256(&value)
}

fn canonical_sha256(value: &serde_json::Value) -> Result<String, String> {
    let bytes = admit_core::encode_canonical_value(value).map_err(|err| err.0)?;
    Ok(hex::encode(sha2::Sha256::digest(&bytes)))
}

fn canonicalize_identity_numbers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize_identity_numbers(item);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                canonicalize_identity_numbers(item);
            }
        }
        serde_json::Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                return;
            }
            // Canonical CBOR identity in this repo forbids floats.
            // Preserve decimal intent deterministically as a string for identity hashing.
            let repr = number.to_string();
            *value = serde_json::Value::String(repr);
        }
        _ => {}
    }
}

fn parse_changed_paths_text(text: &str) -> Result<Vec<String>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|err| format!("decode changed paths json: {}", err))?;
        let rows = if let Some(arr) = value.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        } else if let Some(arr) = value.get("paths").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        return Ok(normalize_paths(rows));
    }
    let rows = trimmed
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    Ok(normalize_paths(rows))
}

fn normalize_paths(paths: Vec<String>) -> Vec<String> {
    let mut rows = paths
        .into_iter()
        .map(|p| {
            p.replace('\\', "/")
                .trim_start_matches("./")
                .trim()
                .to_string()
        })
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();
    rows.sort();
    rows.dedup();
    rows
}

// ---------------------------------------------------------------------------
// Public: create plan
// ---------------------------------------------------------------------------

pub fn create_plan(input: PlanNewInput) -> Result<PlanCreatedEvent, DeclareCostError> {
    let answers_raw = fs::read(&input.answers_path).map_err(|_| {
        DeclareCostError::PlanAnswersFileNotFound(input.answers_path.display().to_string())
    })?;
    let answers_file_hash = sha256_hex(&answers_raw);
    let registry_resolved = resolve_meta_registry(input.meta_registry_path.as_deref())?;
    let registry_ref = registry_resolved.as_ref().map(|r| &r.registry);
    let registry_hash = registry_resolved.as_ref().map(|r| r.hash.clone());

    #[derive(Deserialize)]
    struct RawAnswer {
        prompt_id: String,
        answer: String,
    }

    let raw_answers: Vec<RawAnswer> = serde_json::from_slice(&answers_raw)
        .map_err(|err| DeclareCostError::PlanAnswersDecode(err.to_string()))?;

    let prompts = diagnostic_prompts();
    let prompt_ids: std::collections::HashSet<&str> =
        prompts.iter().map(|p| p.prompt_id.as_str()).collect();

    let mut seen_answers = std::collections::HashSet::new();
    for ra in &raw_answers {
        if !seen_answers.insert(ra.prompt_id.clone()) {
            return Err(DeclareCostError::PlanAnswersDuplicatePrompt(
                ra.prompt_id.clone(),
            ));
        }
    }

    // Check for extra answers (not in template)
    for ra in &raw_answers {
        if !prompt_ids.contains(ra.prompt_id.as_str()) {
            return Err(DeclareCostError::PlanAnswersExtraPrompt(
                ra.prompt_id.clone(),
            ));
        }
    }

    // Build answer map from input
    let answer_map: std::collections::BTreeMap<&str, &str> = raw_answers
        .iter()
        .map(|ra| (ra.prompt_id.as_str(), ra.answer.as_str()))
        .collect();

    // Check for missing answers and build ordered list
    let mut answers = Vec::with_capacity(prompts.len());
    for prompt in &prompts {
        let answer_text = answer_map
            .get(prompt.prompt_id.as_str())
            .ok_or_else(|| DeclareCostError::PlanAnswersMissingPrompt(prompt.prompt_id.clone()))?;
        answers.push(admit_core::PlanAnswer {
            prompt_id: prompt.prompt_id.clone(),
            answer: answer_text.to_string(),
        });
    }

    let derived = derive_risks(&answers);

    // Compute template hash from the canonical prompts list
    let prompts_value =
        serde_json::to_value(&prompts).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let template_bytes = admit_core::encode_canonical_value(&prompts_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let template_hash = sha256_hex(&template_bytes);
    let plan_witness_schema_id = select_plan_witness_schema_id(registry_ref);

    let witness = admit_core::PlanWitness {
        schema_id: plan_witness_schema_id.to_string(),
        created_at: input.timestamp.clone(),
        engine_version: Some(input.tool_version.clone()),
        input_id: Some(answers_file_hash.clone()),
        config_hash: Some(template_hash.clone()),
        producer: admit_core::PlanProducer {
            surface: input.surface.clone(),
            tool_version: input.tool_version.clone(),
        },
        inputs: admit_core::PlanInputs {
            template_id: PLAN_TEMPLATE_ID.to_string(),
            scope: input.scope.clone(),
            target: input.target.clone(),
        },
        template: admit_core::PlanTemplate {
            template_id: PLAN_TEMPLATE_ID.to_string(),
            template_hash: template_hash.clone(),
            prompts,
        },
        answers,
        derived,
        repro: admit_core::PlanRepro {
            snapshot_hash: input.snapshot_hash.clone(),
            template_hash: template_hash.clone(),
            answers_file_hash: answers_file_hash.clone(),
        },
    };

    let witness_value =
        serde_json::to_value(&witness).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&witness_value)
        .map_err(|err| DeclareCostError::Json(err.0))?;

    let json_projection =
        serde_json::to_vec(&witness).map_err(|err| DeclareCostError::Json(err.to_string()))?;

    let artifacts_root = input.artifacts_root.unwrap_or_else(default_artifacts_dir);
    let witness_ref = store_artifact(
        &artifacts_root,
        "plan_witness",
        plan_witness_schema_id,
        &cbor_bytes,
        "cbor",
        Some(json_projection),
        registry_ref,
    )?;

    let producer_ref = PlanProducerRef {
        surface: input.surface,
        tool_version: input.tool_version,
    };
    let repro_ref = PlanReproRef {
        snapshot_hash: input.snapshot_hash,
        template_hash,
        answers_file_hash,
    };

    let payload = PlanCreatedPayload {
        event_type: "plan.created".to_string(),
        timestamp: input.timestamp.clone(),
        plan_witness: witness_ref.clone(),
        producer: producer_ref.clone(),
        template_id: PLAN_TEMPLATE_ID.to_string(),
        repro: repro_ref.clone(),
        registry_hash: registry_hash.clone(),
    };
    let event_id = payload_hash(&payload)?;

    Ok(PlanCreatedEvent {
        event_type: payload.event_type,
        event_id,
        timestamp: input.timestamp,
        plan_witness: witness_ref,
        producer: producer_ref,
        template_id: PLAN_TEMPLATE_ID.to_string(),
        repro: repro_ref,
        registry_hash,
    })
}

// ---------------------------------------------------------------------------
// Public: append plan created event
// ---------------------------------------------------------------------------

pub fn append_plan_created_event(
    ledger_path: &Path,
    event: &PlanCreatedEvent,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal: load plan witness from artifact store
// ---------------------------------------------------------------------------

fn load_plan_witness(
    artifacts_root: &Path,
    plan_id: &str,
) -> Result<admit_core::PlanWitness, DeclareCostError> {
    // Try CBOR first
    let cbor_path = artifact_disk_path(artifacts_root, "plan_witness", plan_id, "cbor");
    if cbor_path.exists() {
        let bytes = fs::read(&cbor_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        let value = decode_cbor_to_value(&bytes)?;
        return serde_json::from_value::<admit_core::PlanWitness>(value)
            .map_err(|err| DeclareCostError::Json(err.to_string()));
    }
    // Fall back to JSON projection
    let json_path = artifact_disk_path(artifacts_root, "plan_witness", plan_id, "json");
    if json_path.exists() {
        let bytes = fs::read(&json_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        return serde_json::from_slice::<admit_core::PlanWitness>(&bytes)
            .map_err(|err| DeclareCostError::Json(err.to_string()));
    }
    Err(DeclareCostError::PlanWitnessMissing(plan_id.to_string()))
}

// ---------------------------------------------------------------------------
// Public: render plan as key=value text
// ---------------------------------------------------------------------------

pub fn render_plan_text(artifacts_root: &Path, plan_id: &str) -> Result<String, DeclareCostError> {
    let witness = load_plan_witness(artifacts_root, plan_id)?;
    let mut out = String::new();

    out.push_str(&format!("plan_id={}\n", plan_id));
    out.push_str(&format!("schema_id={}\n", witness.schema_id));
    out.push_str(&format!("created_at={}\n", witness.created_at));
    out.push_str(&format!(
        "producer={}/{}\n",
        witness.producer.surface, witness.producer.tool_version
    ));
    out.push_str(&format!("scope={}\n", witness.inputs.scope));
    out.push_str(&format!("target={}\n", witness.inputs.target));
    out.push_str(&format!(
        "erasure_grade={:?}\n",
        witness.derived.erasure_grade
    ));
    out.push_str(&format!("risk_label={}\n", witness.derived.risk_label));
    out.push_str(&format!(
        "invariants_touched={}\n",
        witness.derived.invariants_touched.join(",")
    ));

    for prompt in &witness.template.prompts {
        let answer_text = witness
            .answers
            .iter()
            .find(|a| a.prompt_id == prompt.prompt_id)
            .map(|a| a.answer.as_str())
            .unwrap_or("");
        out.push_str(&format!(
            "\n--- Section {}: {} ---\n{}\n",
            prompt.section, prompt.title, answer_text
        ));
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Public: export plan as Markdown
// ---------------------------------------------------------------------------

pub fn export_plan_markdown(
    artifacts_root: &Path,
    plan_id: &str,
) -> Result<String, DeclareCostError> {
    let witness = load_plan_witness(artifacts_root, plan_id)?;
    let mut out = String::new();

    // Repro header as HTML comment (survives Markdown rendering)
    out.push_str("<!-- plan-projection\n");
    out.push_str(&format!("plan_id: {}\n", plan_id));
    out.push_str(&format!("witness_created_at: {}\n", witness.created_at));
    out.push_str(&format!("witness_hash: {}\n", plan_id));
    out.push_str("identity: plan_id == sha256(canonical_cbor(plan_witness))\n");
    out.push_str("repro: plan_witness includes created_at; to reproduce plan_id, pass the same created_at and identical answers bytes.\n");
    out.push_str(&format!("template_id: {}\n", witness.template.template_id));
    out.push_str("source: plan_witness artifact (canonical CBOR)\n");
    out.push_str("NOTE: This is a projection. The CBOR artifact is the source of truth.\n");
    out.push_str("-->\n\n");

    out.push_str("## Irreversibility-First Plan Design Prompt\n\n");

    for prompt in &witness.template.prompts {
        let answer_text = witness
            .answers
            .iter()
            .find(|a| a.prompt_id == prompt.prompt_id)
            .map(|a| a.answer.as_str())
            .unwrap_or("");

        out.push_str(&format!(
            "### {}. {}\n\n{}\n\n---\n\n",
            prompt.section, prompt.title, answer_text
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod plan_contract_tests {
    use super::*;

    fn sample_plan() -> PlanArtifact {
        PlanArtifact {
            schema_id: PLAN_ARTIFACT_SCHEMA_ID.to_string(),
            plan_id: "plan:placeholder".to_string(),
            intent: "doc update".to_string(),
            scope_targets: vec!["docs/**".to_string()],
            expected_changed_paths: vec!["docs/spec/agent-plan-contract.md".to_string()],
            assumptions: vec!["docs-only".to_string()],
            constraints_expected: vec!["R-CI-130".to_string()],
            allowed_exceptions: vec![],
            validation_steps: vec![PlanValidationStep {
                id: "lint".to_string(),
                command: "cargo test --workspace".to_string(),
                required: true,
            }],
            stop_conditions: vec!["touches_github_workflows".to_string()],
            risk_routes: vec![PlanRiskRoute {
                bucket: "docs".to_string(),
                cost_estimate: 1.0,
                unit: "change".to_string(),
                rationale: "documentation only".to_string(),
            }],
            unknowns: vec![],
            confidence: 0.9,
            generated_by: PlanGeneratedBy {
                provider: "openai".to_string(),
                model: "gpt-5".to_string(),
                surface: "cli".to_string(),
                timestamp: "2026-02-14T00:00:00Z".to_string(),
                planner_prompt_hash: Some("a".repeat(64)),
                implementer_prompt_hash: Some("b".repeat(64)),
            },
        }
    }

    fn sample_manifest(plan_id: &str) -> ProposalManifest {
        ProposalManifest {
            schema_id: PROPOSAL_MANIFEST_SCHEMA_ID.to_string(),
            manifest_id: "manifest:placeholder".to_string(),
            plan_id: plan_id.to_string(),
            base_sha: "abc123".to_string(),
            head_sha: "def456".to_string(),
            changed_paths: vec!["docs/spec/agent-plan-contract.md".to_string()],
            commands_run: vec!["cargo test --workspace".to_string()],
            artifacts_produced: vec!["out/ci-witness.json".to_string()],
            test_results: vec![ManifestTestResult {
                command: "cargo test --workspace".to_string(),
                status: "ok".to_string(),
            }],
            exceptions_requested: vec![],
            status: ManifestStatus::ReadyForReview,
        }
    }

    #[test]
    fn plan_id_matches_canonical_hash() {
        let mut plan = sample_plan();
        let hash = canonical_hash_without_field(&plan, "plan_id").expect("hash");
        plan.plan_id = format!("plan:{}", hash);
        let temp = tempfile::tempdir().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        fs::write(&plan_path, serde_json::to_vec(&plan).expect("encode")).expect("write");
        let out = check_plan_contract(PlanCheckInput {
            plan_path: Some(plan_path),
            manifest_path: None,
            changed_paths_observed: vec![],
            enforce: false,
        });
        assert!(out.plan_valid);
        assert!(out
            .errors
            .iter()
            .all(|e| !e.contains("plan_id mismatch")));
    }

    #[test]
    fn hard_stop_detects_meta_schema_change() {
        let mut plan = sample_plan();
        let hash = canonical_hash_without_field(&plan, "plan_id").expect("hash");
        plan.plan_id = format!("plan:{}", hash);
        let temp = tempfile::tempdir().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        let bytes = serde_json::to_vec(&plan).expect("encode");
        fs::write(&plan_path, bytes).expect("write");

        let out = check_plan_contract(PlanCheckInput {
            plan_path: Some(plan_path),
            manifest_path: None,
            changed_paths_observed: vec![".admit/schemas/plan-artifact.v0.schema.json".to_string()],
            enforce: false,
        });
        assert!(out.requires_manual_approval);
        assert!(out.stop_reasons.contains(&"meta_schema_change".to_string()));
    }

    #[test]
    fn manifest_plan_mismatch_is_reported() {
        let mut plan = sample_plan();
        let plan_hash = canonical_hash_without_field(&plan, "plan_id").expect("hash");
        plan.plan_id = format!("plan:{}", plan_hash);

        let mut manifest = sample_manifest("plan:deadbeef");
        let manifest_hash = canonical_hash_without_field(&manifest, "manifest_id").expect("hash");
        manifest.manifest_id = format!("manifest:{}", manifest_hash);

        let temp = tempfile::tempdir().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        let manifest_path = temp.path().join("manifest.json");
        fs::write(&plan_path, serde_json::to_vec(&plan).expect("encode")).expect("write");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("encode"),
        )
        .expect("write");

        let out = check_plan_contract(PlanCheckInput {
            plan_path: Some(plan_path),
            manifest_path: Some(manifest_path),
            changed_paths_observed: vec!["docs/spec/agent-plan-contract.md".to_string()],
            enforce: true,
        });
        assert!(out
            .errors
            .iter()
            .any(|e| e.contains("manifest plan_id mismatch")));
        assert_eq!(out.exit_code, 2);
    }

    #[test]
    fn autogen_outputs_pass_enforce_plan_contract() {
        let temp = tempfile::tempdir().expect("tempdir");
        let plan_path = temp.path().join("out/plan/plan-artifact.json");
        let manifest_path = temp.path().join("out/plan/proposal-manifest.json");
        let expected_path = "docs/spec/agent-plan-contract.md".to_string();

        let generated = autogen_plan_artifacts(PlanAutogenInput {
            out_plan_path: plan_path.clone(),
            out_manifest_path: manifest_path.clone(),
            intent: "Auto-generated CI scaffold".to_string(),
            scope_targets: vec![],
            expected_changed_paths: vec![expected_path.clone()],
            commands_run: vec!["cargo test -p admit_cli --test ci_command".to_string()],
            artifacts_produced: vec![],
            base_sha: "1111111111111111111111111111111111111111".to_string(),
            head_sha: "2222222222222222222222222222222222222222".to_string(),
            surface: "ci".to_string(),
            timestamp: "2026-02-14T00:00:00Z".to_string(),
        })
        .expect("autogen");

        let report = check_plan_contract(PlanCheckInput {
            plan_path: Some(plan_path),
            manifest_path: Some(manifest_path),
            changed_paths_observed: vec![expected_path],
            enforce: true,
        });
        assert!(report.plan_valid);
        assert!(report.manifest_valid);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.plan_id.as_deref(), Some(generated.plan_id.as_str()));
        assert_eq!(
            report.manifest_id.as_deref(),
            Some(generated.manifest_id.as_str())
        );
    }

    #[test]
    fn enforce_mode_stops_when_changed_paths_unavailable() {
        let mut plan = sample_plan();
        let plan_hash = canonical_hash_without_field(&plan, "plan_id").expect("hash");
        plan.plan_id = format!("plan:{}", plan_hash);

        let mut manifest = sample_manifest(&plan.plan_id);
        let manifest_hash = canonical_hash_without_field(&manifest, "manifest_id").expect("hash");
        manifest.manifest_id = format!("manifest:{}", manifest_hash);

        let temp = tempfile::tempdir().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        let manifest_path = temp.path().join("manifest.json");
        fs::write(&plan_path, serde_json::to_vec(&plan).expect("encode")).expect("write");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("encode"),
        )
        .expect("write");

        let out = check_plan_contract(PlanCheckInput {
            plan_path: Some(plan_path),
            manifest_path: Some(manifest_path),
            changed_paths_observed: vec![],
            enforce: true,
        });
        assert!(out.requires_manual_approval);
        assert!(out
            .stop_reasons
            .contains(&"changed_paths_unavailable".to_string()));
        assert_eq!(out.exit_code, 2);
    }

    #[test]
    fn enforce_mode_stops_on_unverified_sensitive_claim() {
        let mut plan = sample_plan();
        plan.expected_changed_paths = vec![".github/workflows/ci.yml".to_string()];
        let plan_hash = canonical_hash_without_field(&plan, "plan_id").expect("hash");
        plan.plan_id = format!("plan:{}", plan_hash);

        let mut manifest = sample_manifest(&plan.plan_id);
        manifest.changed_paths = vec![".github/workflows/ci.yml".to_string()];
        let manifest_hash = canonical_hash_without_field(&manifest, "manifest_id").expect("hash");
        manifest.manifest_id = format!("manifest:{}", manifest_hash);

        let temp = tempfile::tempdir().expect("tempdir");
        let plan_path = temp.path().join("plan.json");
        let manifest_path = temp.path().join("manifest.json");
        fs::write(&plan_path, serde_json::to_vec(&plan).expect("encode")).expect("write");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("encode"),
        )
        .expect("write");

        let out = check_plan_contract(PlanCheckInput {
            plan_path: Some(plan_path),
            manifest_path: Some(manifest_path),
            changed_paths_observed: vec!["src/lib.rs".to_string()],
            enforce: true,
        });
        assert!(out.requires_manual_approval);
        assert!(out
            .stop_reasons
            .contains(&"claimed_sensitive_path_unverified".to_string()));
        assert!(out
            .stop_reasons
            .contains(&"touches_github_workflows".to_string()));
        assert_eq!(out.exit_code, 2);
    }
}
