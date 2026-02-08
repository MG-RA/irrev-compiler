use std::fs;
use std::path::Path;

use serde::Deserialize;

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
