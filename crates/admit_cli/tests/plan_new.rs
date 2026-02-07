use std::fs;
use std::path::PathBuf;

use admit_cli::{
    append_plan_created_event, create_plan, export_plan_markdown, render_plan_text, verify_ledger,
    PlanNewInput,
};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-plan-{}-{}", label, nanos))
}

fn write_answers(dir: &PathBuf, answers: serde_json::Value) -> PathBuf {
    fs::create_dir_all(dir).expect("create dir");
    let path = dir.join("answers.json");
    fs::write(
        &path,
        serde_json::to_string(&answers).expect("serialize answers"),
    )
    .expect("write answers");
    path
}

fn write_registry(path: &PathBuf, value: serde_json::Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create dir");
    }
    fs::write(
        path,
        serde_json::to_string(&value).expect("serialize registry"),
    )
    .expect("write registry");
}

fn full_answers() -> serde_json::Value {
    serde_json::json!([
        { "prompt_id": "action_definition",      "answer": "Add a new config file to out/" },
        { "prompt_id": "boundary_declaration",   "answer": "Only out/config.json changes." },
        { "prompt_id": "persistence_analysis",   "answer": "The file persists on disk by default." },
        { "prompt_id": "erasure_cost",           "answer": "Grade 2: lossy to reverse because the old config is not kept." },
        { "prompt_id": "displacement_ownership", "answer": "The actor bears the erasure cost." },
        { "prompt_id": "preconditions",          "answer": "The out/ directory must exist." },
        { "prompt_id": "execution_constraints",  "answer": "Must not overwrite existing files." },
        { "prompt_id": "postconditions",         "answer": "out/config.json exists with expected content." },
        { "prompt_id": "accountability",         "answer": "CI system, build 42." },
        { "prompt_id": "acceptance_criteria",    "answer": "File present and hash matches." },
        { "prompt_id": "refusal_conditions",     "answer": "Refuse if out/ does not exist." },
        { "prompt_id": "final_check",            "answer": "yes, yes, yes, yes" }
    ])
}

fn make_input(dir: &PathBuf, answers: serde_json::Value) -> PlanNewInput {
    let answers_path = write_answers(dir, answers);
    PlanNewInput {
        answers_path,
        scope: "out/".to_string(),
        target: "config.json".to_string(),
        surface: "cli".to_string(),
        tool_version: "test-build-1".to_string(),
        snapshot_hash: None,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        artifacts_root: Some(dir.join("artifacts")),
        meta_registry_path: None,
    }
}

#[test]
fn create_plan_produces_deterministic_event_id() {
    let dir = temp_dir("deterministic");
    let input_a = make_input(&dir, full_answers());
    let input_b = make_input(&dir, full_answers());

    let event_a = create_plan(input_a).expect("first create");
    let event_b = create_plan(input_b).expect("second create");

    assert_eq!(event_a.event_id, event_b.event_id);
    assert_eq!(event_a.plan_witness.sha256, event_b.plan_witness.sha256);
    assert_eq!(event_a.plan_witness.kind, "plan_witness");
    assert_eq!(event_a.plan_witness.schema_id, "plan-witness/2");
    assert_eq!(event_a.template_id, "plan:diagnostic@1");
}

#[test]
fn create_plan_uses_legacy_schema_with_v1_only_registry() {
    let dir = temp_dir("legacy-schema");
    let registry_path = dir.join("meta-registry.json");
    write_registry(
        &registry_path,
        serde_json::json!({
            "schema_id": "meta-registry/0",
            "schema_version": 0,
            "registry_version": 0,
            "stdlib": [{ "module_id": "module:irrev_std@1" }],
            "schemas": [
                { "id": "meta-registry/0", "schema_version": 0, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
                { "id": "plan-witness/1", "schema_version": 1, "kind": "plan_witness", "canonical_encoding": "canonical-cbor" }
            ],
            "scopes": [{ "id": "scope:patch.plan", "version": 0 }]
        }),
    );

    let mut input = make_input(&dir, full_answers());
    input.meta_registry_path = Some(registry_path);

    let event = create_plan(input).expect("create plan");
    assert_eq!(event.plan_witness.schema_id, "plan-witness/1");
}

#[test]
fn create_plan_stores_artifact_files() {
    let dir = temp_dir("artifact-files");
    let input = make_input(&dir, full_answers());
    let artifacts_dir = dir.join("artifacts");

    let event = create_plan(input).expect("create plan");
    let plan_id = &event.plan_witness.sha256;

    let cbor_path = artifacts_dir
        .join("plan_witness")
        .join(format!("{}.cbor", plan_id));
    let json_path = artifacts_dir
        .join("plan_witness")
        .join(format!("{}.json", plan_id));

    assert!(cbor_path.exists(), "CBOR artifact must exist");
    assert!(json_path.exists(), "JSON projection must exist");
    assert!(cbor_path.metadata().unwrap().len() > 0);
    assert!(json_path.metadata().unwrap().len() > 0);
}

#[test]
fn create_plan_and_verify_ledger_passes() {
    let dir = temp_dir("ledger-verify");
    let input = make_input(&dir, full_answers());
    let ledger_path = dir.join("ledger.jsonl");
    let artifacts_dir = dir.join("artifacts");

    let event = create_plan(input).expect("create plan");
    append_plan_created_event(&ledger_path, &event).expect("append event");

    let report = verify_ledger(&ledger_path, Some(artifacts_dir.as_path())).expect("verify ledger");
    assert_eq!(
        report.issues.len(),
        0,
        "ledger should have no issues, got: {:?}",
        report.issues
    );
}

#[test]
fn duplicate_plan_event_is_rejected() {
    let dir = temp_dir("duplicate");
    let input = make_input(&dir, full_answers());
    let ledger_path = dir.join("ledger.jsonl");

    let event = create_plan(input).expect("create plan");
    append_plan_created_event(&ledger_path, &event).expect("first append");

    let err = append_plan_created_event(&ledger_path, &event);
    assert!(err.is_err(), "duplicate event_id must be rejected");
}

#[test]
fn missing_prompt_answer_fails() {
    let dir = temp_dir("missing-prompt");
    // Only one answer provided — the rest are missing
    let answers = serde_json::json!([
        { "prompt_id": "action_definition", "answer": "test" }
    ]);
    let input = make_input(&dir, answers);

    let err = create_plan(input);
    assert!(err.is_err(), "should fail on missing prompts");
    assert!(
        format!("{}", err.unwrap_err()).contains("missing answer for prompt"),
        "error message should indicate missing prompt"
    );
}

#[test]
fn extra_prompt_answer_fails() {
    let dir = temp_dir("extra-prompt");
    let mut answers = full_answers().as_array().unwrap().clone();
    answers.push(serde_json::json!({
        "prompt_id": "nonexistent_section",
        "answer": "should not be here"
    }));
    let input = make_input(&dir, serde_json::Value::Array(answers));

    let err = create_plan(input);
    assert!(err.is_err(), "should fail on extra prompt");
    assert!(
        format!("{}", err.unwrap_err()).contains("extra answer for unknown prompt"),
        "error message should indicate extra prompt"
    );
}

#[test]
fn duplicate_prompt_answer_fails() {
    let dir = temp_dir("duplicate-prompt");
    let mut answers = full_answers().as_array().unwrap().clone();
    answers.push(serde_json::json!({
        "prompt_id": "action_definition",
        "answer": "duplicate entry"
    }));
    let input = make_input(&dir, serde_json::Value::Array(answers));

    let err = create_plan(input);
    assert!(err.is_err(), "should fail on duplicate prompt");
    assert!(
        format!("{}", err.unwrap_err()).contains("duplicate answer for prompt"),
        "error message should indicate duplicate prompt"
    );
}

#[test]
fn render_plan_text_produces_output() {
    let dir = temp_dir("render");
    let artifacts_dir = dir.join("artifacts");
    let input = make_input(&dir, full_answers());

    let event = create_plan(input).expect("create plan");
    let plan_id = &event.plan_witness.sha256;

    let text = render_plan_text(&artifacts_dir, plan_id).expect("render plan");
    assert!(text.contains(&format!("plan_id={}", plan_id)));
    assert!(text.contains("schema_id=plan-witness/2"));
    assert!(text.contains("--- Section 1: Action Definition ---"));
    assert!(text.contains("Add a new config file to out/"));
    assert!(text.contains("--- Section 4: Erasure Cost ---"));
    assert!(text.contains("Grade 2"));
}

#[test]
fn export_plan_markdown_produces_valid_projection() {
    let dir = temp_dir("export");
    let artifacts_dir = dir.join("artifacts");
    let input = make_input(&dir, full_answers());

    let event = create_plan(input).expect("create plan");
    let plan_id = &event.plan_witness.sha256;

    let md = export_plan_markdown(&artifacts_dir, plan_id).expect("export plan");
    // Must have repro header
    assert!(md.contains("<!-- plan-projection"));
    assert!(md.contains(&format!("plan_id: {}", plan_id)));
    assert!(md.contains("source: plan_witness artifact (canonical CBOR)"));
    assert!(md.contains("NOTE: This is a projection"));
    // Must have section headings
    assert!(md.contains("### 1. Action Definition"));
    assert!(md.contains("### 4. Erasure Cost"));
    assert!(md.contains("### 12. Final Check"));
    // Must have answer content
    assert!(md.contains("Add a new config file to out/"));
}

#[test]
fn template_hash_is_stable() {
    let dir = temp_dir("template-hash");
    let input = make_input(&dir, full_answers());

    let event = create_plan(input).expect("create plan");
    let expected = "61ad0c15762e73e0f2118a14c5aa8c8e709f141e715f859e9ead7bd0feddd974";
    assert_eq!(
        event.repro.template_hash, expected,
        "template hash changed; prompts may have been modified"
    );
}

#[test]
fn risk_derivation_grade3_is_destructive() {
    let dir = temp_dir("grade3");
    let mut answers = full_answers().as_array().unwrap().clone();
    // Replace erasure_cost answer with Grade 3
    for item in &mut answers {
        if item["prompt_id"] == "erasure_cost" {
            *item = serde_json::json!({
                "prompt_id": "erasure_cost",
                "answer": "Grade 3: irreversible. Data is permanently lost."
            });
        }
    }
    let input = make_input(&dir, serde_json::Value::Array(answers));
    let artifacts_dir = dir.join("artifacts");

    let event = create_plan(input).expect("create plan");
    let text = render_plan_text(&artifacts_dir, &event.plan_witness.sha256).expect("render plan");
    assert!(
        text.contains("risk_label=mutation_destructive"),
        "Grade 3 should produce mutation_destructive"
    );
}

#[test]
fn risk_derivation_detects_invariant_keywords() {
    let dir = temp_dir("invariants");
    let mut answers = full_answers().as_array().unwrap().clone();
    // Inject invariant keywords into answers
    for item in &mut answers {
        if item["prompt_id"] == "action_definition" {
            *item = serde_json::json!({
                "prompt_id": "action_definition",
                "answer": "This touches governance and attribution boundaries."
            });
        }
    }
    let input = make_input(&dir, serde_json::Value::Array(answers));
    let artifacts_dir = dir.join("artifacts");

    let event = create_plan(input).expect("create plan");
    let text = render_plan_text(&artifacts_dir, &event.plan_witness.sha256).expect("render plan");
    assert!(
        text.contains("attribution"),
        "should detect attribution keyword"
    );
    assert!(
        text.contains("governance"),
        "should detect governance keyword"
    );
}

#[test]
fn nonexistent_plan_id_returns_error() {
    let dir = temp_dir("missing-plan");
    fs::create_dir_all(&dir).expect("create dir");

    let err = render_plan_text(
        &dir,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(err.is_err(), "nonexistent plan_id should error");
    assert!(
        format!("{}", err.unwrap_err()).contains("plan witness not found"),
        "error should indicate plan not found"
    );
}
