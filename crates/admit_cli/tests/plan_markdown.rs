use std::fs;
use std::path::PathBuf;

use admit_cli::{
    create_plan, export_plan_markdown, parse_plan_answers_markdown, render_plan_prompt_template,
    PlanNewInput,
};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-plan-md-{}-{}", label, nanos))
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
fn prompt_template_includes_answer_markers() {
    let template = render_plan_prompt_template(true);
    assert!(template.contains("### 1. Action Definition"));
    assert!(template.contains("Prompt ID: `action_definition`"));
    assert!(template.contains("Guidance:"));
    assert!(template.contains("Answer:"));
}

#[test]
fn parse_answers_from_exported_markdown_roundtrip() {
    let dir = temp_dir("roundtrip");
    let artifacts_dir = dir.join("artifacts");
    let event = create_plan(make_input(&dir, full_answers())).expect("create plan");
    let plan_id = event.plan_witness.sha256;
    let markdown = export_plan_markdown(&artifacts_dir, &plan_id).expect("export markdown");

    let answers = parse_plan_answers_markdown(&markdown).expect("parse answers");
    assert_eq!(answers.len(), 12);
    assert_eq!(answers[0].prompt_id, "action_definition");
    assert_eq!(answers[0].answer, "Add a new config file to out/");
    assert_eq!(answers[11].prompt_id, "final_check");
}

#[test]
fn parse_answers_errors_when_template_is_unfilled() {
    let template = render_plan_prompt_template(true);
    let err = parse_plan_answers_markdown(&template).expect_err("should fail");
    assert!(format!("{}", err).contains("plan markdown parse error"));
}
