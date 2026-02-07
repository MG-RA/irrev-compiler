use std::path::{Path, PathBuf};

use admit_cli::calc_commands::{calc_execute, calc_plan};
use admit_core::encode_canonical_value;
use admit_core::exact_types::ExactValue;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn write_json(path: &Path, value: &serde_json::Value) {
    let text = serde_json::to_string_pretty(value).expect("serialize json");
    std::fs::write(path, text).expect("write json");
}

fn hash_canonical(value: &serde_json::Value) -> String {
    let cbor = encode_canonical_value(value).expect("canonical encode");
    hex::encode(Sha256::digest(&cbor))
}

fn temp_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[test]
fn calc_execute_deterministic_core_hash() {
    let dir = TempDir::new().expect("tempdir");
    let expr_path = temp_path(&dir, "expr.json");
    let plan_path = temp_path(&dir, "plan.json");
    let witness_path_1 = temp_path(&dir, "witness-1.json");
    let witness_path_2 = temp_path(&dir, "witness-2.json");

    let expr = json!({
        "type": "add",
        "left": { "type": "input_ref", "name": "a" },
        "right": { "type": "input_ref", "name": "b" }
    });
    write_json(&expr_path, &expr);

    let plan = calc_plan(
        &expr_path,
        vec!["a:int:hours".to_string(), "b:int:hours".to_string()],
        Some("hours".to_string()),
        &plan_path,
    )
    .expect("create plan");

    let witness_1 = calc_execute(
        &plan_path,
        vec!["a=5".to_string(), "b=7".to_string()],
        false,
        &witness_path_1,
        None,
    )
    .expect("execute plan 1");

    let witness_2 = calc_execute(
        &plan_path,
        vec!["a=5".to_string(), "b=7".to_string()],
        false,
        &witness_path_2,
        None,
    )
    .expect("execute plan 2");

    let core_hash_1 = hash_canonical(&serde_json::to_value(&witness_1.core).unwrap());
    let core_hash_2 = hash_canonical(&serde_json::to_value(&witness_2.core).unwrap());

    assert_eq!(core_hash_1, core_hash_2);
    assert_eq!(witness_1.core, witness_2.core);
    assert_eq!(witness_1.core.output.value, ExactValue::int(12));
    assert_eq!(witness_1.core.output.unit, Some("hours".to_string()));
    assert_eq!(witness_1.core.plan_hash, plan_hash(&plan));
    assert!(witness_1.envelope.trace.is_none());
    assert!(!witness_1.envelope.created_at.is_empty());
}

#[test]
fn calc_execute_hashes_match_values() {
    let dir = TempDir::new().expect("tempdir");
    let expr_path = temp_path(&dir, "expr.json");
    let plan_path = temp_path(&dir, "plan.json");
    let witness_path = temp_path(&dir, "witness.json");

    let expr = json!({
        "type": "add",
        "left": { "type": "input_ref", "name": "a" },
        "right": { "type": "input_ref", "name": "b" }
    });
    write_json(&expr_path, &expr);

    let plan = calc_plan(
        &expr_path,
        vec!["a:int:hours".to_string(), "b:int:hours".to_string()],
        Some("hours".to_string()),
        &plan_path,
    )
    .expect("create plan");

    let witness = calc_execute(
        &plan_path,
        vec!["a=5".to_string(), "b=7".to_string()],
        false,
        &witness_path,
        None,
    )
    .expect("execute plan");

    let input_a = witness
        .core
        .inputs
        .iter()
        .find(|input| input.name == "a")
        .expect("input a");
    let input_b = witness
        .core
        .inputs
        .iter()
        .find(|input| input.name == "b")
        .expect("input b");

    let expected_input_a_hash = hash_canonical(&serde_json::to_value(&input_a.value).unwrap());
    let expected_input_b_hash = hash_canonical(&serde_json::to_value(&input_b.value).unwrap());

    assert_eq!(input_a.hash, expected_input_a_hash);
    assert_eq!(input_b.hash, expected_input_b_hash);

    let expected_output_hash =
        hash_canonical(&serde_json::to_value(&witness.core.output.value).unwrap());
    assert_eq!(witness.core.output.hash, expected_output_hash);
    assert_eq!(witness.core.plan_hash, plan_hash(&plan));
}

#[test]
fn calc_execute_trace_enabled_records_steps() {
    let dir = TempDir::new().expect("tempdir");
    let expr_path = temp_path(&dir, "expr.json");
    let plan_path = temp_path(&dir, "plan.json");
    let witness_path = temp_path(&dir, "witness.json");

    let expr = json!({
        "type": "add",
        "left": { "type": "input_ref", "name": "a" },
        "right": { "type": "input_ref", "name": "b" }
    });
    write_json(&expr_path, &expr);

    calc_plan(
        &expr_path,
        vec!["a:int:hours".to_string(), "b:int:hours".to_string()],
        Some("hours".to_string()),
        &plan_path,
    )
    .expect("create plan");

    let witness = calc_execute(
        &plan_path,
        vec!["a=5".to_string(), "b=7".to_string()],
        true,
        &witness_path,
        None,
    )
    .expect("execute plan");

    let trace = witness.envelope.trace.expect("trace");
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].operation, "add");
    assert_eq!(trace[0].result, ExactValue::int(12));
    assert_eq!(trace[0].step, 1);
}

#[test]
fn calc_execute_rejects_output_unit_mismatch() {
    let dir = TempDir::new().expect("tempdir");
    let expr_path = temp_path(&dir, "expr.json");
    let plan_path = temp_path(&dir, "plan.json");
    let witness_path = temp_path(&dir, "witness.json");

    let expr = json!({
        "type": "literal",
        "value": { "type": "int", "value": "5" }
    });
    write_json(&expr_path, &expr);

    calc_plan(&expr_path, vec![], Some("hours".to_string()), &plan_path).expect("create plan");

    let err = calc_execute(&plan_path, vec![], false, &witness_path, None)
        .expect_err("should fail on output unit mismatch");
    let message = format!("{}", err);
    assert!(message.contains("output unit mismatch"));
}

#[test]
fn calc_execute_rejects_missing_input() {
    let dir = TempDir::new().expect("tempdir");
    let expr_path = temp_path(&dir, "expr.json");
    let plan_path = temp_path(&dir, "plan.json");
    let witness_path = temp_path(&dir, "witness.json");

    let expr = json!({
        "type": "add",
        "left": { "type": "input_ref", "name": "a" },
        "right": { "type": "input_ref", "name": "b" }
    });
    write_json(&expr_path, &expr);

    calc_plan(
        &expr_path,
        vec!["a:int:hours".to_string(), "b:int:hours".to_string()],
        Some("hours".to_string()),
        &plan_path,
    )
    .expect("create plan");

    let err = calc_execute(
        &plan_path,
        vec!["a=5".to_string()],
        false,
        &witness_path,
        None,
    )
    .expect_err("should fail on missing input");
    let message = format!("{}", err);
    assert!(message.contains("missing required input"));
}

fn plan_hash(plan: &admit_core::calc_witness::CalcPlanArtifact) -> String {
    let plan_value = serde_json::to_value(plan).expect("plan to value");
    hash_canonical(&plan_value)
}
