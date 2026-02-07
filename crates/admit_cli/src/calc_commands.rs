use std::collections::BTreeMap;
use std::path::Path;

use admit_core::calc_ast::CalcExpr;
use admit_core::calc_eval::{CalcEvaluator, EvalResult};
use admit_core::calc_witness::{
    CalcInputContract, CalcOutput, CalcPlanArtifact, CalcResolvedInput, CalcWitness,
    CalcWitnessCore, CalcWitnessEnvelope, ExactType,
};
use admit_core::cbor::encode_canonical_value;
use admit_core::exact_types::ExactValue;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::types::DeclareCostError;

/// Create a calculator plan from expression and input contracts.
pub fn calc_plan(
    expression_path: &Path,
    input_contracts: Vec<String>,
    output_unit: Option<String>,
    out_path: &Path,
) -> Result<CalcPlanArtifact, DeclareCostError> {
    // Load expression JSON
    let expr_bytes = std::fs::read(expression_path)
        .map_err(|e| DeclareCostError::Io(format!("failed to read expression: {}", e)))?;

    let expression: CalcExpr = serde_json::from_slice(&expr_bytes)
        .map_err(|e| DeclareCostError::Json(format!("failed to parse expression: {}", e)))?;

    // Parse input contracts: format "name:type:unit" or "name:type"
    let mut inputs = Vec::new();
    for contract_str in input_contracts {
        let parts: Vec<&str> = contract_str.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(DeclareCostError::Io(format!(
                "invalid input contract format '{}', expected 'name:type' or 'name:type:unit'",
                contract_str
            )));
        }

        let name = parts[0].to_string();
        let type_str = parts[1];
        let expected_type = match type_str {
            "int" => ExactType::Int,
            "nat" => ExactType::Nat,
            "rational" => ExactType::Rational,
            "bool" => ExactType::Bool,
            _ => {
                return Err(DeclareCostError::Io(format!(
                    "invalid type '{}', expected int|nat|rational|bool",
                    type_str
                )))
            }
        };

        let expected_unit = parts.get(2).map(|s| s.to_string());

        inputs.push(CalcInputContract::new(name, expected_type, expected_unit));
    }

    // Build plan artifact
    let mut plan = CalcPlanArtifact::new(expression, inputs);
    if let Some(unit) = output_unit {
        plan = plan.with_output_unit(unit);
    }

    // Write plan to output file
    let plan_json = serde_json::to_string_pretty(&plan)
        .map_err(|e| DeclareCostError::Json(format!("failed to serialize plan: {}", e)))?;

    std::fs::write(out_path, plan_json)
        .map_err(|e| DeclareCostError::Io(format!("failed to write plan: {}", e)))?;

    Ok(plan)
}

/// Execute a calculator plan with provided inputs.
pub fn calc_execute(
    plan_path: &Path,
    input_values: Vec<String>,
    trace_enabled: bool,
    out_path: &Path,
    _artifacts_dir: Option<&Path>,
) -> Result<CalcWitness, DeclareCostError> {
    // Load plan
    let plan_bytes = std::fs::read(plan_path)
        .map_err(|e| DeclareCostError::Io(format!("failed to read plan: {}", e)))?;

    let plan: CalcPlanArtifact = serde_json::from_slice(&plan_bytes)
        .map_err(|e| DeclareCostError::Json(format!("failed to parse plan: {}", e)))?;

    // Compute plan hash
    let plan_value = serde_json::to_value(&plan)
        .map_err(|e| DeclareCostError::Json(format!("failed to convert plan to value: {}", e)))?;
    let plan_cbor = encode_canonical_value(&plan_value)
        .map_err(|e| DeclareCostError::CanonicalEncode(e.to_string()))?;
    let plan_hash = hex::encode(Sha256::digest(&plan_cbor));

    // Parse input values: format "name=value" or "name=value unit"
    let mut inputs_map = BTreeMap::new();
    let mut resolved_inputs = Vec::new();

    for input_str in input_values {
        let parts: Vec<&str> = input_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(DeclareCostError::Io(format!(
                "invalid input format '{}', expected 'name=value'",
                input_str
            )));
        }

        let name = parts[0].to_string();
        let value_str = parts[1];

        // Find contract for this input
        let contract = plan
            .inputs
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| {
                DeclareCostError::Io(format!("input '{}' not found in plan", name))
            })?;

        // Parse value based on expected type
        let value = match contract.expected_type {
            ExactType::Int => {
                let i = value_str.parse::<i64>().map_err(|e| {
                    DeclareCostError::Io(format!("invalid int value '{}': {}", value_str, e))
                })?;
                ExactValue::int(i)
            }
            ExactType::Nat => {
                let n = value_str.parse::<u64>().map_err(|e| {
                    DeclareCostError::Io(format!("invalid nat value '{}': {}", value_str, e))
                })?;
                ExactValue::nat(n)
            }
            ExactType::Rational => {
                // Parse "num/denom" format
                let rat_parts: Vec<&str> = value_str.split('/').collect();
                if rat_parts.len() != 2 {
                    return Err(DeclareCostError::Io(format!(
                        "invalid rational format '{}', expected 'num/denom'",
                        value_str
                    )));
                }
                let num = rat_parts[0].parse::<i64>().map_err(|e| {
                    DeclareCostError::Io(format!("invalid numerator: {}", e))
                })?;
                let denom = rat_parts[1].parse::<i64>().map_err(|e| {
                    DeclareCostError::Io(format!("invalid denominator: {}", e))
                })?;
                ExactValue::rational(num, denom)
                    .map_err(|e| DeclareCostError::Io(format!("invalid rational: {}", e)))?
            }
            ExactType::Bool => {
                let b = value_str.parse::<bool>().map_err(|e| {
                    DeclareCostError::Io(format!("invalid bool value '{}': {}", value_str, e))
                })?;
                ExactValue::bool(b)
            }
        };

        // Verify type matches
        if !contract.expected_type.matches(&value) {
            return Err(DeclareCostError::Io(format!(
                "input '{}' type mismatch: expected {:?}, got {}",
                name,
                contract.expected_type,
                value.type_name()
            )));
        }

        // Compute input hash
        let input_value = serde_json::to_value(&value)
            .map_err(|e| DeclareCostError::Json(format!("failed to serialize input: {}", e)))?;
        let input_cbor = encode_canonical_value(&input_value)
            .map_err(|e| DeclareCostError::CanonicalEncode(e.to_string()))?;
        let input_hash = hex::encode(Sha256::digest(&input_cbor));

        resolved_inputs.push(CalcResolvedInput::new(
            name.clone(),
            value.clone(),
            contract.expected_unit.clone(),
            input_hash,
        ));

        inputs_map.insert(
            name,
            EvalResult::new(value, contract.expected_unit.clone()),
        );
    }

    // Verify all required inputs provided
    for contract in &plan.inputs {
        if !inputs_map.contains_key(&contract.name) {
            return Err(DeclareCostError::Io(format!(
                "missing required input: {}",
                contract.name
            )));
        }
    }

    // Create evaluator and evaluate
    let mut evaluator = CalcEvaluator::new(inputs_map, trace_enabled);
    let result = evaluator
        .eval(&plan.expression)
        .map_err(|e| DeclareCostError::Io(format!("evaluation failed: {}", e)))?;

    // Verify output unit if specified
    if let Some(expected_unit) = &plan.expected_output_unit {
        match &result.unit {
            Some(u) if u == expected_unit => {}
            Some(u) => {
                return Err(DeclareCostError::Io(format!(
                    "output unit mismatch: expected {}, got {}",
                    expected_unit, u
                )))
            }
            None => {
                return Err(DeclareCostError::Io(format!(
                    "output unit mismatch: expected {}, got unitless",
                    expected_unit
                )))
            }
        }
    }

    // Compute output hash
    let output_value = serde_json::to_value(&result.value)
        .map_err(|e| DeclareCostError::Json(format!("failed to serialize output: {}", e)))?;
    let output_cbor = encode_canonical_value(&output_value)
        .map_err(|e| DeclareCostError::CanonicalEncode(e.to_string()))?;
    let output_hash = hex::encode(Sha256::digest(&output_cbor));

    let output = CalcOutput::new(result.value, result.unit, output_hash);

    // Build witness core
    let core = CalcWitnessCore {
        schema_id: "calc-witness/0".to_string(),
        schema_version: 0,
        plan_hash,
        inputs: resolved_inputs,
        expression: plan.expression,
        output,
    };

    // Build envelope with timestamp
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut envelope = CalcWitnessEnvelope::new(timestamp);

    if trace_enabled {
        let trace = evaluator.into_trace();
        envelope = envelope.with_trace(trace);
    }

    let witness = CalcWitness::new(core, envelope);

    // Write witness to output file
    let witness_json = serde_json::to_string_pretty(&witness)
        .map_err(|e| DeclareCostError::Json(format!("failed to serialize witness: {}", e)))?;

    std::fs::write(out_path, witness_json)
        .map_err(|e| DeclareCostError::Io(format!("failed to write witness: {}", e)))?;

    Ok(witness)
}

/// Describe the calculator mechanism capabilities.
pub fn calc_describe() -> Value {
    serde_json::json!({
        "mechanism_id": "mechanism.calc.pure",
        "version": "0.1.0",
        "schema_version": 0,
        "capabilities": [
            "plan",
            "execute",
            "describe"
        ],
        "supported_operations": [
            "add",
            "subtract",
            "multiply",
            "divide",
            "compare",
            "convert_unit"
        ],
        "value_types": ["int", "nat", "rational", "bool"],
        "comparison_ops": ["eq", "neq", "gt", "gte", "lt", "lte"],
        "deterministic": true,
        "unit_discipline": "strict",
        "features": {
            "exact_arithmetic": true,
            "trace_support": true,
            "content_addressed": true,
            "two_layer_witness": true
        },
        "touched_scope": "scope:calc.pure"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_calc_describe() {
        let desc = calc_describe();
        assert_eq!(desc["mechanism_id"], "mechanism.calc.pure");
        assert_eq!(desc["deterministic"], true);
    }

    #[test]
    fn test_plan_creation() {
        let mut expr_file = NamedTempFile::new().unwrap();
        let expr = serde_json::json!({
            "type": "add",
            "left": {
                "type": "input_ref",
                "name": "a"
            },
            "right": {
                "type": "input_ref",
                "name": "b"
            }
        });
        expr_file.write_all(expr.to_string().as_bytes()).unwrap();
        expr_file.flush().unwrap();

        let out_file = NamedTempFile::new().unwrap();

        let contracts = vec!["a:int:hours".to_string(), "b:int:hours".to_string()];

        let plan = calc_plan(
            expr_file.path(),
            contracts,
            Some("hours".to_string()),
            out_file.path(),
        )
        .unwrap();

        assert_eq!(plan.inputs.len(), 2);
        assert_eq!(plan.expected_output_unit, Some("hours".to_string()));
    }
}
