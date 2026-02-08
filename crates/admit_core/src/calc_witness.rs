use serde::{Deserialize, Serialize};

use crate::calc_ast::{CalcExpr, CalcLiteral};
use crate::exact_types::ExactValue;

/// Calculator plan artifact - defines the computation contract.
/// Plans are stable and shareable; they contain input contracts, not values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcPlanArtifact {
    pub schema_id: String,
    pub schema_version: u32,
    pub mechanism_id: String,
    pub mechanism_version: String,

    pub expression: CalcExpr,
    pub inputs: Vec<CalcInputContract>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unit_rules: Vec<UnitConversionRule>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_output_unit: Option<String>,

    pub touched_scope: String,
}

impl CalcPlanArtifact {
    pub fn new(expression: CalcExpr, inputs: Vec<CalcInputContract>) -> Self {
        CalcPlanArtifact {
            schema_id: "calc-plan/0".to_string(),
            schema_version: 0,
            mechanism_id: "mechanism.calc.pure".to_string(),
            mechanism_version: "0.1.0".to_string(),
            expression,
            inputs,
            unit_rules: Vec::new(),
            expected_output_unit: None,
            touched_scope: "scope:calc.pure".to_string(),
        }
    }

    pub fn with_output_unit(mut self, unit: impl Into<String>) -> Self {
        self.expected_output_unit = Some(unit.into());
        self
    }

    pub fn with_unit_rules(mut self, rules: Vec<UnitConversionRule>) -> Self {
        self.unit_rules = rules;
        self
    }
}

/// Input contract - defines what the plan expects, not actual values.
/// This keeps plans stable and shareable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CalcInputContract {
    pub name: String,
    pub expected_type: ExactType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_unit: Option<String>,
}

impl CalcInputContract {
    pub fn new(
        name: impl Into<String>,
        expected_type: ExactType,
        expected_unit: Option<String>,
    ) -> Self {
        CalcInputContract {
            name: name.into(),
            expected_type,
            expected_unit,
        }
    }
}

/// Type specification for input contracts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExactType {
    Int,
    Nat,
    Rational,
    Bool,
}

impl ExactType {
    pub fn matches(&self, value: &ExactValue) -> bool {
        match (self, value) {
            (ExactType::Int, ExactValue::Int { .. }) => true,
            (ExactType::Nat, ExactValue::Nat { .. }) => true,
            (ExactType::Rational, ExactValue::Rational { .. }) => true,
            (ExactType::Bool, ExactValue::Bool { .. }) => true,
            // Allow Int to match Rational (integers are a subset of rationals)
            (ExactType::Rational, ExactValue::Int { .. }) => true,
            _ => false,
        }
    }
}

/// Unit conversion rule for explicit conversions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnitConversionRule {
    pub from_unit: String,
    pub to_unit: String,
    pub factor: CalcLiteral,
}

/// Calculator witness with two-layer structure.
/// The envelope contains metadata that is NOT part of the witness identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcWitness {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "court_version")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// Core payload - content-addressed, deterministic
    #[serde(flatten)]
    pub core: CalcWitnessCore,

    /// Envelope metadata - NOT part of witness identity
    #[serde(flatten)]
    pub envelope: CalcWitnessEnvelope,
}

impl CalcWitness {
    pub fn new(core: CalcWitnessCore, envelope: CalcWitnessEnvelope) -> Self {
        CalcWitness {
            schema_id: None,
            created_at: None,
            engine_version: None,
            input_id: None,
            config_hash: None,
            core,
            envelope,
        }
    }
}

/// Core witness payload - this is what gets hashed for witness identity.
/// CRITICAL: Excludes timestamps and traces to ensure determinism.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcWitnessCore {
    pub schema_id: String,
    pub schema_version: u32,
    pub plan_hash: String,
    pub inputs: Vec<CalcResolvedInput>,
    pub expression: CalcExpr,
    pub output: CalcOutput,
}

/// Envelope metadata - NOT part of witness identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcWitnessEnvelope {
    pub created_at: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<Vec<CalcTraceStep>>,
}

impl CalcWitnessEnvelope {
    pub fn new(created_at: String) -> Self {
        CalcWitnessEnvelope {
            created_at,
            trace: None,
        }
    }

    pub fn with_trace(mut self, trace: Vec<CalcTraceStep>) -> Self {
        self.trace = Some(trace);
        self
    }
}

/// Resolved input with its value and content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcResolvedInput {
    pub name: String,
    pub value: ExactValue,
    pub unit: Option<String>,
    pub hash: String,
}

impl CalcResolvedInput {
    pub fn new(
        name: impl Into<String>,
        value: ExactValue,
        unit: Option<String>,
        hash: impl Into<String>,
    ) -> Self {
        CalcResolvedInput {
            name: name.into(),
            value,
            unit,
            hash: hash.into(),
        }
    }
}

/// Output value with its content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcOutput {
    pub value: ExactValue,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    pub hash: String,
}

impl CalcOutput {
    pub fn new(value: ExactValue, unit: Option<String>, hash: impl Into<String>) -> Self {
        CalcOutput {
            value,
            unit,
            hash: hash.into(),
        }
    }
}

/// Trace step for audit trail.
/// CRITICAL: Must be deterministic - semantic steps only, no implementation details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalcTraceStep {
    pub step: u32,
    pub operation: String,
    pub operands: Vec<ExactValue>,
    pub result: ExactValue,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl CalcTraceStep {
    pub fn new(
        step: u32,
        operation: impl Into<String>,
        operands: Vec<ExactValue>,
        result: ExactValue,
        unit: Option<String>,
    ) -> Self {
        CalcTraceStep {
            step,
            operation: operation.into(),
            operands,
            result,
            unit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calc_ast::CalcLiteral;

    #[test]
    fn test_exact_type_matches() {
        let int_val = ExactValue::int(42);
        let nat_val = ExactValue::nat(42);
        let bool_val = ExactValue::bool(true);

        assert!(ExactType::Int.matches(&int_val));
        assert!(!ExactType::Int.matches(&nat_val));
        assert!(!ExactType::Int.matches(&bool_val));

        // Int should match Rational contract
        assert!(ExactType::Rational.matches(&int_val));
    }

    #[test]
    fn test_plan_artifact_construction() {
        let inputs = vec![CalcInputContract::new(
            "x",
            ExactType::Int,
            Some("hours".to_string()),
        )];

        let expr = CalcExpr::Literal {
            value: CalcLiteral::Int {
                value: "5".to_string(),
            },
            unit: Some("hours".to_string()),
        };

        let plan = CalcPlanArtifact::new(expr, inputs).with_output_unit("hours");

        assert_eq!(plan.schema_id, "calc-plan/0");
        assert_eq!(plan.mechanism_id, "mechanism.calc.pure");
        assert_eq!(plan.touched_scope, "scope:calc.pure");
        assert_eq!(plan.expected_output_unit, Some("hours".to_string()));
    }

    #[test]
    fn test_witness_two_layer_structure() {
        let core = CalcWitnessCore {
            schema_id: "calc-witness/0".to_string(),
            schema_version: 0,
            plan_hash: "abc123".to_string(),
            inputs: vec![],
            expression: CalcExpr::Literal {
                value: CalcLiteral::Int {
                    value: "42".to_string(),
                },
                unit: None,
            },
            output: CalcOutput::new(ExactValue::int(42), None, "def456"),
        };

        let envelope = CalcWitnessEnvelope::new("2026-01-01T00:00:00Z".to_string());

        let witness = CalcWitness::new(core, envelope);

        assert_eq!(witness.core.plan_hash, "abc123");
        assert_eq!(witness.envelope.created_at, "2026-01-01T00:00:00Z");
        assert!(witness.envelope.trace.is_none());
    }

    #[test]
    fn test_witness_serialization_excludes_none_trace() {
        let core = CalcWitnessCore {
            schema_id: "calc-witness/0".to_string(),
            schema_version: 0,
            plan_hash: "abc123".to_string(),
            inputs: vec![],
            expression: CalcExpr::Literal {
                value: CalcLiteral::Int {
                    value: "42".to_string(),
                },
                unit: None,
            },
            output: CalcOutput::new(ExactValue::int(42), None, "def456"),
        };

        let envelope = CalcWitnessEnvelope::new("2026-01-01T00:00:00Z".to_string());
        let witness = CalcWitness::new(core, envelope);

        let json = serde_json::to_string(&witness).unwrap();
        // Trace should not appear in JSON when None
        assert!(!json.contains("\"trace\""));
    }
}
