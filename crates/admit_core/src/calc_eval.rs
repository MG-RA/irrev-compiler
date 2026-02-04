use std::collections::BTreeMap;

use crate::calc_ast::{CalcCmpOp, CalcExpr, CalcLiteral};
use crate::calc_witness::CalcTraceStep;
use crate::exact_types::{ExactQuantity, ExactValue};

/// Calculator evaluation result with value and optional unit.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalResult {
    pub value: ExactValue,
    pub unit: Option<String>,
}

impl EvalResult {
    pub fn new(value: ExactValue, unit: Option<String>) -> Self {
        EvalResult { value, unit }
    }

    pub fn unitless(value: ExactValue) -> Self {
        EvalResult { value, unit: None }
    }

    pub fn with_unit(value: ExactValue, unit: String) -> Self {
        EvalResult {
            value,
            unit: Some(unit),
        }
    }

    pub fn to_quantity(&self) -> ExactQuantity {
        match &self.unit {
            Some(u) => ExactQuantity::new(self.value.clone(), u.clone()),
            None => ExactQuantity::unitless(self.value.clone()),
        }
    }
}

/// Deterministic calculator evaluator.
/// All operations are exact arithmetic with strict unit discipline.
pub struct CalcEvaluator {
    inputs: BTreeMap<String, EvalResult>,
    trace: Vec<CalcTraceStep>,
    trace_enabled: bool,
    next_step: u32,
}

impl CalcEvaluator {
    pub fn new(inputs: BTreeMap<String, EvalResult>, trace_enabled: bool) -> Self {
        CalcEvaluator {
            inputs,
            trace: Vec::new(),
            trace_enabled,
            next_step: 1,
        }
    }

    /// Evaluate an expression, returning the result value and unit.
    pub fn eval(&mut self, expr: &CalcExpr) -> Result<EvalResult, String> {
        match expr {
            CalcExpr::Literal { value, unit } => {
                // Normalize rational literals to lowest terms
                let exact_value = value.to_exact_value()?.normalize()?;
                Ok(EvalResult::new(exact_value, unit.clone()))
            }

            CalcExpr::InputRef { name, .. } => {
                self.inputs.get(name).cloned().ok_or_else(|| {
                    format!("input '{}' not found (available: {:?})", name, self.inputs.keys())
                })
            }

            CalcExpr::Add { left, right } => {
                let l = self.eval(left)?;
                let r = self.eval(right)?;

                let lq = l.to_quantity();
                let rq = r.to_quantity();
                let result_qty = lq.add(&rq)?;

                let result = EvalResult::new(result_qty.value.clone(), Some(result_qty.unit.clone()));

                if self.trace_enabled {
                    self.record_trace("add", vec![l.value, r.value], result.value.clone(), result.unit.clone());
                }

                Ok(result)
            }

            CalcExpr::Subtract { left, right } => {
                let l = self.eval(left)?;
                let r = self.eval(right)?;

                let lq = l.to_quantity();
                let rq = r.to_quantity();
                let result_qty = lq.subtract(&rq)?;

                let result = EvalResult::new(result_qty.value.clone(), Some(result_qty.unit.clone()));

                if self.trace_enabled {
                    self.record_trace("subtract", vec![l.value, r.value], result.value.clone(), result.unit.clone());
                }

                Ok(result)
            }

            CalcExpr::Multiply { left, right } => {
                let l = self.eval(left)?;
                let r = self.eval(right)?;

                let lq = l.to_quantity();
                let rq = r.to_quantity();
                let result_qty = lq.multiply(&rq)?;

                let result = EvalResult::new(
                    result_qty.value.clone(),
                    if result_qty.unit.is_empty() {
                        None
                    } else {
                        Some(result_qty.unit.clone())
                    },
                );

                if self.trace_enabled {
                    self.record_trace("multiply", vec![l.value, r.value], result.value.clone(), result.unit.clone());
                }

                Ok(result)
            }

            CalcExpr::Divide { left, right } => {
                let l = self.eval(left)?;
                let r = self.eval(right)?;

                let lq = l.to_quantity();
                let rq = r.to_quantity();
                let result_qty = lq.divide(&rq)?;

                let result = EvalResult::new(
                    result_qty.value.clone(),
                    if result_qty.unit.is_empty() {
                        None
                    } else {
                        Some(result_qty.unit.clone())
                    },
                );

                if self.trace_enabled {
                    self.record_trace("divide", vec![l.value, r.value], result.value.clone(), result.unit.clone());
                }

                Ok(result)
            }

            CalcExpr::Compare { left, right, op } => {
                let l = self.eval(left)?;
                let r = self.eval(right)?;

                let lq = l.to_quantity();
                let rq = r.to_quantity();
                let ord = lq.compare(&rq)?;

                let result_bool = op.apply(ord);
                let result_value = ExactValue::bool(result_bool);

                if self.trace_enabled {
                    self.record_trace(
                        format!("compare_{:?}", op),
                        vec![l.value, r.value],
                        result_value.clone(),
                        None,
                    );
                }

                Ok(EvalResult::unitless(result_value))
            }

            CalcExpr::ConvertUnit {
                expr,
                from_unit,
                to_unit,
                factor,
            } => {
                let val = self.eval(expr)?;

                // Verify source unit matches
                match &val.unit {
                    Some(u) if u == from_unit => {}
                    Some(u) => {
                        return Err(format!(
                            "unit mismatch in conversion: expected {}, got {}",
                            from_unit, u
                        ))
                    }
                    None => {
                        return Err(format!(
                            "cannot convert unitless value (expected unit: {})",
                            from_unit
                        ))
                    }
                }

                // Apply conversion factor
                let factor_value = factor.to_exact_value()?.normalize()?;
                let converted = val.value.multiply(&factor_value)?;

                let result = EvalResult::with_unit(converted.clone(), to_unit.clone());

                if self.trace_enabled {
                    self.record_trace(
                        format!("convert_{}_{}", from_unit, to_unit),
                        vec![val.value],
                        converted,
                        Some(to_unit.clone()),
                    );
                }

                Ok(result)
            }
        }
    }

    fn record_trace(
        &mut self,
        operation: impl Into<String>,
        operands: Vec<ExactValue>,
        result: ExactValue,
        unit: Option<String>,
    ) {
        let step = CalcTraceStep::new(self.next_step, operation, operands, result, unit);
        self.trace.push(step);
        self.next_step += 1;
    }

    /// Consume the evaluator and return the trace.
    pub fn into_trace(self) -> Vec<CalcTraceStep> {
        self.trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs(pairs: Vec<(&str, i64, Option<&str>)>) -> BTreeMap<String, EvalResult> {
        pairs
            .into_iter()
            .map(|(name, val, unit)| {
                (
                    name.to_string(),
                    EvalResult::new(ExactValue::int(val), unit.map(|u| u.to_string())),
                )
            })
            .collect()
    }

    #[test]
    fn test_literal_evaluation() {
        let mut eval = CalcEvaluator::new(BTreeMap::new(), false);

        let expr = CalcExpr::Literal {
            value: CalcLiteral::Int {
                value: "42".to_string(),
            },
            unit: Some("hours".to_string()),
        };

        let result = eval.eval(&expr).unwrap();
        assert_eq!(result.value, ExactValue::int(42));
        assert_eq!(result.unit, Some("hours".to_string()));
    }

    #[test]
    fn test_input_ref() {
        let inputs = make_inputs(vec![("x", 10, Some("hours"))]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::InputRef {
            name: "x".to_string(),
            hash: None,
        };

        let result = eval.eval(&expr).unwrap();
        assert_eq!(result.value, ExactValue::int(10));
        assert_eq!(result.unit, Some("hours".to_string()));
    }

    #[test]
    fn test_addition() {
        let inputs = make_inputs(vec![("a", 5, Some("hours")), ("b", 3, Some("hours"))]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::Add {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
        };

        let result = eval.eval(&expr).unwrap();
        assert_eq!(result.value, ExactValue::int(8));
        assert_eq!(result.unit, Some("hours".to_string()));
    }

    #[test]
    fn test_unit_mismatch_error() {
        let inputs = make_inputs(vec![("a", 5, Some("hours")), ("b", 3, Some("dollars"))]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::Add {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
        };

        let result = eval.eval(&expr);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unit mismatch"));
    }

    #[test]
    fn test_multiply_with_unitless() {
        let inputs = make_inputs(vec![("a", 5, Some("hours")), ("b", 3, None)]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::Multiply {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
        };

        let result = eval.eval(&expr).unwrap();
        assert_eq!(result.value, ExactValue::int(15));
        assert_eq!(result.unit, Some("hours".to_string()));
    }

    #[test]
    fn test_multiply_both_units_error() {
        let inputs = make_inputs(vec![("a", 5, Some("hours")), ("b", 3, Some("dollars"))]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::Multiply {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
        };

        let result = eval.eval(&expr);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("compound units"));
    }

    #[test]
    fn test_comparison() {
        let inputs = make_inputs(vec![("a", 5, Some("hours")), ("b", 3, Some("hours"))]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::Compare {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
            op: CalcCmpOp::Gt,
        };

        let result = eval.eval(&expr).unwrap();
        assert_eq!(result.value, ExactValue::bool(true));
        assert_eq!(result.unit, None);
    }

    #[test]
    fn test_division_by_zero() {
        let inputs = make_inputs(vec![("a", 5, None), ("b", 0, None)]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::Divide {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
        };

        let result = eval.eval(&expr);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("division by zero"));
    }

    #[test]
    fn test_trace_recording() {
        let inputs = make_inputs(vec![("a", 5, None), ("b", 3, None)]);
        let mut eval = CalcEvaluator::new(inputs, true);

        let expr = CalcExpr::Add {
            left: Box::new(CalcExpr::InputRef {
                name: "a".to_string(),
                hash: None,
            }),
            right: Box::new(CalcExpr::InputRef {
                name: "b".to_string(),
                hash: None,
            }),
        };

        let _result = eval.eval(&expr).unwrap();
        let trace = eval.into_trace();

        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].operation, "add");
        assert_eq!(trace[0].step, 1);
        assert_eq!(trace[0].result, ExactValue::int(8));
    }

    #[test]
    fn test_unit_conversion() {
        let inputs = make_inputs(vec![("cost", 300, Some("usd"))]);
        let mut eval = CalcEvaluator::new(inputs, false);

        let expr = CalcExpr::ConvertUnit {
            expr: Box::new(CalcExpr::InputRef {
                name: "cost".to_string(),
                hash: None,
            }),
            from_unit: "usd".to_string(),
            to_unit: "engineer_hours".to_string(),
            factor: CalcLiteral::Rational {
                numerator: "1".to_string(),
                denominator: "150".to_string(),
            },
        };

        let result = eval.eval(&expr).unwrap();
        assert_eq!(result.value, ExactValue::int(2)); // 300 / 150 = 2
        assert_eq!(result.unit, Some("engineer_hours".to_string()));
    }
}
