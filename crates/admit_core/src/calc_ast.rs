use serde::{Deserialize, Serialize};

/// Calculator expression tree for deterministic computation.
/// All literals are typed with string payloads to avoid JSON number model issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum CalcExpr {
    #[serde(rename = "literal")]
    Literal {
        value: CalcLiteral,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },

    #[serde(rename = "input_ref")]
    InputRef {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        hash: Option<String>,
    },

    #[serde(rename = "add")]
    Add {
        left: Box<CalcExpr>,
        right: Box<CalcExpr>,
    },

    #[serde(rename = "subtract")]
    Subtract {
        left: Box<CalcExpr>,
        right: Box<CalcExpr>,
    },

    #[serde(rename = "multiply")]
    Multiply {
        left: Box<CalcExpr>,
        right: Box<CalcExpr>,
    },

    #[serde(rename = "divide")]
    Divide {
        left: Box<CalcExpr>,
        right: Box<CalcExpr>,
    },

    #[serde(rename = "compare")]
    Compare {
        left: Box<CalcExpr>,
        right: Box<CalcExpr>,
        op: CalcCmpOp,
    },

    #[serde(rename = "convert_unit")]
    ConvertUnit {
        expr: Box<CalcExpr>,
        from_unit: String,
        to_unit: String,
        factor: CalcLiteral,
    },
}

/// Typed literal values with string payloads.
/// CRITICAL: No raw JSON numbers allowed to avoid representation drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum CalcLiteral {
    #[serde(rename = "int")]
    Int { value: String },

    #[serde(rename = "nat")]
    Nat { value: String },

    #[serde(rename = "rational")]
    Rational {
        numerator: String,
        denominator: String,
    },

    #[serde(rename = "bool")]
    Bool { value: bool },
}

impl CalcLiteral {
    /// Validate that string payloads are well-formed numbers.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            CalcLiteral::Int { value } => {
                value
                    .parse::<i64>()
                    .map_err(|e| format!("invalid int value '{}': {}", value, e))?;
                Ok(())
            }
            CalcLiteral::Nat { value } => {
                value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid nat value '{}': {}", value, e))?;
                Ok(())
            }
            CalcLiteral::Rational {
                numerator,
                denominator,
            } => {
                numerator
                    .parse::<i64>()
                    .map_err(|e| format!("invalid numerator '{}': {}", numerator, e))?;
                let denom = denominator
                    .parse::<i64>()
                    .map_err(|e| format!("invalid denominator '{}': {}", denominator, e))?;
                if denom == 0 {
                    return Err("denominator cannot be zero".to_string());
                }
                Ok(())
            }
            CalcLiteral::Bool { .. } => Ok(()),
        }
    }

    /// Convert to ExactValue (requires exact_types in scope).
    pub fn to_exact_value(&self) -> Result<crate::exact_types::ExactValue, String> {
        use crate::exact_types::ExactValue;

        match self {
            CalcLiteral::Int { value } => {
                let i = value
                    .parse::<i64>()
                    .map_err(|e| format!("invalid int value '{}': {}", value, e))?;
                Ok(ExactValue::int(i))
            }
            CalcLiteral::Nat { value } => {
                let n = value
                    .parse::<u64>()
                    .map_err(|e| format!("invalid nat value '{}': {}", value, e))?;
                Ok(ExactValue::nat(n))
            }
            CalcLiteral::Rational {
                numerator,
                denominator,
            } => {
                let num = numerator
                    .parse::<i64>()
                    .map_err(|e| format!("invalid numerator '{}': {}", numerator, e))?;
                let denom = denominator
                    .parse::<i64>()
                    .map_err(|e| format!("invalid denominator '{}': {}", denominator, e))?;
                ExactValue::rational(num, denom)
            }
            CalcLiteral::Bool { value } => Ok(ExactValue::bool(*value)),
        }
    }
}

/// Comparison operators for calculator expressions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CalcCmpOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

impl CalcCmpOp {
    pub fn apply(&self, ord: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering;
        match (self, ord) {
            (CalcCmpOp::Eq, Ordering::Equal) => true,
            (CalcCmpOp::Neq, Ordering::Equal) => false,
            (CalcCmpOp::Neq, _) => true,
            (CalcCmpOp::Gt, Ordering::Greater) => true,
            (CalcCmpOp::Gte, Ordering::Greater | Ordering::Equal) => true,
            (CalcCmpOp::Lt, Ordering::Less) => true,
            (CalcCmpOp::Lte, Ordering::Less | Ordering::Equal) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_validation() {
        let int_lit = CalcLiteral::Int {
            value: "125".to_string(),
        };
        assert!(int_lit.validate().is_ok());

        let bad_int = CalcLiteral::Int {
            value: "not_a_number".to_string(),
        };
        assert!(bad_int.validate().is_err());

        let rat_lit = CalcLiteral::Rational {
            numerator: "1".to_string(),
            denominator: "3".to_string(),
        };
        assert!(rat_lit.validate().is_ok());

        let bad_rat = CalcLiteral::Rational {
            numerator: "1".to_string(),
            denominator: "0".to_string(),
        };
        assert!(bad_rat.validate().is_err());
    }

    #[test]
    fn test_literal_to_exact_value() {
        let int_lit = CalcLiteral::Int {
            value: "42".to_string(),
        };
        let exact = int_lit.to_exact_value().unwrap();
        assert_eq!(exact, crate::exact_types::ExactValue::int(42));

        let rat_lit = CalcLiteral::Rational {
            numerator: "1".to_string(),
            denominator: "2".to_string(),
        };
        let exact = rat_lit.to_exact_value().unwrap();
        assert_eq!(
            exact,
            crate::exact_types::ExactValue::rational(1, 2).unwrap()
        );
    }

    #[test]
    fn test_cmp_op_apply() {
        assert!(CalcCmpOp::Eq.apply(std::cmp::Ordering::Equal));
        assert!(!CalcCmpOp::Eq.apply(std::cmp::Ordering::Greater));
        assert!(CalcCmpOp::Neq.apply(std::cmp::Ordering::Greater));
        assert!(CalcCmpOp::Gt.apply(std::cmp::Ordering::Greater));
        assert!(!CalcCmpOp::Gt.apply(std::cmp::Ordering::Equal));
        assert!(CalcCmpOp::Gte.apply(std::cmp::Ordering::Equal));
    }

    #[test]
    fn test_expr_serialization() {
        let expr = CalcExpr::Add {
            left: Box::new(CalcExpr::Literal {
                value: CalcLiteral::Int {
                    value: "5".to_string(),
                },
                unit: Some("hours".to_string()),
            }),
            right: Box::new(CalcExpr::Literal {
                value: CalcLiteral::Int {
                    value: "3".to_string(),
                },
                unit: Some("hours".to_string()),
            }),
        };

        let json = serde_json::to_string_pretty(&expr).unwrap();
        let parsed: CalcExpr = serde_json::from_str(&json).unwrap();
        assert_eq!(expr, parsed);
    }
}
