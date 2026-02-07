use num_rational::Rational64;
use num_traits::{CheckedAdd, CheckedDiv, CheckedMul, CheckedSub, Zero};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::str::FromStr;

/// Exact numeric value types for deterministic computation.
/// All operations are checked for overflow and reject floating-point values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "type")]
pub enum ExactValue {
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

impl ExactValue {
    // Constructors
    pub fn int(value: i64) -> Self {
        ExactValue::Int {
            value: value.to_string(),
        }
    }

    pub fn nat(value: u64) -> Self {
        ExactValue::Nat {
            value: value.to_string(),
        }
    }

    pub fn rational(numerator: i64, denominator: i64) -> Result<Self, String> {
        if denominator == 0 {
            return Err("denominator cannot be zero".to_string());
        }
        let rat = Rational64::new(numerator, denominator);
        // Normalize immediately: if it's a whole number, return as Int
        Self::from_rational(rat)
    }

    pub fn bool(value: bool) -> Self {
        ExactValue::Bool { value }
    }

    // Type checking
    pub fn type_name(&self) -> &'static str {
        match self {
            ExactValue::Int { .. } => "int",
            ExactValue::Nat { .. } => "nat",
            ExactValue::Rational { .. } => "rational",
            ExactValue::Bool { .. } => "bool",
        }
    }

    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            ExactValue::Int { .. } | ExactValue::Nat { .. } | ExactValue::Rational { .. }
        )
    }

    fn to_rational(&self) -> Result<Rational64, String> {
        match self {
            ExactValue::Int { value } => {
                let i = i64::from_str(value)
                    .map_err(|e| format!("invalid int value '{}': {}", value, e))?;
                Ok(Rational64::from_integer(i))
            }
            ExactValue::Nat { value } => {
                let n = u64::from_str(value)
                    .map_err(|e| format!("invalid nat value '{}': {}", value, e))?;
                let i = i64::try_from(n)
                    .map_err(|_| format!("nat value {} too large for i64", value))?;
                Ok(Rational64::from_integer(i))
            }
            ExactValue::Rational {
                numerator,
                denominator,
            } => {
                let num = i64::from_str(numerator)
                    .map_err(|e| format!("invalid numerator '{}': {}", numerator, e))?;
                let denom = i64::from_str(denominator)
                    .map_err(|e| format!("invalid denominator '{}': {}", denominator, e))?;
                if denom == 0 {
                    return Err("denominator cannot be zero".to_string());
                }
                Ok(Rational64::new(num, denom))
            }
            _ => Err(format!("cannot convert {} to rational", self.type_name())),
        }
    }

    // Arithmetic operations
    pub fn add(&self, other: &Self) -> Result<Self, String> {
        if !self.is_numeric() || !other.is_numeric() {
            return Err(format!(
                "cannot add {} and {}",
                self.type_name(),
                other.type_name()
            ));
        }

        let a = self.to_rational()?;
        let b = other.to_rational()?;
        let result = a
            .checked_add(&b)
            .ok_or_else(|| "integer overflow in addition".to_string())?;

        Self::from_rational(result)
    }

    pub fn subtract(&self, other: &Self) -> Result<Self, String> {
        if !self.is_numeric() || !other.is_numeric() {
            return Err(format!(
                "cannot subtract {} and {}",
                self.type_name(),
                other.type_name()
            ));
        }

        let a = self.to_rational()?;
        let b = other.to_rational()?;
        let result = a
            .checked_sub(&b)
            .ok_or_else(|| "integer overflow in subtraction".to_string())?;

        Self::from_rational(result)
    }

    pub fn multiply(&self, other: &Self) -> Result<Self, String> {
        if !self.is_numeric() || !other.is_numeric() {
            return Err(format!(
                "cannot multiply {} and {}",
                self.type_name(),
                other.type_name()
            ));
        }

        let a = self.to_rational()?;
        let b = other.to_rational()?;
        let result = a
            .checked_mul(&b)
            .ok_or_else(|| "integer overflow in multiplication".to_string())?;

        Self::from_rational(result)
    }

    pub fn divide(&self, other: &Self) -> Result<Self, String> {
        if !self.is_numeric() || !other.is_numeric() {
            return Err(format!(
                "cannot divide {} and {}",
                self.type_name(),
                other.type_name()
            ));
        }

        let a = self.to_rational()?;
        let b = other.to_rational()?;

        if b.is_zero() {
            return Err("division by zero".to_string());
        }

        let result = a
            .checked_div(&b)
            .ok_or_else(|| "integer overflow in division".to_string())?;

        Self::from_rational(result)
    }

    pub fn compare(&self, other: &Self) -> Result<Ordering, String> {
        if !self.is_numeric() || !other.is_numeric() {
            return Err(format!(
                "cannot compare {} and {}",
                self.type_name(),
                other.type_name()
            ));
        }

        let a = self.to_rational()?;
        let b = other.to_rational()?;

        Ok(a.cmp(&b))
    }

    // Helper to construct from Rational64 (normalized to lowest terms)
    fn from_rational(rat: Rational64) -> Result<Self, String> {
        // Rational64 automatically normalizes to lowest terms
        if rat.is_integer() {
            // Return as Int if it's a whole number
            Ok(ExactValue::Int {
                value: rat.numer().to_string(),
            })
        } else {
            Ok(ExactValue::Rational {
                numerator: rat.numer().to_string(),
                denominator: rat.denom().to_string(),
            })
        }
    }

    /// Normalize rational values to lowest terms.
    /// This is the ONLY normalization applied in v0.
    pub fn normalize(&self) -> Result<Self, String> {
        match self {
            ExactValue::Rational { .. } => {
                let rat = self.to_rational()?;
                Self::from_rational(rat)
            }
            _ => Ok(self.clone()),
        }
    }
}

/// Exact quantity with unit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExactQuantity {
    pub value: ExactValue,
    pub unit: String,
}

impl ExactQuantity {
    pub fn new(value: ExactValue, unit: impl Into<String>) -> Self {
        ExactQuantity {
            value,
            unit: unit.into(),
        }
    }

    pub fn unitless(value: ExactValue) -> Self {
        ExactQuantity {
            value,
            unit: String::new(),
        }
    }

    pub fn has_unit(&self) -> bool {
        !self.unit.is_empty()
    }

    /// Check if two quantities have compatible units.
    /// Units are compatible if they are exactly equal strings.
    pub fn ensure_compatible(&self, other: &Self) -> Result<(), String> {
        if self.unit != other.unit {
            Err(format!("unit mismatch: {} vs {}", self.unit, other.unit))
        } else {
            Ok(())
        }
    }

    pub fn add(&self, other: &Self) -> Result<Self, String> {
        self.ensure_compatible(other)?;
        let result_value = self.value.add(&other.value)?;
        Ok(ExactQuantity {
            value: result_value,
            unit: self.unit.clone(),
        })
    }

    pub fn subtract(&self, other: &Self) -> Result<Self, String> {
        self.ensure_compatible(other)?;
        let result_value = self.value.subtract(&other.value)?;
        Ok(ExactQuantity {
            value: result_value,
            unit: self.unit.clone(),
        })
    }

    /// Multiply following v0 strict rules:
    /// - If one operand is unitless, result carries the other's unit
    /// - If both have non-empty units → error (no compound units in v0)
    pub fn multiply(&self, other: &Self) -> Result<Self, String> {
        let result_value = self.value.multiply(&other.value)?;

        let result_unit = match (self.has_unit(), other.has_unit()) {
            (false, false) => String::new(),
            (true, false) => self.unit.clone(),
            (false, true) => other.unit.clone(),
            (true, true) => {
                return Err(format!(
                    "cannot multiply quantities with units {} and {} (no compound units in v0)",
                    self.unit, other.unit
                ))
            }
        };

        Ok(ExactQuantity {
            value: result_value,
            unit: result_unit,
        })
    }

    /// Divide following v0 strict rules:
    /// - If one operand is unitless, result carries the other's unit (for numerator)
    /// - If both have non-empty units → error (no compound units in v0)
    pub fn divide(&self, other: &Self) -> Result<Self, String> {
        let result_value = self.value.divide(&other.value)?;

        let result_unit = match (self.has_unit(), other.has_unit()) {
            (false, false) => String::new(),
            (true, false) => self.unit.clone(),
            (false, true) => {
                return Err(format!(
                    "cannot divide unitless by quantity with unit {} (no compound units in v0)",
                    other.unit
                ))
            }
            (true, true) => {
                return Err(format!(
                    "cannot divide quantities with units {} and {} (no compound units in v0)",
                    self.unit, other.unit
                ))
            }
        };

        Ok(ExactQuantity {
            value: result_value,
            unit: result_unit,
        })
    }

    pub fn compare(&self, other: &Self) -> Result<Ordering, String> {
        // Allow comparison if both are unitless OR units match exactly
        if self.has_unit() || other.has_unit() {
            self.ensure_compatible(other)?;
        }
        self.value.compare(&other.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_arithmetic() {
        let a = ExactValue::int(5);
        let b = ExactValue::int(3);

        assert_eq!(a.add(&b).unwrap(), ExactValue::int(8));
        assert_eq!(a.subtract(&b).unwrap(), ExactValue::int(2));
        assert_eq!(a.multiply(&b).unwrap(), ExactValue::int(15));
    }

    #[test]
    fn test_rational_arithmetic() {
        let a = ExactValue::rational(1, 2).unwrap();
        let b = ExactValue::rational(1, 3).unwrap();

        let sum = a.add(&b).unwrap();
        // 1/2 + 1/3 = 5/6
        assert_eq!(
            sum,
            ExactValue::Rational {
                numerator: "5".to_string(),
                denominator: "6".to_string()
            }
        );
    }

    #[test]
    fn test_rational_normalization() {
        let r = ExactValue::Rational {
            numerator: "4".to_string(),
            denominator: "6".to_string(),
        };
        let normalized = r.normalize().unwrap();
        // 4/6 normalizes to 2/3
        assert_eq!(
            normalized,
            ExactValue::Rational {
                numerator: "2".to_string(),
                denominator: "3".to_string()
            }
        );
    }

    #[test]
    fn test_rational_to_int() {
        let r = ExactValue::rational(6, 3).unwrap();
        // 6/3 = 2, should normalize to int
        assert_eq!(r, ExactValue::int(2));
    }

    #[test]
    fn test_division_by_zero() {
        let a = ExactValue::int(5);
        let b = ExactValue::int(0);
        assert!(a.divide(&b).is_err());
    }

    #[test]
    fn test_quantity_unit_compatibility() {
        let a = ExactQuantity::new(ExactValue::int(5), "hours");
        let b = ExactQuantity::new(ExactValue::int(3), "hours");
        let c = ExactQuantity::new(ExactValue::int(2), "dollars");

        assert!(a.add(&b).is_ok());
        assert!(a.add(&c).is_err());
    }

    #[test]
    fn test_quantity_multiply_unitless() {
        let a = ExactQuantity::new(ExactValue::int(5), "hours");
        let b = ExactQuantity::unitless(ExactValue::int(3));

        let result = a.multiply(&b).unwrap();
        assert_eq!(result.value, ExactValue::int(15));
        assert_eq!(result.unit, "hours");
    }

    #[test]
    fn test_quantity_multiply_both_units_error() {
        let a = ExactQuantity::new(ExactValue::int(5), "hours");
        let b = ExactQuantity::new(ExactValue::int(3), "dollars");

        assert!(a.multiply(&b).is_err());
    }

    #[test]
    fn test_quantity_compare() {
        let a = ExactQuantity::new(ExactValue::int(5), "hours");
        let b = ExactQuantity::new(ExactValue::int(3), "hours");

        assert_eq!(a.compare(&b).unwrap(), Ordering::Greater);
    }

    #[test]
    fn test_quantity_compare_unitless() {
        let a = ExactQuantity::unitless(ExactValue::int(5));
        let b = ExactQuantity::unitless(ExactValue::int(3));

        assert_eq!(a.compare(&b).unwrap(), Ordering::Greater);
    }
}
