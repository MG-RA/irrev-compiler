//! Canonical CBOR encoding implementation
//!
//! This module implements `scope:encode.canonical@0` - a foundational
//! scope providing RFC 8949 canonical CBOR encoding for witness identity
//! computation and content-addressable serialization.
//!
//! **Contract**: meta/encode-canonical-scope-contract.md
//! **Fixtures**: tests/encode_canonical_fixtures.rs
//! **Registry**: out/meta-registry.json (scope:encode.canonical@0)
//!
//! All witness identities in the Irreversibility compiler depend on
//! canonical encoding: `witness_id = sha256(canonical_cbor(payload))`

#![allow(dead_code)]

const FRACTION_TOLERANCE: f64 = 1.0e-9;

use std::cmp::Ordering;

use crate::error::EvalError;
use crate::witness::Witness;
use serde_json::Value;

pub fn encode_canonical(witness: &Witness) -> Result<Vec<u8>, EvalError> {
    let value = serde_json::to_value(witness)
        .map_err(|err| EvalError(format!("serialize JSON: {}", err)))?;
    let mut buf = Vec::new();
    encode_value(&value, &mut buf)?;
    Ok(buf)
}

pub fn encode_canonical_value(value: &serde_json::Value) -> Result<Vec<u8>, EvalError> {
    let mut buf = Vec::new();
    encode_value(value, &mut buf)?;
    Ok(buf)
}

fn encode_value(value: &Value, buf: &mut Vec<u8>) -> Result<(), EvalError> {
    match value {
        Value::Null => {
            buf.push(0xf6);
        }
        Value::Bool(true) => {
            buf.push(0xf5);
        }
        Value::Bool(false) => {
            buf.push(0xf4);
        }
        Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                encode_major(0, u, buf);
            } else if let Some(i) = num.as_i64() {
                if i >= 0 {
                    encode_major(0, i as u64, buf);
                } else {
                    let encoded = (-1 - i) as u64;
                    encode_major(1, encoded, buf);
                }
            } else if let Some(f) = num.as_f64() {
                if !f.is_finite() {
                    return Err(EvalError("floats not allowed in canonical CBOR".into()));
                }
                if (f.fract().abs()) > FRACTION_TOLERANCE {
                    return Err(EvalError("floats not allowed in canonical CBOR".into()));
                }
                if f >= 0.0 {
                    encode_major(0, f as u64, buf);
                } else {
                    let i = f as i64;
                    let encoded = (-1 - i) as u64;
                    encode_major(1, encoded, buf);
                }
            } else {
                return Err(EvalError("floats not allowed in canonical CBOR".into()));
            }
        }
        Value::String(s) => {
            encode_major(3, s.len() as u64, buf);
            buf.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            encode_major(4, items.len() as u64, buf);
            for item in items {
                encode_value(item, buf)?;
            }
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| {
                let len_cmp = a.len().cmp(&b.len());
                if len_cmp == Ordering::Equal {
                    a.as_bytes().cmp(b.as_bytes())
                } else {
                    len_cmp
                }
            });
            encode_major(5, entries.len() as u64, buf);
            for (key, value) in entries {
                encode_major(3, key.len() as u64, buf);
                buf.extend_from_slice(key.as_bytes());
                encode_value(value, buf)?;
            }
        }
    }
    Ok(())
}

fn encode_major(major: u8, value: u64, buf: &mut Vec<u8>) {
    if value <= 23 {
        buf.push((major << 5) | value as u8);
    } else if value < 256 {
        buf.push((major << 5) | 24);
        buf.push(value as u8);
    } else if value < 65536 {
        buf.push((major << 5) | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 4294967296 {
        buf.push((major << 5) | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | 27);
        buf.extend_from_slice(&(value as u64).to_be_bytes());
    }
}
