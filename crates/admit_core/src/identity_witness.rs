use crate::cbor::encode_canonical_value;
use crate::error::EvalError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub record_id: String,
    pub issuer_id: String,
    pub delegate_id: String,
    pub scope_ids: Vec<String>,
    pub issued_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityOperation {
    DelegateIssue,
    VerifyDelegation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IdentityVerdict {
    Issued,
    Valid,
    Invalid { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityWitness {
    pub schema_id: String,
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub court_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    pub operation: IdentityOperation,
    pub record_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_utc: Option<String>,
    pub verdict: IdentityVerdict,
    pub created_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IdentityMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DelegationRecordIdPayload<'a> {
    issuer_id: &'a str,
    delegate_id: &'a str,
    scope_ids: &'a [String],
    issued_at_utc: &'a str,
    expires_at_utc: &'a Option<String>,
    constraints: &'a Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IdentityWitnessIdPayload<'a> {
    schema_id: &'a str,
    schema_version: u32,
    operation: &'a IdentityOperation,
    record_id: &'a str,
    required_scope: &'a Option<String>,
    at_utc: &'a Option<String>,
    verdict: &'a IdentityVerdict,
}

impl DelegationRecord {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.issuer_id.trim().is_empty() {
            return Err(EvalError("issuer_id must not be empty".into()));
        }
        if self.delegate_id.trim().is_empty() {
            return Err(EvalError("delegate_id must not be empty".into()));
        }
        if self.scope_ids.is_empty() {
            return Err(EvalError("scope_ids must not be empty".into()));
        }
        if !self.scope_ids.windows(2).all(|w| w[0] < w[1]) {
            return Err(EvalError(
                "scope_ids must be sorted ascending and unique".into(),
            ));
        }
        for scope_id in &self.scope_ids {
            if !is_valid_scope_id(scope_id) {
                return Err(EvalError(format!("invalid scope_id: {}", scope_id)));
            }
        }
        validate_utc_timestamp(&self.issued_at_utc, "issued_at_utc")?;
        if let Some(expires) = self.expires_at_utc.as_ref() {
            validate_utc_timestamp(expires, "expires_at_utc")?;
            if expires < &self.issued_at_utc {
                return Err(EvalError(
                    "expires_at_utc must be >= issued_at_utc".to_string(),
                ));
            }
        }
        if !is_valid_sha256_hex(&self.record_id) {
            return Err(EvalError("record_id must be 64-char lowercase hex".into()));
        }
        let expected = compute_delegation_record_id(
            &self.issuer_id,
            &self.delegate_id,
            &self.scope_ids,
            &self.issued_at_utc,
            self.expires_at_utc.clone(),
            self.constraints.clone(),
        )?;
        if expected != self.record_id {
            return Err(EvalError(format!(
                "record_id mismatch: expected {}, got {}",
                expected, self.record_id
            )));
        }
        Ok(())
    }
}

impl IdentityWitness {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.schema_id != "identity-witness/0" {
            return Err(EvalError(format!(
                "unsupported schema_id: {}",
                self.schema_id
            )));
        }
        if self.schema_version != 0 {
            return Err(EvalError(format!(
                "unsupported schema_version: {}",
                self.schema_version
            )));
        }
        if !is_valid_sha256_hex(&self.record_id) {
            return Err(EvalError("record_id must be 64-char lowercase hex".into()));
        }
        validate_utc_timestamp(&self.created_at_utc, "created_at_utc")?;
        match self.operation {
            IdentityOperation::DelegateIssue => {
                if self.required_scope.is_some() || self.at_utc.is_some() {
                    return Err(EvalError(
                        "delegate_issue witness must not include verification context".into(),
                    ));
                }
                if !matches!(self.verdict, IdentityVerdict::Issued) {
                    return Err(EvalError(
                        "delegate_issue witness verdict must be issued".into(),
                    ));
                }
            }
            IdentityOperation::VerifyDelegation => {
                let required_scope = self
                    .required_scope
                    .as_ref()
                    .ok_or_else(|| EvalError("verify witness missing required_scope".into()))?;
                if !is_valid_scope_id(required_scope) {
                    return Err(EvalError(format!(
                        "verify witness invalid required_scope: {}",
                        required_scope
                    )));
                }
                let at_utc = self
                    .at_utc
                    .as_ref()
                    .ok_or_else(|| EvalError("verify witness missing at_utc".into()))?;
                validate_utc_timestamp(at_utc, "at_utc")?;
                if matches!(self.verdict, IdentityVerdict::Issued) {
                    return Err(EvalError(
                        "verify witness verdict must be valid or invalid".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub fn compute_delegation_record_id(
    issuer_id: &str,
    delegate_id: &str,
    scope_ids: &[String],
    issued_at_utc: &str,
    expires_at_utc: Option<String>,
    constraints: Option<serde_json::Value>,
) -> Result<String, EvalError> {
    let payload = DelegationRecordIdPayload {
        issuer_id,
        delegate_id,
        scope_ids,
        issued_at_utc,
        expires_at_utc: &expires_at_utc,
        constraints: &constraints,
    };
    let value = serde_json::to_value(&payload)
        .map_err(|e| EvalError(format!("serialize payload: {}", e)))?;
    let bytes = encode_canonical_value(&value)?;
    Ok(sha256_hex(&bytes))
}

pub fn encode_delegation_record(record: &DelegationRecord) -> Result<Vec<u8>, EvalError> {
    let value =
        serde_json::to_value(record).map_err(|e| EvalError(format!("serialize record: {}", e)))?;
    encode_canonical_value(&value)
}

pub fn compute_identity_witness_id(witness: &IdentityWitness) -> Result<String, EvalError> {
    let payload = IdentityWitnessIdPayload {
        schema_id: &witness.schema_id,
        schema_version: witness.schema_version,
        operation: &witness.operation,
        record_id: &witness.record_id,
        required_scope: &witness.required_scope,
        at_utc: &witness.at_utc,
        verdict: &witness.verdict,
    };
    let value = serde_json::to_value(&payload)
        .map_err(|e| EvalError(format!("serialize witness id payload: {}", e)))?;
    let bytes = encode_canonical_value(&value)?;
    Ok(sha256_hex(&bytes))
}

pub fn encode_identity_witness(witness: &IdentityWitness) -> Result<Vec<u8>, EvalError> {
    let value = serde_json::to_value(witness)
        .map_err(|e| EvalError(format!("serialize witness: {}", e)))?;
    encode_canonical_value(&value)
}

pub(crate) fn normalize_scope_ids(mut scope_ids: Vec<String>) -> Vec<String> {
    scope_ids.sort();
    scope_ids.dedup();
    scope_ids
}

pub(crate) fn is_valid_scope_id(scope_id: &str) -> bool {
    scope_id.starts_with("scope:") && scope_id.len() > "scope:".len()
}

pub(crate) fn validate_utc_timestamp(ts: &str, field: &str) -> Result<(), EvalError> {
    if ts.len() < 20 || !ts.contains('T') || !ts.ends_with('Z') {
        return Err(EvalError(format!(
            "{} must be ISO-8601 UTC (example: 2026-02-07T00:00:00Z)",
            field
        )));
    }
    Ok(())
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_id_is_order_insensitive_when_scope_ids_are_normalized() {
        let a = normalize_scope_ids(vec![
            "scope:b".to_string(),
            "scope:a".to_string(),
            "scope:a".to_string(),
        ]);
        let b = normalize_scope_ids(vec!["scope:a".to_string(), "scope:b".to_string()]);
        let id_a = compute_delegation_record_id(
            "issuer",
            "delegate",
            &a,
            "2026-02-07T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let id_b = compute_delegation_record_id(
            "issuer",
            "delegate",
            &b,
            "2026-02-07T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn witness_id_excludes_created_at_and_metadata() {
        let mut witness = IdentityWitness {
            schema_id: "identity-witness/0".to_string(),
            schema_version: 0,
            court_version: None,
            input_id: None,
            config_hash: None,
            operation: IdentityOperation::VerifyDelegation,
            record_id: "a".repeat(64),
            required_scope: Some("scope:test".to_string()),
            at_utc: Some("2026-02-07T12:00:00Z".to_string()),
            verdict: IdentityVerdict::Valid,
            created_at_utc: "2026-02-07T12:00:00Z".to_string(),
            metadata: None,
        };
        let id1 = compute_identity_witness_id(&witness).unwrap();
        witness.created_at_utc = "2026-02-07T23:59:59Z".to_string();
        witness.metadata = Some(IdentityMetadata {
            source_ref: Some("x".to_string()),
            purpose: Some("y".to_string()),
        });
        let id2 = compute_identity_witness_id(&witness).unwrap();
        assert_eq!(id1, id2);
    }
}
