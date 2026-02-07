use crate::error::EvalError;
use crate::identity_witness::{
    compute_delegation_record_id, is_valid_scope_id, normalize_scope_ids, validate_utc_timestamp,
    DelegationRecord, IdentityMetadata, IdentityOperation, IdentityVerdict, IdentityWitness,
};

#[derive(Debug, Clone)]
pub struct DelegateIssueInput {
    pub issuer_id: String,
    pub delegate_id: String,
    pub scope_ids: Vec<String>,
    pub issued_at_utc: String,
    pub expires_at_utc: Option<String>,
    pub constraints: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct VerifyDelegationInput {
    pub record: DelegationRecord,
    pub required_scope: String,
    pub at_utc: String,
    pub expected_delegate_id: Option<String>,
}

pub fn delegate_issue(
    input: DelegateIssueInput,
    created_at_utc: String,
    metadata: Option<IdentityMetadata>,
) -> Result<(DelegationRecord, IdentityWitness), EvalError> {
    if input.issuer_id.trim().is_empty() {
        return Err(EvalError("issuer_id must not be empty".into()));
    }
    if input.delegate_id.trim().is_empty() {
        return Err(EvalError("delegate_id must not be empty".into()));
    }
    if input.scope_ids.is_empty() {
        return Err(EvalError("scope_ids must not be empty".into()));
    }
    validate_utc_timestamp(&input.issued_at_utc, "issued_at_utc")?;
    if let Some(expires) = input.expires_at_utc.as_ref() {
        validate_utc_timestamp(expires, "expires_at_utc")?;
        if expires < &input.issued_at_utc {
            return Err(EvalError(
                "expires_at_utc must be >= issued_at_utc".to_string(),
            ));
        }
    }
    let scope_ids = normalize_scope_ids(input.scope_ids);
    for scope in &scope_ids {
        if !is_valid_scope_id(scope) {
            return Err(EvalError(format!("invalid scope_id: {}", scope)));
        }
    }

    let record_id = compute_delegation_record_id(
        &input.issuer_id,
        &input.delegate_id,
        &scope_ids,
        &input.issued_at_utc,
        input.expires_at_utc.clone(),
        input.constraints.clone(),
    )?;

    let record = DelegationRecord {
        record_id: record_id.clone(),
        issuer_id: input.issuer_id,
        delegate_id: input.delegate_id,
        scope_ids,
        issued_at_utc: input.issued_at_utc,
        expires_at_utc: input.expires_at_utc,
        constraints: input.constraints,
    };
    record.validate()?;

    let witness = IdentityWitness {
        schema_id: "identity-witness/0".to_string(),
        schema_version: 0,
        operation: IdentityOperation::DelegateIssue,
        record_id,
        required_scope: None,
        at_utc: None,
        verdict: IdentityVerdict::Issued,
        created_at_utc,
        metadata,
    };
    witness.validate()?;

    Ok((record, witness))
}

pub fn verify_delegation(
    input: VerifyDelegationInput,
    created_at_utc: String,
    metadata: Option<IdentityMetadata>,
) -> Result<IdentityWitness, EvalError> {
    let VerifyDelegationInput {
        record,
        required_scope,
        at_utc,
        expected_delegate_id,
    } = input;
    record.validate()?;
    if !is_valid_scope_id(&required_scope) {
        return Err(EvalError(format!("invalid required_scope: {}", required_scope)));
    }
    validate_utc_timestamp(&at_utc, "at_utc")?;

    let verdict = if let Some(expected_delegate_id) = expected_delegate_id.as_ref() {
        if expected_delegate_id != &record.delegate_id {
            IdentityVerdict::Invalid {
                reason: "delegate_id_mismatch".to_string(),
            }
        } else if !record.scope_ids.iter().any(|scope| scope == &required_scope) {
            IdentityVerdict::Invalid {
                reason: "scope_not_delegated".to_string(),
            }
        } else if at_utc < record.issued_at_utc {
            IdentityVerdict::Invalid {
                reason: "verification_before_issue_time".to_string(),
            }
        } else if record
            .expires_at_utc
            .as_ref()
            .is_some_and(|expires| &at_utc > expires)
        {
            IdentityVerdict::Invalid {
                reason: "delegation_expired".to_string(),
            }
        } else {
            IdentityVerdict::Valid
        }
    } else if !record.scope_ids.iter().any(|scope| scope == &required_scope) {
        IdentityVerdict::Invalid {
            reason: "scope_not_delegated".to_string(),
        }
    } else if at_utc < record.issued_at_utc {
        IdentityVerdict::Invalid {
            reason: "verification_before_issue_time".to_string(),
        }
    } else if record
        .expires_at_utc
        .as_ref()
        .is_some_and(|expires| &at_utc > expires)
    {
        IdentityVerdict::Invalid {
            reason: "delegation_expired".to_string(),
        }
    } else {
        IdentityVerdict::Valid
    };

    let witness = IdentityWitness {
        schema_id: "identity-witness/0".to_string(),
        schema_version: 0,
        operation: IdentityOperation::VerifyDelegation,
        record_id: record.record_id.clone(),
        required_scope: Some(required_scope),
        at_utc: Some(at_utc),
        verdict,
        created_at_utc,
        metadata,
    };
    witness.validate()?;
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_witness::IdentityVerdict;

    #[test]
    fn delegate_issue_normalizes_scope_ids() {
        let (record, witness) = delegate_issue(
            DelegateIssueInput {
                issuer_id: "issuer".to_string(),
                delegate_id: "delegate".to_string(),
                scope_ids: vec![
                    "scope:b".to_string(),
                    "scope:a".to_string(),
                    "scope:a".to_string(),
                ],
                issued_at_utc: "2026-02-07T00:00:00Z".to_string(),
                expires_at_utc: None,
                constraints: None,
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap();
        assert_eq!(
            record.scope_ids,
            vec!["scope:a".to_string(), "scope:b".to_string()]
        );
        assert!(matches!(witness.verdict, IdentityVerdict::Issued));
    }

    #[test]
    fn verify_delegation_happy_path() {
        let (record, _) = delegate_issue(
            DelegateIssueInput {
                issuer_id: "issuer".to_string(),
                delegate_id: "delegate".to_string(),
                scope_ids: vec!["scope:hash.verify".to_string()],
                issued_at_utc: "2026-02-07T00:00:00Z".to_string(),
                expires_at_utc: Some("2026-02-08T00:00:00Z".to_string()),
                constraints: None,
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap();
        let witness = verify_delegation(
            VerifyDelegationInput {
                record,
                required_scope: "scope:hash.verify".to_string(),
                at_utc: "2026-02-07T12:00:00Z".to_string(),
                expected_delegate_id: Some("delegate".to_string()),
            },
            "2026-02-07T12:00:01Z".to_string(),
            None,
        )
        .unwrap();
        assert!(matches!(witness.verdict, IdentityVerdict::Valid));
    }

    #[test]
    fn verify_delegation_rejects_expired() {
        let (record, _) = delegate_issue(
            DelegateIssueInput {
                issuer_id: "issuer".to_string(),
                delegate_id: "delegate".to_string(),
                scope_ids: vec!["scope:hash.verify".to_string()],
                issued_at_utc: "2026-02-07T00:00:00Z".to_string(),
                expires_at_utc: Some("2026-02-07T01:00:00Z".to_string()),
                constraints: None,
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap();
        let witness = verify_delegation(
            VerifyDelegationInput {
                record,
                required_scope: "scope:hash.verify".to_string(),
                at_utc: "2026-02-07T12:00:00Z".to_string(),
                expected_delegate_id: None,
            },
            "2026-02-07T12:00:01Z".to_string(),
            None,
        )
        .unwrap();
        assert_eq!(
            witness.verdict,
            IdentityVerdict::Invalid {
                reason: "delegation_expired".to_string()
            }
        );
    }
}

