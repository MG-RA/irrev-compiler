use admit_core::{
    compute_identity_witness_id, delegate_issue, encode_delegation_record, encode_identity_witness,
    verify_delegation, DelegateIssueInput, IdentityMetadata, IdentityVerdict,
    VerifyDelegationInput,
};

#[test]
fn delegation_record_and_witness_are_canonical_bytes() {
    let (record, issue_witness) = delegate_issue(
        DelegateIssueInput {
            issuer_id: "issuer:ops".to_string(),
            delegate_id: "agent:buildbot".to_string(),
            scope_ids: vec![
                "scope:hash.verify".to_string(),
                "scope:patch.plan".to_string(),
            ],
            issued_at_utc: "2026-02-07T00:00:00Z".to_string(),
            expires_at_utc: Some("2026-02-08T00:00:00Z".to_string()),
            constraints: Some(serde_json::json!({"max_actions": 10})),
        },
        "2026-02-07T00:00:01Z".to_string(),
        Some(IdentityMetadata {
            source_ref: Some("plan:abc".to_string()),
            purpose: Some("bootstrap".to_string()),
        }),
    )
    .unwrap();

    let record_bytes = encode_delegation_record(&record).unwrap();
    let witness_bytes = encode_identity_witness(&issue_witness).unwrap();

    assert!(!record_bytes.is_empty());
    assert!(!witness_bytes.is_empty());
    assert_eq!(record.record_id.len(), 64);
}

#[test]
fn verify_delegation_emits_valid_and_invalid_verdicts() {
    let (record, _) = delegate_issue(
        DelegateIssueInput {
            issuer_id: "issuer:ops".to_string(),
            delegate_id: "agent:buildbot".to_string(),
            scope_ids: vec!["scope:hash.verify".to_string()],
            issued_at_utc: "2026-02-07T00:00:00Z".to_string(),
            expires_at_utc: Some("2026-02-08T00:00:00Z".to_string()),
            constraints: None,
        },
        "2026-02-07T00:00:01Z".to_string(),
        None,
    )
    .unwrap();

    let valid = verify_delegation(
        VerifyDelegationInput {
            record: record.clone(),
            required_scope: "scope:hash.verify".to_string(),
            at_utc: "2026-02-07T12:00:00Z".to_string(),
            expected_delegate_id: Some("agent:buildbot".to_string()),
        },
        "2026-02-07T12:00:01Z".to_string(),
        None,
    )
    .unwrap();
    assert!(matches!(valid.verdict, IdentityVerdict::Valid));

    let invalid = verify_delegation(
        VerifyDelegationInput {
            record,
            required_scope: "scope:patch.plan".to_string(),
            at_utc: "2026-02-07T12:00:00Z".to_string(),
            expected_delegate_id: Some("agent:buildbot".to_string()),
        },
        "2026-02-07T12:00:01Z".to_string(),
        None,
    )
    .unwrap();
    assert_eq!(
        invalid.verdict,
        IdentityVerdict::Invalid {
            reason: "scope_not_delegated".to_string()
        }
    );
}

#[test]
fn identity_witness_id_is_stable_across_metadata_changes() {
    let (record, _) = delegate_issue(
        DelegateIssueInput {
            issuer_id: "issuer:ops".to_string(),
            delegate_id: "agent:buildbot".to_string(),
            scope_ids: vec!["scope:hash.verify".to_string()],
            issued_at_utc: "2026-02-07T00:00:00Z".to_string(),
            expires_at_utc: None,
            constraints: None,
        },
        "2026-02-07T00:00:00Z".to_string(),
        None,
    )
    .unwrap();

    let a = verify_delegation(
        VerifyDelegationInput {
            record: record.clone(),
            required_scope: "scope:hash.verify".to_string(),
            at_utc: "2026-02-07T12:00:00Z".to_string(),
            expected_delegate_id: None,
        },
        "2026-02-07T12:00:00Z".to_string(),
        None,
    )
    .unwrap();
    let b = verify_delegation(
        VerifyDelegationInput {
            record,
            required_scope: "scope:hash.verify".to_string(),
            at_utc: "2026-02-07T12:00:00Z".to_string(),
            expected_delegate_id: None,
        },
        "2026-02-07T23:59:59Z".to_string(),
        Some(IdentityMetadata {
            source_ref: Some("run:xyz".to_string()),
            purpose: Some("audit".to_string()),
        }),
    )
    .unwrap();
    let id_a = compute_identity_witness_id(&a).unwrap();
    let id_b = compute_identity_witness_id(&b).unwrap();
    assert_eq!(id_a, id_b);
}
