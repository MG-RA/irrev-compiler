#[cfg(test)]
mod tests {
    use crate::*;
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf};

    fn base_span() -> Span {
        Span {
            file: "test.adm".to_string(),
            start: Some(0),
            end: Some(0),
            line: Some(1),
            col: Some(1),
        }
    }

    fn symbol(ns: SymbolNamespace, name: &str) -> SymbolRef {
        SymbolRef {
            ns,
            name: name.to_string(),
        }
    }

    #[test]
    fn serde_round_trip_program() {
        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![Stmt::DeclareDifference {
                diff: symbol(SymbolNamespace::Difference, "crew_fatigue"),
                unit: Some("risk_points".to_string()),
                span: base_span(),
            }],
        };

        let json = serde_json::to_string(&program).expect("serialize program");
        let decoded: Program = serde_json::from_str(&json).expect("deserialize program");
        assert_eq!(program, decoded);
    }

    #[test]
    fn predicate_serde_roundtrip_provider_predicate() {
        let pred = Predicate::ProviderPredicate {
            scope_id: ScopeId("obsidian".into()),
            name: "vault_rule".into(),
            params: serde_json::json!({ "rule_id": "broken-link" }),
        };
        let json = serde_json::to_string(&pred).expect("serialize");
        let decoded: Predicate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pred, decoded);
    }

    #[test]
    fn allow_erasure_triggers_inadmissible() {
        let witness = allow_erasure_witness();
        assert_eq!(witness.verdict, Verdict::Inadmissible);
    }

    #[test]
    fn golden_allow_erasure_witness_matches_fixture() {
        let witness = allow_erasure_witness();
        let actual_json =
            serde_json::to_string_pretty(&witness).expect("serialize witness to JSON");
        let expected_json = fs::read_to_string(golden_fixture_path("allow-erasure-trigger.json"))
            .expect("read golden JSON");
        let expected_json = expected_json.trim_end_matches(|c| c == '\n' || c == '\r');
        assert_eq!(actual_json, expected_json);

        let actual_hash = canonical_hash(&witness).expect("hash canonical witness");
        let expected_hash =
            fs::read_to_string(golden_fixture_path("allow-erasure-trigger.cbor.sha256"))
                .expect("read golden hash")
                .trim()
                .to_string();
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn admissibility_witness_v2_hash_is_pinned() {
        let witness = allow_erasure_witness();
        let actual_hash = canonical_hash(&witness).expect("hash canonical witness");
        assert_eq!(
            actual_hash,
            "4b09904735046be2aebab585bc974fba206f25e78600d03481b505313fa67055",
            "admissibility-witness/2 canonical hash changed - update pin intentionally if schema changes"
        );
    }

    #[test]
    fn golden_scope_widen_unaccounted_matches_fixture() {
        let witness = scope_widen_unaccounted_witness();
        assert_eq!(witness.verdict, Verdict::Inadmissible);

        let actual_json =
            serde_json::to_string_pretty(&witness).expect("serialize witness to JSON");
        let expected_json = fs::read_to_string(golden_fixture_path("scope-widen-unaccounted.json"))
            .expect("read golden JSON");
        let expected_json = expected_json.trim_end_matches(|c| c == '\n' || c == '\r');
        assert_eq!(actual_json, expected_json);

        let actual_hash = canonical_hash(&witness).expect("hash canonical witness");
        let expected_hash =
            fs::read_to_string(golden_fixture_path("scope-widen-unaccounted.cbor.sha256"))
                .expect("read golden hash")
                .trim()
                .to_string();
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn golden_scope_widen_accounted_matches_fixture() {
        let witness = scope_widen_accounted_witness();
        assert_eq!(witness.verdict, Verdict::Admissible);

        let actual_json =
            serde_json::to_string_pretty(&witness).expect("serialize witness to JSON");
        let expected_json = fs::read_to_string(golden_fixture_path("scope-widen-accounted.json"))
            .expect("read golden JSON");
        let expected_json = expected_json.trim_end_matches(|c| c == '\n' || c == '\r');
        assert_eq!(actual_json, expected_json);

        let actual_hash = canonical_hash(&witness).expect("hash canonical witness");
        let expected_hash =
            fs::read_to_string(golden_fixture_path("scope-widen-accounted.cbor.sha256"))
                .expect("read golden hash")
                .trim()
                .to_string();
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn golden_two_scope_changes_are_deterministic() {
        let witness = two_scope_changes_accounted_witness();
        assert_eq!(witness.verdict, Verdict::Admissible);

        let actual_json =
            serde_json::to_string_pretty(&witness).expect("serialize witness to JSON");
        let expected_json =
            fs::read_to_string(golden_fixture_path("scope-two-changes-accounted.json"))
                .expect("read golden JSON");
        let expected_json = expected_json.trim_end_matches(|c| c == '\n' || c == '\r');
        assert_eq!(actual_json, expected_json);

        let actual_hash = canonical_hash(&witness).expect("hash canonical witness");
        let expected_hash = fs::read_to_string(golden_fixture_path(
            "scope-two-changes-accounted.cbor.sha256",
        ))
        .expect("read golden hash")
        .trim()
        .to_string();
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn deny_erasure_allows_admissible() {
        let diff = symbol(SymbolNamespace::Difference, "crew_fatigue");
        let bucket = symbol(SymbolNamespace::Bucket, "safety_risk");

        let constraint = Stmt::Constraint {
            id: Some(symbol(SymbolNamespace::Constraint, "over_limit")),
            expr: BoolExpr::Pred {
                pred: Predicate::DisplacedTotal {
                    bucket: bucket.clone(),
                    op: CmpOp::Gt,
                    value: Quantity {
                        value: 3.0,
                        unit: "risk_points".to_string(),
                    },
                },
            },
            span: base_span(),
        };

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: Some("risk_points".to_string()),
                    span: base_span(),
                },
                Stmt::ErasureRule {
                    diff: diff.clone(),
                    cost: Quantity {
                        value: 8.0,
                        unit: "risk_points".to_string(),
                    },
                    displaced_to: bucket.clone(),
                    span: base_span(),
                },
                Stmt::DenyErase {
                    diff: diff.clone(),
                    span: base_span(),
                },
                constraint,
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        assert_eq!(witness.verdict, Verdict::Admissible);
    }

    #[test]
    fn allow_without_rule_errors() {
        let diff = symbol(SymbolNamespace::Difference, "crew_fatigue");

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: Some("risk_points".to_string()),
                    span: base_span(),
                },
                Stmt::AllowErase {
                    diff: diff.clone(),
                    span: base_span(),
                },
            ],
        };

        eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect_err("missing erasure rule");
    }

    #[test]
    fn commit_predicates_log_commit_usage() {
        let diff = symbol(SymbolNamespace::Difference, "crew_fatigue");

        let commit_value = Quantity {
            value: 5.0,
            unit: "risk_points".to_string(),
        };

        let constraint = Stmt::Constraint {
            id: None,
            expr: BoolExpr::Pred {
                pred: Predicate::CommitEquals {
                    diff: diff.clone(),
                    value: CommitValue::Quantity(commit_value.clone()),
                },
            },
            span: base_span(),
        };

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: Some("risk_points".to_string()),
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff.clone(),
                    value: CommitValue::Quantity(commit_value.clone()),
                    span: base_span(),
                },
                constraint,
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        assert!(witness.facts.iter().any(|fact| match fact {
            Fact::CommitUsed {
                diff: d,
                value: CommitValue::Quantity(q),
                ..
            } => {
                d == &diff && q.value == commit_value.value && q.unit == commit_value.unit
            }
            _ => false,
        }));
    }

    #[test]
    fn witness_builder_canonical_predicate_string_is_sorted() {
        let metadata = WitnessProgram {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: None,
            facts_bundle_hash: None,
            ruleset_hash: None,
        };

        let span_a = Span {
            file: "test.adm".to_string(),
            start: None,
            end: None,
            line: Some(1),
            col: Some(1),
        };

        let span_b = Span {
            file: "test.adm".to_string(),
            start: None,
            end: None,
            line: Some(2),
            col: Some(1),
        };

        let builder =
            WitnessBuilder::new(metadata, Verdict::Admissible, "sorted").with_facts(vec![
                Fact::PredicateEvaluated {
                    predicate: "predicate-b".to_string(),
                    result: true,
                    span: span_b.clone(),
                },
                Fact::PredicateEvaluated {
                    predicate: "predicate-a".to_string(),
                    result: false,
                    span: span_a.clone(),
                },
            ]);

        assert_eq!(
            builder.canonical_predicate_strings(),
            vec!["predicate-a".to_string(), "predicate-b".to_string()]
        );
        assert_eq!(
            builder.canonical_predicate_string(),
            "predicate-a\npredicate-b"
        );
    }

    #[test]
    fn witness_builder_sets_default_schema_id() {
        let metadata = WitnessProgram {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: None,
            facts_bundle_hash: None,
            ruleset_hash: None,
        };

        let witness = WitnessBuilder::new(metadata, Verdict::Admissible, "ok").build();
        assert_eq!(
            witness.schema_id.as_deref(),
            Some(DEFAULT_WITNESS_SCHEMA_ID)
        );
    }

    /// Run with `--ignored` to regenerate golden fixtures:
    /// `cargo test -p admit_core -- --ignored dump_scope_change_goldens`
    #[test]
    #[ignore]
    fn dump_scope_change_goldens() {
        let cases: Vec<(&str, Witness)> = vec![
            ("allow-erasure-trigger", allow_erasure_witness()),
            ("scope-widen-unaccounted", scope_widen_unaccounted_witness()),
            ("scope-widen-accounted", scope_widen_accounted_witness()),
            (
                "scope-two-changes-accounted",
                two_scope_changes_accounted_witness(),
            ),
        ];

        for (name, witness) in &cases {
            let json = serde_json::to_string_pretty(witness).unwrap();
            let hash = canonical_hash(witness).unwrap();
            fs::write(golden_fixture_path(&format!("{}.json", name)), &json).unwrap();
            fs::write(golden_fixture_path(&format!("{}.cbor.sha256", name)), &hash).unwrap();
            println!("WROTE {}: hash={}", name, hash);
        }
    }

    fn allow_erasure_program() -> Program {
        let diff = symbol(SymbolNamespace::Difference, "crew_fatigue");
        let bucket = symbol(SymbolNamespace::Bucket, "safety_risk");
        let constraint_id = symbol(SymbolNamespace::Constraint, "over_limit");

        let constraint = Stmt::Constraint {
            id: Some(constraint_id),
            expr: BoolExpr::Pred {
                pred: Predicate::DisplacedTotal {
                    bucket: bucket.clone(),
                    op: CmpOp::Gt,
                    value: Quantity {
                        value: 3.0,
                        unit: "risk_points".to_string(),
                    },
                },
            },
            span: base_span(),
        };

        Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: Some("risk_points".to_string()),
                    span: base_span(),
                },
                Stmt::ErasureRule {
                    diff: diff.clone(),
                    cost: Quantity {
                        value: 8.0,
                        unit: "risk_points".to_string(),
                    },
                    displaced_to: bucket.clone(),
                    span: base_span(),
                },
                Stmt::AllowErase {
                    diff: diff.clone(),
                    span: base_span(),
                },
                constraint,
            ],
        }
    }

    fn allow_erasure_witness() -> Witness {
        eval(
            &allow_erasure_program(),
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval")
    }

    fn golden_fixture_path(filename: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("testdata")
            .join("golden-witness")
            .join(filename)
    }

    fn canonical_hash(witness: &Witness) -> Result<String, EvalError> {
        let bytes = encode_canonical(witness)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn scope_span(line: u32) -> Span {
        Span {
            file: "scope-change.adm".to_string(),
            start: Some(0),
            end: Some(0),
            line: Some(line),
            col: Some(1),
        }
    }

    fn boundary_loss_diff(from: &ScopeId, to: &ScopeId) -> SymbolRef {
        crate::boundary_loss_diff(from, to)
    }

    fn scope_widen_unaccounted_program() -> Program {
        let from = ScopeId("scope:main".to_string());
        let to = ScopeId("scope:prod".to_string());

        Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![Stmt::ScopeChange {
                from: from.clone(),
                to: to.clone(),
                mode: ScopeMode::Widen,
                span: scope_span(1),
            }],
        }
    }

    fn scope_widen_unaccounted_witness() -> Witness {
        eval(
            &scope_widen_unaccounted_program(),
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval")
    }

    fn scope_widen_accounted_program() -> Program {
        let from = ScopeId("scope:main".to_string());
        let to = ScopeId("scope:prod".to_string());
        let bucket = symbol(SymbolNamespace::Bucket, "boundary_risk");
        let diff = boundary_loss_diff(&from, &to);

        Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![
                Stmt::AllowErase {
                    diff: diff.clone(),
                    span: scope_span(2),
                },
                Stmt::ErasureRule {
                    diff: diff.clone(),
                    cost: Quantity {
                        value: 1.0,
                        unit: "risk_points".to_string(),
                    },
                    displaced_to: bucket.clone(),
                    span: scope_span(3),
                },
                Stmt::ScopeChange {
                    from: from.clone(),
                    to: to.clone(),
                    mode: ScopeMode::Widen,
                    span: scope_span(1),
                },
            ],
        }
    }

    fn scope_widen_accounted_witness() -> Witness {
        eval(
            &scope_widen_accounted_program(),
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval")
    }

    #[test]
    fn scope_change_accounting_contributes_to_displacement_trace() {
        let from = ScopeId("scope:main".to_string());
        let to = ScopeId("scope:prod".to_string());
        let diff = boundary_loss_diff(&from, &to);

        let witness = scope_widen_accounted_witness();
        assert!(witness
            .displacement_trace
            .contributions
            .iter()
            .any(|c| c.diff == diff));
    }

    fn two_scope_changes_accounted_program() -> Program {
        let from_a = ScopeId("scope:main".to_string());
        let to_a = ScopeId("scope:prod".to_string());
        let from_b = ScopeId("scope:prod".to_string());
        let to_b = ScopeId("scope:main".to_string());

        let bucket = symbol(SymbolNamespace::Bucket, "boundary_risk");
        let diff_a = boundary_loss_diff(&from_a, &to_a);
        let diff_b = boundary_loss_diff(&from_b, &to_b);

        Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:main".to_string()),
            dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
            statements: vec![
                Stmt::AllowErase {
                    diff: diff_a.clone(),
                    span: scope_span(2),
                },
                Stmt::ErasureRule {
                    diff: diff_a.clone(),
                    cost: Quantity {
                        value: 1.0,
                        unit: "risk_points".to_string(),
                    },
                    displaced_to: bucket.clone(),
                    span: scope_span(3),
                },
                Stmt::AllowErase {
                    diff: diff_b.clone(),
                    span: scope_span(4),
                },
                Stmt::ErasureRule {
                    diff: diff_b.clone(),
                    cost: Quantity {
                        value: 2.0,
                        unit: "risk_points".to_string(),
                    },
                    displaced_to: bucket.clone(),
                    span: scope_span(5),
                },
                Stmt::ScopeChange {
                    from: from_a.clone(),
                    to: to_a.clone(),
                    mode: ScopeMode::Widen,
                    span: scope_span(10),
                },
                Stmt::ScopeChange {
                    from: from_b.clone(),
                    to: to_b.clone(),
                    mode: ScopeMode::Translate,
                    span: scope_span(11),
                },
            ],
        }
    }

    fn two_scope_changes_accounted_witness() -> Witness {
        eval(
            &two_scope_changes_accounted_program(),
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval")
    }

    // ── Invariant-first tests ──────────────────────────────────────────

    #[test]
    fn constraint_with_invariant_tag_appears_in_fact() {
        let diff = symbol(SymbolNamespace::Difference, "approved");
        let cid = symbol(SymbolNamespace::Constraint, "gov_check");

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:test".to_string()),
            dependencies: vec![],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: None,
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff.clone(),
                    value: CommitValue::Bool(false),
                    span: base_span(),
                },
                Stmt::Constraint {
                    id: Some(cid.clone()),
                    expr: BoolExpr::Pred {
                        pred: Predicate::CommitEquals {
                            diff: diff.clone(),
                            value: CommitValue::Bool(false),
                        },
                    },
                    span: base_span(),
                },
                Stmt::ConstraintMeta {
                    id: cid.clone(),
                    key: "invariant".to_string(),
                    value: "governance".to_string(),
                    span: base_span(),
                },
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        assert_eq!(witness.verdict, Verdict::Inadmissible);

        // ConstraintTriggered fact should carry invariant: Some("governance")
        let ct = witness
            .facts
            .iter()
            .find(|f| matches!(f, Fact::ConstraintTriggered { .. }));
        assert!(ct.is_some(), "should have ConstraintTriggered fact");
        if let Some(Fact::ConstraintTriggered { invariant, .. }) = ct {
            assert_eq!(invariant, &Some("governance".to_string()));
        }

        // InvariantProfile should contain governance
        assert_eq!(witness.invariants_touched(), vec!["governance".to_string()]);

        // Reason should contain [governance]
        assert!(
            witness.reason.contains("[governance]"),
            "reason should contain [governance], got: {}",
            witness.reason
        );
    }

    #[test]
    fn anonymous_constraint_has_no_invariant() {
        let diff = symbol(SymbolNamespace::Difference, "x");

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:test".to_string()),
            dependencies: vec![],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: None,
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff.clone(),
                    value: CommitValue::Bool(true),
                    span: base_span(),
                },
                Stmt::Constraint {
                    id: None, // anonymous
                    expr: BoolExpr::Pred {
                        pred: Predicate::CommitEquals {
                            diff: diff.clone(),
                            value: CommitValue::Bool(true),
                        },
                    },
                    span: base_span(),
                },
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        assert_eq!(witness.verdict, Verdict::Inadmissible);
        // Anonymous constraint → invariant: None → not in profile
        assert!(witness.invariants_touched().is_empty());
        assert!(witness.invariant_profile.is_empty());
    }

    #[test]
    fn multi_invariant_profile_is_sorted() {
        let diff_a = symbol(SymbolNamespace::Difference, "a");
        let diff_b = symbol(SymbolNamespace::Difference, "b");
        let cid_attr = symbol(SymbolNamespace::Constraint, "attr_check");
        let cid_gov = symbol(SymbolNamespace::Constraint, "gov_check");

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:test".to_string()),
            dependencies: vec![],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff_a.clone(),
                    unit: None,
                    span: base_span(),
                },
                Stmt::DeclareDifference {
                    diff: diff_b.clone(),
                    unit: None,
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff_a.clone(),
                    value: CommitValue::Bool(true),
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff_b.clone(),
                    value: CommitValue::Bool(true),
                    span: base_span(),
                },
                // governance constraint (will appear second alphabetically but defined first)
                Stmt::Constraint {
                    id: Some(cid_gov.clone()),
                    expr: BoolExpr::Pred {
                        pred: Predicate::CommitEquals {
                            diff: diff_a.clone(),
                            value: CommitValue::Bool(true),
                        },
                    },
                    span: base_span(),
                },
                Stmt::ConstraintMeta {
                    id: cid_gov.clone(),
                    key: "invariant".to_string(),
                    value: "governance".to_string(),
                    span: base_span(),
                },
                // attribution constraint
                Stmt::Constraint {
                    id: Some(cid_attr.clone()),
                    expr: BoolExpr::Pred {
                        pred: Predicate::CommitEquals {
                            diff: diff_b.clone(),
                            value: CommitValue::Bool(true),
                        },
                    },
                    span: base_span(),
                },
                Stmt::ConstraintMeta {
                    id: cid_attr.clone(),
                    key: "invariant".to_string(),
                    value: "attribution".to_string(),
                    span: base_span(),
                },
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        assert_eq!(witness.verdict, Verdict::Inadmissible);
        // Profile should be sorted alphabetically: attribution before governance
        assert_eq!(
            witness.invariants_touched(),
            vec!["attribution".to_string(), "governance".to_string()]
        );
        assert!(witness.reason.contains("[attribution, governance]"));
    }

    #[test]
    fn invariant_normalization_lowercases_and_trims() {
        let diff = symbol(SymbolNamespace::Difference, "x");
        let cid = symbol(SymbolNamespace::Constraint, "check");

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:test".to_string()),
            dependencies: vec![],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: None,
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff.clone(),
                    value: CommitValue::Bool(true),
                    span: base_span(),
                },
                Stmt::Constraint {
                    id: Some(cid.clone()),
                    expr: BoolExpr::Pred {
                        pred: Predicate::CommitEquals {
                            diff: diff.clone(),
                            value: CommitValue::Bool(true),
                        },
                    },
                    span: base_span(),
                },
                Stmt::ConstraintMeta {
                    id: cid.clone(),
                    key: "invariant".to_string(),
                    value: " GOVERNANCE ".to_string(), // mixed case, extra spaces
                    span: base_span(),
                },
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        // Should be normalized to "governance"
        assert_eq!(witness.invariants_touched(), vec!["governance".to_string()]);
    }

    #[test]
    fn conflicting_invariant_tags_emit_diagnostic() {
        let diff = symbol(SymbolNamespace::Difference, "x");
        let cid = symbol(SymbolNamespace::Constraint, "check");

        let program = Program {
            module: ModuleId("module:test@1".to_string()),
            scope: ScopeId("scope:test".to_string()),
            dependencies: vec![],
            statements: vec![
                Stmt::DeclareDifference {
                    diff: diff.clone(),
                    unit: None,
                    span: base_span(),
                },
                Stmt::Commit {
                    diff: diff.clone(),
                    value: CommitValue::Bool(true),
                    span: base_span(),
                },
                Stmt::Constraint {
                    id: Some(cid.clone()),
                    expr: BoolExpr::Pred {
                        pred: Predicate::CommitEquals {
                            diff: diff.clone(),
                            value: CommitValue::Bool(true),
                        },
                    },
                    span: base_span(),
                },
                // First tag
                Stmt::ConstraintMeta {
                    id: cid.clone(),
                    key: "invariant".to_string(),
                    value: "governance".to_string(),
                    span: base_span(),
                },
                // Conflicting second tag (last-write-wins)
                Stmt::ConstraintMeta {
                    id: cid.clone(),
                    key: "invariant".to_string(),
                    value: "attribution".to_string(),
                    span: base_span(),
                },
            ],
        };

        let witness = eval(
            &program,
            Query::Admissible,
            EvalOpts {
                displacement_mode: DisplacementMode::Potential,
                float_policy: FloatPolicy::Ban,
            },
        )
        .expect("eval");

        // Last-write-wins: attribution
        assert!(witness
            .invariants_touched()
            .contains(&"attribution".to_string()));

        // Should have a meta-conflict LintFinding
        let conflict_finding = witness
            .facts
            .iter()
            .find(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == "meta-conflict"));
        assert!(
            conflict_finding.is_some(),
            "should emit meta-conflict lint finding"
        );
    }

    #[test]
    fn old_witness_json_without_invariant_profile_deserializes() {
        // Simulate old witness JSON (before invariant_profile was added)
        let json = r#"{
            "verdict": "admissible",
            "program": {
                "module": "module:test@1",
                "scope": "scope:main"
            },
            "reason": "admissible",
            "facts": [],
            "displacement_trace": {
                "mode": "potential",
                "totals": [],
                "contributions": []
            }
        }"#;

        let witness: Witness = serde_json::from_str(json).expect("deserialize old witness");
        assert_eq!(witness.verdict, Verdict::Admissible);
        assert!(witness.invariant_profile.is_empty());
        assert!(witness.invariants_touched().is_empty());
    }
}
