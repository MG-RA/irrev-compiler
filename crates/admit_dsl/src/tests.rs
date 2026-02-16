#[cfg(test)]
mod tests {
    use crate::ast::Stmt;
    use crate::{lower_to_ir, parse_program};

    #[test]
    fn parse_and_lower_minimal_program() {
        let source = include_str!("../testdata/programs/basic.adm");
        let program = parse_program(source, "basic.adm").expect("parse program");
        let ir = lower_to_ir(program).expect("lower to ir");
        assert_eq!(ir.module.0, "module:test@1");
        assert_eq!(ir.scope.0, "scope:main");
        assert!(ir.statements.len() >= 5);
    }

    #[test]
    fn parse_error_invalid_module_decl() {
        let source = "module test\nscope main\n";
        let err = parse_program(source, "bad.adm").expect_err("expected parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn parse_error_bad_keyword_fixture() {
        let source = include_str!("../testdata/programs/bad-keyword.adm");
        let err = parse_program(source, "bad-keyword.adm").expect_err("expected parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn parse_error_scope_change_missing_mode_fixture() {
        let source = include_str!("../testdata/programs/scope-change-missing-mode.adm");
        let err = parse_program(source, "scope-change-missing-mode.adm").expect_err("parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn parse_error_unclosed_paren_fixture() {
        let source = include_str!("../testdata/programs/unclosed-paren.adm");
        let err = parse_program(source, "unclosed-paren.adm").expect_err("parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn lower_error_missing_dependency() {
        let source = include_str!("../testdata/programs/missing-dep.adm");
        let program = parse_program(source, "missing-dep.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err
            .iter()
            .any(|e| e.contains("missing required dependency")));
    }

    #[test]
    fn lower_error_invalid_prefix() {
        let source = include_str!("../testdata/programs/invalid-prefix.adm");
        let program = parse_program(source, "invalid-prefix.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err.iter().any(|e| e.contains("invalid namespace")));
    }

    #[test]
    fn lower_error_allow_without_rule() {
        let source = include_str!("../testdata/programs/allow-without-rule.adm");
        let program = parse_program(source, "allow-without-rule.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err
            .iter()
            .any(|e| e.contains("allow_erase requires erasure_rule")));
    }

    #[test]
    fn lower_error_conflicting_permissions() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

difference crew_fatigue
deny_erase crew_fatigue
allow_erase crew_fatigue
"#;
        let program = parse_program(source, "conflict.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err.iter().any(|e| e.contains("conflicting permissions")));
    }

    #[test]
    fn parse_round_trip_program() {
        let source = include_str!("../testdata/programs/basic.adm");
        let program = parse_program(source, "basic.adm").expect("parse program");
        let json = serde_json::to_string(&program).expect("serialize program");
        let decoded: crate::Program = serde_json::from_str(&json).expect("deserialize program");
        assert_eq!(program, decoded);
    }

    #[test]
    fn parse_and_lower_scope_change_program() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

scope_change main -> prod widen
allow_scope_change main -> prod
scope_change_rule main -> prod cost 1 "risk_points" -> safety_risk
"#;
        let program = parse_program(source, "scope-change.adm").expect("parse program");
        let ir = lower_to_ir(program).expect("lower to ir");

        assert!(ir
            .statements
            .iter()
            .any(|stmt| matches!(stmt, admit_core::Stmt::ScopeChange { .. })));
        assert!(ir
            .statements
            .iter()
            .any(|stmt| matches!(stmt, admit_core::Stmt::AllowErase { .. })));
        assert!(ir
            .statements
            .iter()
            .any(|stmt| matches!(stmt, admit_core::Stmt::ErasureRule { .. })));
    }

    #[test]
    fn parse_scope_change_block_desugars() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

bucket boundary_loss

scope_change main -> prod widen { allow; cost 1 "risk_points" -> boundary_loss }
"#;
        let program = parse_program(source, "scope-change-block.adm").expect("parse program");
        assert!(matches!(program.statements[4], Stmt::ScopeChange(_)));
        assert!(matches!(program.statements[5], Stmt::AllowScopeChange(_)));
        assert!(matches!(program.statements[6], Stmt::ScopeChangeRule(_)));
    }

    #[test]
    fn parse_inadmissible_if_attribute() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

@inadmissible_if erase_allowed crew_fatigue
"#;
        let program = parse_program(source, "inadmissible-attr.adm").expect("parse program");
        assert!(matches!(program.statements[3], Stmt::InadmissibleIf { .. }));
    }

    #[test]
    fn parse_predicate_call_syntax() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

inadmissible_if displaced_total(boundary_loss) > 1 "risk_points"
"#;
        let program = parse_program(source, "pred-call.adm").expect("parse program");
        assert!(matches!(program.statements[3], Stmt::InadmissibleIf { .. }));
    }

    #[test]
    fn parse_and_lower_constraint_tags_and_lint_query() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope vault_lint

constraint broken-link
tag severity warning
@inadmissible_if obsidian_vault_rule("broken-link")

query lint fail_on warning
query witness
"#;
        let program = parse_program(source, "tags-and-lint.adm").expect("parse program");
        assert!(program.statements.iter().any(|s| matches!(s, Stmt::Tag(_))));
        assert!(program.statements.iter().any(
            |s| matches!(s, Stmt::Query(q) if matches!(q.kind, crate::ast::QueryKind::Lint { .. }))
        ));

        let ir = lower_to_ir(program).expect("lower to ir");
        assert!(ir
            .statements
            .iter()
            .any(|s| matches!(s, admit_core::Stmt::ConstraintMeta { .. })));
        assert!(ir.statements.iter().any(|s| {
            matches!(
                s,
                admit_core::Stmt::Query {
                    query: admit_core::Query::Lint { .. },
                    ..
                }
            )
        }));
    }

    #[test]
    fn parse_legacy_vault_rule_alias_lowers_to_provider_predicate() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope vault_lint

@inadmissible_if vault_rule("broken-link")
"#;

        let program = parse_program(source, "legacy-vault-rule.adm").expect("parse program");
        let ir = lower_to_ir(program).expect("lower to ir");
        assert!(ir.statements.iter().any(|s| {
            matches!(
                s,
                admit_core::Stmt::Constraint {
                    expr: admit_core::BoolExpr::Pred {
                        pred: admit_core::Predicate::ProviderPredicate { scope_id, name, .. }
                    },
                    ..
                } if scope_id.0 == "obsidian" && name == "vault_rule"
            )
        }));
    }

    #[test]
    fn parse_allow_scope_change_is_unambiguous() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

allow_scope_change main -> prod
"#;
        let program = parse_program(source, "allow-scope-only.adm").expect("parse program");
        assert_eq!(program.statements.len(), 4);
        assert!(matches!(program.statements[3], Stmt::AllowScopeChange(_)));
    }

    #[test]
    fn lower_error_allow_scope_change_without_rule() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

scope_change main -> prod widen
allow_scope_change main -> prod
"#;
        let program =
            parse_program(source, "scope-change-missing-rule.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err
            .iter()
            .any(|e| e.contains("allow_erase requires erasure_rule")));
    }

    #[test]
    fn parse_import_scope_pack_statement() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

import scope_pack "git.working_tree@1"
"#;
        let program = parse_program(source, "import-scope-pack.adm").expect("parse program");
        assert!(program.statements.iter().any(|stmt| matches!(
            stmt,
            Stmt::ImportScopePack(import)
                if import.scope_id == "git.working_tree" && import.version == 1
        )));
    }

    #[test]
    fn parse_import_scope_pack_statement_unquoted() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

import scope_pack git.working_tree@1
"#;
        let program =
            parse_program(source, "import-scope-pack-unquoted.adm").expect("parse program");
        assert!(program.statements.iter().any(|stmt| matches!(
            stmt,
            Stmt::ImportScopePack(import)
                if import.scope_id == "git.working_tree" && import.version == 1
        )));
    }

    #[test]
    fn lower_error_scope_pack_import_requires_registry_context() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

import scope_pack "git.working_tree@1"
"#;
        let program =
            parse_program(source, "import-scope-pack-no-registry.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected missing registry context");
        assert!(err
            .iter()
            .any(|e| e.contains("requires registry scope_packs context")));
    }

    #[test]
    fn lower_resolves_scope_pack_import_with_registry() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

import scope_pack "git.working_tree@1"
"#;
        let program =
            parse_program(source, "import-scope-pack-with-registry.adm").expect("parse program");
        let ir = crate::lower_to_ir_with_scope_packs(
            program,
            &[crate::ScopePackRegistryEntry {
                scope_id: "git.working_tree".to_string(),
                version: 1,
            }],
        )
        .expect("lower with registry");
        assert_eq!(ir.module.0, "module:test@1");
    }

    #[test]
    fn lower_error_unknown_scope_pack_import() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

import scope_pack "github.ceremony@1"
"#;
        let program =
            parse_program(source, "import-scope-pack-unknown.adm").expect("parse program");
        let err = crate::lower_to_ir_with_scope_packs(
            program,
            &[crate::ScopePackRegistryEntry {
                scope_id: "git.working_tree".to_string(),
                version: 1,
            }],
        )
        .expect_err("expected unknown scope pack import");
        assert!(err.iter().any(|e| e.contains("unknown scope_pack import")));
    }

    #[test]
    fn scope_packs_from_meta_registry_extracts_entries() {
        let meta_registry = serde_json::json!({
            "schema_id": "meta-registry/1",
            "scope_packs": [
                { "scope_id": "git.working_tree", "version": 1 },
                { "scope_id": "scope:deps.manifest", "version": 1 }
            ]
        });
        let entries =
            crate::scope_packs_from_meta_registry(&meta_registry).expect("extract scope packs");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].scope_id, "git.working_tree");
        assert_eq!(entries[0].version, 1);
        assert_eq!(entries[1].scope_id, "deps.manifest");
        assert_eq!(entries[1].version, 1);
    }

    #[test]
    fn lower_resolves_scope_pack_import_with_meta_registry() {
        let source = r#"
module test@1
depends [irrev_std@1]
scope main

import scope_pack "git.working_tree@1"
"#;
        let program =
            parse_program(source, "import-scope-pack-meta-registry.adm").expect("parse program");
        let meta_registry = serde_json::json!({
            "schema_id": "meta-registry/1",
            "scope_packs": [
                { "scope_id": "git.working_tree", "version": 1 }
            ]
        });
        let ir = crate::lower_to_ir_with_meta_registry(program, &meta_registry)
            .expect("lower with meta registry");
        assert_eq!(ir.module.0, "module:test@1");
    }
}
