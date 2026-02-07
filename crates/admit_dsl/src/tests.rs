#[cfg(test)]
mod tests {
    use crate::ast::Stmt;
    use crate::{lower_to_ir, parse_program};

    #[test]
    fn parse_and_lower_minimal_program() {
        let source = include_str!("../../../testdata/programs/basic.adm");
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
        let source = include_str!("../../../testdata/programs/bad-keyword.adm");
        let err = parse_program(source, "bad-keyword.adm").expect_err("expected parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn parse_error_scope_change_missing_mode_fixture() {
        let source = include_str!("../../../testdata/programs/scope-change-missing-mode.adm");
        let err = parse_program(source, "scope-change-missing-mode.adm").expect_err("parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn parse_error_unclosed_paren_fixture() {
        let source = include_str!("../../../testdata/programs/unclosed-paren.adm");
        let err = parse_program(source, "unclosed-paren.adm").expect_err("parse errors");
        assert!(!err.is_empty());
    }

    #[test]
    fn lower_error_missing_dependency() {
        let source = include_str!("../../../testdata/programs/missing-dep.adm");
        let program = parse_program(source, "missing-dep.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err
            .iter()
            .any(|e| e.contains("missing required dependency")));
    }

    #[test]
    fn lower_error_invalid_prefix() {
        let source = include_str!("../../../testdata/programs/invalid-prefix.adm");
        let program = parse_program(source, "invalid-prefix.adm").expect("parse program");
        let err = lower_to_ir(program).expect_err("expected lowering errors");
        assert!(err.iter().any(|e| e.contains("invalid namespace")));
    }

    #[test]
    fn lower_error_allow_without_rule() {
        let source = include_str!("../../../testdata/programs/allow-without-rule.adm");
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
        let source = include_str!("../../../testdata/programs/basic.adm");
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
@inadmissible_if vault_rule("broken-link")

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
}
