use std::collections::{HashMap, HashSet};

use crate::ast::*;

pub fn lower_to_ir(program: Program) -> Result<admit_core::Program, Vec<String>> {
    let mut module: Option<(String, u32)> = None;
    let mut scope: Option<String> = None;
    let mut depends: Vec<String> = Vec::new();
    let mut pending_constraint_id: Option<String> = None;
    let mut pending_constraint_tags: Vec<(String, String, crate::span::Span)> = Vec::new();
    let mut decls = Vec::new();
    let mut rest = Vec::new();
    let mut errors = Vec::new();
    let mut declared_differences: HashSet<String> = HashSet::new();
    let mut declared_transforms: HashSet<String> = HashSet::new();
    let mut declared_buckets: HashSet<String> = HashSet::new();
    let mut declared_constraints: HashSet<String> = HashSet::new();
    let mut erasure_rules: HashSet<String> = HashSet::new();
    let mut permissions: HashMap<String, PermissionKind> = HashMap::new();

    for stmt in program.statements {
        match stmt {
            Stmt::Module(decl) => {
                if module.is_some() {
                    errors.push("multiple module declarations".to_string());
                    continue;
                }
                module = Some((decl.name, decl.major));
            }
            Stmt::Depends(decl) => {
                depends.extend(decl.modules);
            }
            Stmt::Scope(decl) => {
                if scope.is_some() {
                    errors.push("multiple scope declarations".to_string());
                    continue;
                }
                scope = Some(normalize_name("scope", decl.name, &mut errors));
            }
            Stmt::ScopeChange(stmt) => {
                let from = normalize_name("scope", stmt.from, &mut errors);
                let to = normalize_name("scope", stmt.to, &mut errors);
                let mode = match stmt.mode {
                    ScopeMode::Widen => admit_core::ScopeMode::Widen,
                    ScopeMode::Narrow => admit_core::ScopeMode::Narrow,
                    ScopeMode::Translate => admit_core::ScopeMode::Translate,
                };
                rest.push(admit_core::Stmt::ScopeChange {
                    from: admit_core::ScopeId(format!("scope:{}", from)),
                    to: admit_core::ScopeId(format!("scope:{}", to)),
                    mode,
                    span: lower_span(&stmt.span),
                });
            }
            Stmt::AllowScopeChange(stmt) => {
                let from = normalize_name("scope", stmt.from, &mut errors);
                let to = normalize_name("scope", stmt.to, &mut errors);
                let from_id = admit_core::ScopeId(format!("scope:{}", from));
                let to_id = admit_core::ScopeId(format!("scope:{}", to));
                let diff_name = admit_core::boundary_loss_diff_name(&from_id, &to_id);
                let diff = symbol(admit_core::SymbolNamespace::Difference, &diff_name);
                let span = lower_span(&stmt.span);
                rest.push(admit_core::Stmt::AllowErase { diff, span });
                permissions.insert(diff_name, PermissionKind::Allow);
            }
            Stmt::ScopeChangeRule(stmt) => {
                let from = normalize_name("scope", stmt.from, &mut errors);
                let to = normalize_name("scope", stmt.to, &mut errors);
                let from_id = admit_core::ScopeId(format!("scope:{}", from));
                let to_id = admit_core::ScopeId(format!("scope:{}", to));
                let diff_name = admit_core::boundary_loss_diff_name(&from_id, &to_id);
                let bucket = normalize_name("bucket", stmt.bucket, &mut errors);
                if stmt.cost_unit.trim().is_empty() {
                    errors.push("scope_change_rule missing unit".to_string());
                }
                if bucket.trim().is_empty() {
                    errors.push("scope_change_rule missing bucket".to_string());
                }
                erasure_rules.insert(diff_name.clone());
                rest.push(admit_core::Stmt::ErasureRule {
                    diff: symbol(admit_core::SymbolNamespace::Difference, &diff_name),
                    cost: admit_core::Quantity {
                        value: stmt.cost_value,
                        unit: stmt.cost_unit,
                    },
                    displaced_to: symbol(admit_core::SymbolNamespace::Bucket, &bucket),
                    span: lower_span(&stmt.span),
                });
            }
            Stmt::Difference(decl) => {
                let name = normalize_name("difference", decl.name, &mut errors);
                if !declared_differences.insert(name.clone()) {
                    errors.push(format!("duplicate difference declaration: {}", name));
                }
                decls.push(admit_core::Stmt::DeclareDifference {
                    diff: symbol(admit_core::SymbolNamespace::Difference, &name),
                    unit: decl.unit,
                    span: lower_span(&decl.span),
                });
            }
            Stmt::Transform(decl) => {
                let name = normalize_name("transform", decl.name, &mut errors);
                if !declared_transforms.insert(name.clone()) {
                    errors.push(format!("duplicate transform declaration: {}", name));
                }
                decls.push(admit_core::Stmt::DeclareTransform {
                    transform: symbol(admit_core::SymbolNamespace::Transform, &name),
                    span: lower_span(&decl.span),
                });
            }
            Stmt::Bucket(decl) => {
                let name = normalize_name("bucket", decl.name, &mut errors);
                if !declared_buckets.insert(name.clone()) {
                    errors.push(format!("duplicate bucket declaration: {}", name));
                }
            }
            Stmt::Constraint(decl) => {
                if pending_constraint_id.is_some() {
                    errors
                        .push("constraint declared without following inadmissible_if".to_string());
                }
                let name = normalize_name("constraint", decl.name, &mut errors);
                if !declared_constraints.insert(name.clone()) {
                    errors.push(format!("duplicate constraint declaration: {}", name));
                }
                pending_constraint_id = Some(name);
                pending_constraint_tags.clear();
            }
            Stmt::Tag(stmt) => {
                let Some(cur) = pending_constraint_id.as_ref() else {
                    errors.push("tag declared without preceding constraint".to_string());
                    continue;
                };

                if pending_constraint_tags
                    .iter()
                    .any(|(k, _, _)| k == &stmt.key)
                {
                    errors.push(format!(
                        "duplicate tag key for constraint {}: {}",
                        cur, stmt.key
                    ));
                    continue;
                }

                pending_constraint_tags.push((stmt.key, stmt.value, stmt.span));
            }
            Stmt::Persist(stmt) => {
                let diff = normalize_name("difference", stmt.diff, &mut errors);
                let under = stmt
                    .under
                    .into_iter()
                    .map(|t| normalize_name("transform", t, &mut errors))
                    .collect::<Vec<_>>();
                rest.push(admit_core::Stmt::Persist {
                    diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
                    under: under
                        .into_iter()
                        .map(|t| symbol(admit_core::SymbolNamespace::Transform, &t))
                        .collect(),
                    span: lower_span(&stmt.span),
                });
            }
            Stmt::ErasureRule(stmt) => {
                let diff = normalize_name("difference", stmt.diff, &mut errors);
                let bucket = normalize_name("bucket", stmt.bucket, &mut errors);
                if stmt.cost_unit.trim().is_empty() {
                    errors.push(format!("erasure_rule missing unit for {}", diff));
                }
                if bucket.trim().is_empty() {
                    errors.push(format!("erasure_rule missing bucket for {}", diff));
                }
                erasure_rules.insert(diff.clone());
                rest.push(admit_core::Stmt::ErasureRule {
                    diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
                    cost: admit_core::Quantity {
                        value: stmt.cost_value,
                        unit: stmt.cost_unit,
                    },
                    displaced_to: symbol(admit_core::SymbolNamespace::Bucket, &bucket),
                    span: lower_span(&stmt.span),
                });
            }
            Stmt::Permission(stmt) => {
                let diff_name = normalize_name("difference", stmt.diff, &mut errors);
                if let Some(existing) = permissions.get(&diff_name) {
                    if existing != &stmt.kind {
                        errors.push(format!(
                            "conflicting permissions for {}: {:?} vs {:?}",
                            diff_name, existing, stmt.kind
                        ));
                    }
                } else {
                    permissions.insert(diff_name.clone(), stmt.kind.clone());
                }
                let diff = symbol(admit_core::SymbolNamespace::Difference, &diff_name);
                let span = lower_span(&stmt.span);
                let ir = match stmt.kind {
                    PermissionKind::Allow => admit_core::Stmt::AllowErase { diff, span },
                    PermissionKind::Deny => admit_core::Stmt::DenyErase { diff, span },
                };
                rest.push(ir);
            }
            Stmt::Commit(stmt) => {
                let diff = normalize_name("difference", stmt.diff, &mut errors);
                rest.push(admit_core::Stmt::Commit {
                    diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
                    value: lower_commit_value(stmt.value),
                    span: lower_span(&stmt.span),
                });
            }
            Stmt::InadmissibleIf { expr, span } => {
                let id = pending_constraint_id.take();
                let id = id.map(|name| admit_core::SymbolRef {
                    ns: admit_core::SymbolNamespace::Constraint,
                    name,
                });
                if let Some(constraint_id) = id.as_ref() {
                    // Emit tags deterministically (key,value ordering) so the program hash is stable.
                    pending_constraint_tags
                        .sort_by(|(ak, av, _), (bk, bv, _)| (ak, av).cmp(&(bk, bv)));
                    for (key, value, tag_span) in pending_constraint_tags.drain(..) {
                        rest.push(admit_core::Stmt::ConstraintMeta {
                            id: constraint_id.clone(),
                            key,
                            value,
                            span: lower_span(&tag_span),
                        });
                    }
                } else {
                    pending_constraint_tags.clear();
                }
                rest.push(admit_core::Stmt::Constraint {
                    id,
                    expr: lower_expr(expr, &mut errors),
                    span: lower_span(&span),
                });
            }
            Stmt::Query(stmt) => {
                let query = match stmt.kind {
                    QueryKind::Admissible => admit_core::Query::Admissible,
                    QueryKind::Witness => admit_core::Query::Witness,
                    QueryKind::Delta => admit_core::Query::Delta,
                    QueryKind::Lint { fail_on } => admit_core::Query::Lint {
                        fail_on: match fail_on {
                            crate::ast::LintFailOn::Error => admit_core::LintFailOn::Error,
                            crate::ast::LintFailOn::Warning => admit_core::LintFailOn::Warning,
                            crate::ast::LintFailOn::Info => admit_core::LintFailOn::Info,
                        },
                    },
                };
                rest.push(admit_core::Stmt::Query {
                    query,
                    span: lower_span(&stmt.span),
                });
            }
        }
    }

    if module.is_none() {
        errors.push("missing module declaration".to_string());
    }
    if scope.is_none() {
        errors.push("missing scope declaration".to_string());
    }

    if pending_constraint_id.is_some() {
        errors.push("constraint declared without following inadmissible_if".to_string());
    }

    for (diff, kind) in &permissions {
        if *kind == PermissionKind::Allow && !erasure_rules.contains(diff) {
            errors.push(format!(
                "allow_erase requires erasure_rule for difference: {}",
                diff
            ));
        }
    }

    let mut seen_dep: HashSet<String> = HashSet::new();
    for dep in &depends {
        if !seen_dep.insert(dep.clone()) {
            errors.push(format!("duplicate dependency: module:{}", dep));
        }
    }

    if !depends.iter().any(|m| m == "irrev_std@1") {
        errors.push("missing required dependency: module:irrev_std@1".to_string());
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let (module_name, module_major) = match module {
        Some(value) => value,
        None => return Err(vec!["missing module declaration".to_string()]),
    };
    let scope_name = match scope {
        Some(value) => value,
        None => return Err(vec!["missing scope declaration".to_string()]),
    };

    let dependencies = depends
        .into_iter()
        .map(|dep| admit_core::ModuleId(format!("module:{}", dep)))
        .collect();

    decls.sort_by(|a, b| stmt_sort_key(a).cmp(&stmt_sort_key(b)));
    let mut statements = decls;
    statements.extend(rest);

    Ok(admit_core::Program {
        module: admit_core::ModuleId(format!("module:{}@{}", module_name, module_major)),
        scope: admit_core::ScopeId(format!("scope:{}", scope_name)),
        dependencies,
        statements,
    })
}

fn lower_span(span: &crate::span::Span) -> admit_core::Span {
    admit_core::Span {
        file: span.file.clone(),
        start: Some(span.start as u32),
        end: Some(span.end as u32),
        line: Some(span.line),
        col: Some(span.col),
    }
}

fn symbol(ns: admit_core::SymbolNamespace, name: &str) -> admit_core::SymbolRef {
    admit_core::SymbolRef {
        ns,
        name: name.to_string(),
    }
}

fn lower_commit_value(value: CommitValue) -> admit_core::CommitValue {
    match value {
        CommitValue::Number { value, unit } => {
            admit_core::CommitValue::Quantity(admit_core::Quantity {
                value,
                unit: unit.unwrap_or_default(),
            })
        }
        CommitValue::Text(value) => admit_core::CommitValue::Text(value),
        CommitValue::Bool(value) => admit_core::CommitValue::Bool(value),
    }
}

fn lower_expr(expr: BoolExpr, errors: &mut Vec<String>) -> admit_core::BoolExpr {
    match expr {
        BoolExpr::And(items) => admit_core::BoolExpr::And {
            items: items.into_iter().map(|e| lower_expr(e, errors)).collect(),
        },
        BoolExpr::Or(items) => admit_core::BoolExpr::Or {
            items: items.into_iter().map(|e| lower_expr(e, errors)).collect(),
        },
        BoolExpr::Not(item) => admit_core::BoolExpr::Not {
            item: Box::new(lower_expr(*item, errors)),
        },
        BoolExpr::Pred(pred) => admit_core::BoolExpr::Pred {
            pred: lower_predicate(pred, errors),
        },
    }
}

fn lower_predicate(pred: Predicate, errors: &mut Vec<String>) -> admit_core::Predicate {
    match pred {
        Predicate::EraseAllowed { diff } => {
            let diff = normalize_name("difference", diff, errors);
            admit_core::Predicate::EraseAllowed {
                diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
            }
        }
        Predicate::DisplacedTotal {
            bucket,
            op,
            value,
            unit,
        } => {
            let bucket = normalize_name("bucket", bucket, errors);
            admit_core::Predicate::DisplacedTotal {
                bucket: symbol(admit_core::SymbolNamespace::Bucket, &bucket),
                op: lower_cmp(op),
                value: admit_core::Quantity { value, unit },
            }
        }
        Predicate::HasCommit { diff } => {
            let diff = normalize_name("difference", diff, errors);
            admit_core::Predicate::HasCommit {
                diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
            }
        }
        Predicate::CommitEquals { diff, value } => {
            let diff = normalize_name("difference", diff, errors);
            admit_core::Predicate::CommitEquals {
                diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
                value: lower_commit_value(value),
            }
        }
        Predicate::CommitCmp {
            diff,
            op,
            value,
            unit,
        } => {
            let diff = normalize_name("difference", diff, errors);
            admit_core::Predicate::CommitCmp {
                diff: symbol(admit_core::SymbolNamespace::Difference, &diff),
                op: lower_cmp(op),
                value: admit_core::Quantity { value, unit },
            }
        }
        Predicate::ObsidianVaultRule { rule_id } => {
            admit_core::Predicate::ObsidianVaultRule { rule_id }
        }
    }
}

fn lower_cmp(op: CmpOp) -> admit_core::CmpOp {
    match op {
        CmpOp::Eq => admit_core::CmpOp::Eq,
        CmpOp::Neq => admit_core::CmpOp::Neq,
        CmpOp::Gt => admit_core::CmpOp::Gt,
        CmpOp::Gte => admit_core::CmpOp::Gte,
        CmpOp::Lt => admit_core::CmpOp::Lt,
        CmpOp::Lte => admit_core::CmpOp::Lte,
    }
}

fn normalize_name(prefix: &str, raw: String, errors: &mut Vec<String>) -> String {
    if let Some((ns, rest)) = raw.split_once(':') {
        if ns == "module" {
            errors.push(format!(
                "cross-module reference not supported in {}: {}",
                prefix, raw
            ));
            return rest.to_string();
        }
        if ns != prefix {
            errors.push(format!("invalid namespace for {}: {}", prefix, raw));
            return rest.to_string();
        }
        if rest.is_empty() {
            errors.push(format!("empty {} name", prefix));
        }
        return rest.to_string();
    }
    raw
}

fn stmt_sort_key(stmt: &admit_core::Stmt) -> String {
    match stmt {
        admit_core::Stmt::DeclareDifference { diff, .. } => format!("difference:{}", diff.name),
        admit_core::Stmt::DeclareTransform { transform, .. } => {
            format!("transform:{}", transform.name)
        }
        _ => "zzzz".to_string(),
    }
}
