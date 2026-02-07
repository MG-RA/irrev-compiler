use chumsky::prelude::*;
use chumsky::Stream;

use crate::ast::*;
use crate::errors::{to_parse_error, ParseError};
use crate::lexer::lexer;
use crate::span::{make_span, LineIndex};
use crate::tokens::{Number, Token};

#[derive(Debug, Clone)]
struct ScopeChangeBlock {
    allow_span: Option<std::ops::Range<usize>>,
    cost: Option<ScopeChangeCost>,
}

#[derive(Debug, Clone)]
struct ScopeChangeCost {
    cost_value: f64,
    cost_unit: String,
    bucket: String,
    span: std::ops::Range<usize>,
}

pub fn parse_program(source: &str, file: &str) -> Result<Program, Vec<ParseError>> {
    let line_index = LineIndex::new(source);
    let (tokens, lex_errs) = lexer().parse_recovery(source);
    if !lex_errs.is_empty() {
        let errs = lex_errs
            .into_iter()
            .map(|e| to_parse_error(e, file, &line_index))
            .collect::<Vec<_>>();
        return Err(errs);
    }

    let tokens = tokens.unwrap_or_default();
    let span_end = source.len()..source.len() + 1;
    let stream = Stream::from_iter(span_end, tokens.into_iter());

    let ident = select! { Token::Ident(s) => s };
    let number = select! { Token::Number(Number(n)) => n };
    let string = select! { Token::Str(s) => s };
    let ident_or_paren = choice::<_, Simple<Token>>((
        ident
            .clone()
            .delimited_by(just(Token::LParen), just(Token::RParen)),
        ident.clone(),
    ));

    let cmp_op = choice::<_, Simple<Token>>((
        just(Token::CmpEq).to(CmpOp::Eq),
        just(Token::CmpNeq).to(CmpOp::Neq),
        just(Token::CmpGte).to(CmpOp::Gte),
        just(Token::CmpGt).to(CmpOp::Gt),
        just(Token::CmpLte).to(CmpOp::Lte),
        just(Token::CmpLt).to(CmpOp::Lt),
    ));

    let bool_value =
        choice::<_, Simple<Token>>((just(Token::True).to(true), just(Token::False).to(false)));

    let commit_value = choice::<_, Simple<Token>>((
        number
            .clone()
            .then(string.clone().or_not())
            .map(|(value, unit)| CommitValue::Number { value, unit }),
        string.clone().map(CommitValue::Text),
        bool_value.map(CommitValue::Bool),
    ));

    let rule_id_value = choice::<_, Simple<Token>>((
        string
            .clone()
            .delimited_by(just(Token::LParen), just(Token::RParen)),
        ident
            .clone()
            .delimited_by(just(Token::LParen), just(Token::RParen)),
        string.clone(),
        ident.clone(),
    ));

    let predicate = choice::<_, Simple<Token>>((
        just(Token::KwEraseAllowed)
            .ignore_then(ident_or_paren.clone())
            .map(|diff| Predicate::EraseAllowed { diff }),
        just(Token::KwDisplacedTotal)
            .ignore_then(ident_or_paren.clone())
            .then(cmp_op.clone())
            .then(number.clone())
            .then(string.clone())
            .map(|(((bucket, op), value), unit)| Predicate::DisplacedTotal {
                bucket,
                op,
                value,
                unit,
            }),
        just(Token::KwHasCommit)
            .ignore_then(ident_or_paren.clone())
            .map(|diff| Predicate::HasCommit { diff }),
        just(Token::KwCommitEquals)
            .ignore_then(ident_or_paren.clone())
            .then_ignore(just(Token::Eq))
            .then(commit_value.clone())
            .map(|(diff, value)| Predicate::CommitEquals { diff, value }),
        just(Token::KwCommitCmp)
            .ignore_then(ident_or_paren.clone())
            .then(cmp_op.clone())
            .then(number.clone())
            .then(string.clone())
            .map(|(((diff, op), value), unit)| Predicate::CommitCmp {
                diff,
                op,
                value,
                unit,
            }),
        just(Token::KwVaultRule)
            .ignore_then(rule_id_value.clone())
            .map(|rule_id| Predicate::VaultRule { rule_id }),
    ));

    let expr = recursive(|expr| {
        let atom = choice::<_, Simple<Token>>((
            predicate.clone().map(BoolExpr::Pred),
            expr.clone()
                .delimited_by(just(Token::LParen), just(Token::RParen)),
        ));
        let not = choice::<_, Simple<Token>>((
            just(Token::KwNot)
                .ignore_then(atom.clone())
                .map(|e| BoolExpr::Not(Box::new(e))),
            atom,
        ));
        let and = not
            .clone()
            .separated_by(just(Token::KwAnd))
            .at_least(1)
            .map(|mut items| {
                if items.len() == 1 {
                    items.remove(0)
                } else {
                    BoolExpr::And(items)
                }
            });
        let or = and
            .clone()
            .separated_by(just(Token::KwOr))
            .at_least(1)
            .map(|mut items| {
                if items.len() == 1 {
                    items.remove(0)
                } else {
                    BoolExpr::Or(items)
                }
            });
        or
    });

    let module_decl = ident
        .clone()
        .try_map(|raw, span| parse_module_decl(&raw).map_err(|msg| Simple::custom(span, msg)));

    let module_stmt = just(Token::KwModule)
        .ignore_then(module_decl)
        .map_with_span(|(name, major), span| {
            Stmt::Module(ModuleDecl {
                name,
                major,
                span: make_span(file, span, &line_index),
            })
        });

    let depends_ref = ident
        .clone()
        .try_map(|raw, span| parse_module_ref(&raw).map_err(|msg| Simple::custom(span, msg)));

    let depends_stmt = just(Token::KwDepends)
        .ignore_then(
            depends_ref
                .separated_by(just(Token::Comma))
                .delimited_by(just(Token::LBracket), just(Token::RBracket)),
        )
        .map_with_span(|modules: Vec<String>, span| {
            Stmt::Depends(DependsDecl {
                modules,
                span: make_span(file, span, &line_index),
            })
        });

    let scope_stmt =
        just(Token::KwScope)
            .ignore_then(ident.clone())
            .try_map(|raw: String, span| {
                let name = resolve_prefixed("scope", &raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::Scope(ScopeDecl {
                    name,
                    span: make_span(file, span, &line_index),
                }))
            });

    let scope_mode = ident
        .clone()
        .then(ident.clone().or_not())
        .try_map(|(first, second), span| {
            let raw = if first == "mode" {
                second.ok_or_else(|| Simple::custom(span.clone(), "missing scope_change mode"))?
            } else {
                if second.is_some() {
                    return Err(Simple::custom(
                        span.clone(),
                        "unexpected token after scope_change mode",
                    ));
                }
                first
            };
            match raw.as_str() {
                "widen" => Ok(ScopeMode::Widen),
                "narrow" => Ok(ScopeMode::Narrow),
                "translate" => Ok(ScopeMode::Translate),
                _ => Err(Simple::custom(
                    span.clone(),
                    "invalid scope_change mode (expected widen|narrow|translate)",
                )),
            }
        });

    let scope_change_cost = just(Token::KwCost)
        .ignore_then(number.clone())
        .then(string.clone())
        .then_ignore(just(Token::Arrow))
        .then(ident.clone())
        .map_with_span(|((cost_value, cost_unit), bucket), span| ScopeChangeCost {
            cost_value,
            cost_unit,
            bucket,
            span,
        });

    let scope_change_block = just(Token::LBrace)
        .ignore_then(
            choice::<_, Simple<Token>>((
                just(Token::KwAllow).map_with_span(|_, span| ScopeChangeBlock {
                    allow_span: Some(span),
                    cost: None,
                }),
                scope_change_cost.map(|cost| ScopeChangeBlock {
                    allow_span: None,
                    cost: Some(cost),
                }),
            ))
            .separated_by(just(Token::Semi))
            .allow_trailing(),
        )
        .then_ignore(just(Token::RBrace))
        .try_map(|items: Vec<ScopeChangeBlock>, span| {
            let mut allow_span = None;
            let mut cost = None;
            for item in items {
                if let Some(item_span) = item.allow_span {
                    if allow_span.is_some() {
                        return Err(Simple::custom(
                            span.clone(),
                            "duplicate allow in scope_change block",
                        ));
                    }
                    allow_span = Some(item_span);
                }
                if let Some(item_cost) = item.cost {
                    if cost.is_some() {
                        return Err(Simple::custom(
                            span.clone(),
                            "duplicate cost in scope_change block",
                        ));
                    }
                    cost = Some(item_cost);
                }
            }
            Ok(ScopeChangeBlock { allow_span, cost })
        });

    let scope_change_stmt = just(Token::KwScopeChange)
        .ignore_then(ident.clone())
        .then_ignore(just(Token::Arrow))
        .then(ident.clone())
        .then(scope_mode)
        .then(scope_change_block.or_not())
        .try_map(|(((from_raw, to_raw), mode), block), span| {
            let from = resolve_prefixed("scope", &from_raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            let to = resolve_prefixed("scope", &to_raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            let mut stmts = vec![Stmt::ScopeChange(ScopeChangeStmt {
                from: from.clone(),
                to: to.clone(),
                mode,
                span: make_span(file, span.clone(), &line_index),
            })];
            if let Some(block) = block {
                if let Some(allow_span) = block.allow_span {
                    stmts.push(Stmt::AllowScopeChange(AllowScopeChangeStmt {
                        from: from.clone(),
                        to: to.clone(),
                        span: make_span(file, allow_span, &line_index),
                    }));
                }
                if let Some(cost) = block.cost {
                    let bucket = resolve_prefixed("bucket", &cost.bucket)
                        .map_err(|msg| Simple::custom(span.clone(), msg))?;
                    stmts.push(Stmt::ScopeChangeRule(ScopeChangeRuleStmt {
                        from,
                        to,
                        cost_value: cost.cost_value,
                        cost_unit: cost.cost_unit,
                        bucket,
                        span: make_span(file, cost.span, &line_index),
                    }));
                }
            }
            Ok(stmts)
        });

    let allow_scope_change_stmt = just(Token::KwAllowScopeChange)
        .ignore_then(ident.clone())
        .then_ignore(just(Token::Arrow))
        .then(ident.clone())
        .try_map(|(from_raw, to_raw), span| {
            let from = resolve_prefixed("scope", &from_raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            let to = resolve_prefixed("scope", &to_raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            Ok(Stmt::AllowScopeChange(AllowScopeChangeStmt {
                from,
                to,
                span: make_span(file, span, &line_index),
            }))
        });

    let scope_change_rule_stmt = just(Token::KwScopeChangeRule)
        .ignore_then(ident.clone())
        .then_ignore(just(Token::Arrow))
        .then(ident.clone())
        .then_ignore(just(Token::KwCost))
        .then(number.clone())
        .then(string.clone())
        .then_ignore(just(Token::Arrow))
        .then(ident.clone())
        .try_map(
            |((((from_raw, to_raw), cost_value), cost_unit), bucket): (
                (((String, String), f64), String),
                String,
            ),
             span| {
                let from = resolve_prefixed("scope", &from_raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                let to = resolve_prefixed("scope", &to_raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                let bucket = resolve_prefixed("bucket", &bucket)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::ScopeChangeRule(ScopeChangeRuleStmt {
                    from,
                    to,
                    cost_value,
                    cost_unit,
                    bucket,
                    span: make_span(file, span, &line_index),
                }))
            },
        );

    let difference_stmt = just(Token::KwDifference)
        .ignore_then(ident.clone())
        .then(just(Token::KwUnit).ignore_then(string.clone()).or_not())
        .try_map(|(raw, unit): (String, Option<String>), span| {
            let name = resolve_prefixed("difference", &raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            Ok(Stmt::Difference(DifferenceDecl {
                name,
                unit,
                span: make_span(file, span, &line_index),
            }))
        });

    let transform_stmt =
        just(Token::KwTransform)
            .ignore_then(ident.clone())
            .try_map(|raw: String, span| {
                let name = resolve_prefixed("transform", &raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::Transform(TransformDecl {
                    name,
                    span: make_span(file, span, &line_index),
                }))
            });

    let bucket_stmt =
        just(Token::KwBucket)
            .ignore_then(ident.clone())
            .try_map(|raw: String, span| {
                let name = resolve_prefixed("bucket", &raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::Bucket(BucketDecl {
                    name,
                    span: make_span(file, span, &line_index),
                }))
            });

    let constraint_stmt = just(Token::KwConstraint)
        .ignore_then(ident.clone())
        .try_map(|raw: String, span| {
            let name = resolve_prefixed("constraint", &raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            Ok(Stmt::Constraint(ConstraintDecl {
                name,
                span: make_span(file, span, &line_index),
            }))
        });

    let persist_stmt = just(Token::KwPersist)
        .ignore_then(ident.clone())
        .then_ignore(just(Token::KwUnder))
        .then(
            ident
                .clone()
                .separated_by(just(Token::Comma))
                .delimited_by(just(Token::LBracket), just(Token::RBracket)),
        )
        .try_map(|(raw, under): (String, Vec<String>), span| {
            let diff = resolve_prefixed("difference", &raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            let under = under
                .into_iter()
                .map(|u| {
                    resolve_prefixed("transform", &u)
                        .map_err(|msg| Simple::custom(span.clone(), msg))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Stmt::Persist(PersistStmt {
                diff,
                under,
                span: make_span(file, span, &line_index),
            }))
        });

    let erasure_rule_stmt = just(Token::KwErasureRule)
        .ignore_then(ident.clone())
        .then_ignore(just(Token::KwCost))
        .then(number.clone())
        .then(string.clone())
        .then_ignore(just(Token::Arrow))
        .then(ident.clone())
        .try_map(
            |(((raw, cost_value), cost_unit), bucket): (((String, f64), String), String), span| {
                let diff = resolve_prefixed("difference", &raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                let bucket = resolve_prefixed("bucket", &bucket)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::ErasureRule(ErasureRuleStmt {
                    diff,
                    cost_value,
                    cost_unit,
                    bucket,
                    span: make_span(file, span, &line_index),
                }))
            },
        );

    let permission_stmt = choice::<_, Simple<Token>>((
        just(Token::KwAllowErase)
            .ignore_then(ident.clone())
            .try_map(|raw: String, span| {
                let diff = resolve_prefixed("difference", &raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::Permission(PermissionStmt {
                    kind: PermissionKind::Allow,
                    diff,
                    span: make_span(file, span, &line_index),
                }))
            }),
        just(Token::KwDenyErase)
            .ignore_then(ident.clone())
            .try_map(|raw: String, span| {
                let diff = resolve_prefixed("difference", &raw)
                    .map_err(|msg| Simple::custom(span.clone(), msg))?;
                Ok(Stmt::Permission(PermissionStmt {
                    kind: PermissionKind::Deny,
                    diff,
                    span: make_span(file, span, &line_index),
                }))
            }),
    ));

    let commit_stmt = just(Token::KwCommit)
        .ignore_then(ident.clone())
        .then_ignore(just(Token::Eq))
        .then(commit_value.clone())
        .try_map(|(raw, value): (String, CommitValue), span| {
            let diff = resolve_prefixed("difference", &raw)
                .map_err(|msg| Simple::custom(span.clone(), msg))?;
            Ok(Stmt::Commit(CommitStmt {
                diff,
                value,
                span: make_span(file, span, &line_index),
            }))
        });

    let inadmissible_if_stmt = just(Token::KwInadmissibleIf)
        .ignore_then(expr.clone())
        .map_with_span(|expr, span| Stmt::InadmissibleIf {
            expr,
            span: make_span(file, span, &line_index),
        });

    let inadmissible_if_attr_stmt = just(Token::At)
        .ignore_then(just(Token::KwInadmissibleIf))
        .ignore_then(expr.clone())
        .map_with_span(|expr, span| Stmt::InadmissibleIf {
            expr,
            span: make_span(file, span, &line_index),
        });

    let query_stmt = just(Token::KwQuery)
        .ignore_then(choice::<_, Simple<Token>>((
            just(Token::KwAdmissible).to(QueryKind::Admissible),
            just(Token::KwWitness).to(QueryKind::Witness),
            just(Token::KwDelta).to(QueryKind::Delta),
            just(Token::KwLint)
                .ignore_then(just(Token::KwFailOn).ignore_then(ident.clone()).or_not())
                .try_map(|fail_on: Option<String>, span| {
                    let raw = fail_on.unwrap_or_else(|| "error".to_string());
                    let kind = match raw.as_str() {
                        "error" => crate::ast::LintFailOn::Error,
                        "warning" => crate::ast::LintFailOn::Warning,
                        "info" => crate::ast::LintFailOn::Info,
                        _ => {
                            return Err(Simple::custom(
                                span,
                                "invalid fail_on (expected error|warning|info)",
                            ))
                        }
                    };
                    Ok(QueryKind::Lint { fail_on: kind })
                }),
        )))
        .map_with_span(|kind, span| {
            Stmt::Query(QueryStmt {
                kind,
                span: make_span(file, span, &line_index),
            })
        });

    let tag_stmt = just(Token::KwTag)
        .ignore_then(ident.clone())
        .then(choice::<_, Simple<Token>>((ident.clone(), string.clone())))
        .map_with_span(|(key, value): (String, String), span| {
            Stmt::Tag(TagStmt {
                key,
                value,
                span: make_span(file, span, &line_index),
            })
        });

    let stmt = choice::<_, Simple<Token>>((
        module_stmt.map(|s| vec![s]),
        depends_stmt.map(|s| vec![s]),
        scope_stmt.map(|s| vec![s]),
        scope_change_stmt,
        allow_scope_change_stmt.map(|s| vec![s]),
        scope_change_rule_stmt.map(|s| vec![s]),
        difference_stmt.map(|s| vec![s]),
        transform_stmt.map(|s| vec![s]),
        bucket_stmt.map(|s| vec![s]),
        constraint_stmt.map(|s| vec![s]),
        tag_stmt.map(|s| vec![s]),
        persist_stmt.map(|s| vec![s]),
        erasure_rule_stmt.map(|s| vec![s]),
        permission_stmt.map(|s| vec![s]),
        commit_stmt.map(|s| vec![s]),
        inadmissible_if_attr_stmt.map(|s| vec![s]),
        inadmissible_if_stmt.map(|s| vec![s]),
        query_stmt.map(|s| vec![s]),
    ));

    let program = stmt.repeated().map(|chunks| {
        chunks
            .into_iter()
            .flat_map(|items| items.into_iter())
            .collect::<Vec<_>>()
    });
    let program = program.then_ignore(end());

    let (parsed, parse_errs) = program.parse_recovery(stream);
    if !parse_errs.is_empty() {
        let errs = parse_errs
            .into_iter()
            .map(|e| to_parse_error(e, file, &line_index))
            .collect::<Vec<_>>();
        return Err(errs);
    }

    Ok(Program {
        statements: parsed.unwrap_or_default(),
    })
}

fn parse_module_decl(raw: &str) -> Result<(String, u32), String> {
    let rest = raw.strip_prefix("module:").unwrap_or(raw);
    let (name, major) = rest
        .rsplit_once('@')
        .ok_or_else(|| "expected module:<name>@<major>".to_string())?;
    let major = major
        .parse::<u32>()
        .map_err(|_| "module major must be an integer".to_string())?;
    if name.is_empty() {
        return Err("module name cannot be empty".to_string());
    }
    Ok((name.to_string(), major))
}

fn parse_module_ref(raw: &str) -> Result<String, String> {
    let rest = raw.strip_prefix("module:").unwrap_or(raw);
    let (name, major) = rest
        .rsplit_once('@')
        .ok_or_else(|| "expected module:<name>@<major>".to_string())?;
    let major = major
        .parse::<u32>()
        .map_err(|_| "module major must be an integer".to_string())?;
    if name.is_empty() {
        return Err("module name cannot be empty".to_string());
    }
    Ok(format!("{}@{}", name, major))
}

fn resolve_prefixed(prefix: &str, raw: &str) -> Result<String, String> {
    if let Some((ns, rest)) = raw.split_once(':') {
        if ns == prefix {
            if rest.is_empty() {
                return Err(format!("empty {} name", prefix));
            }
            Ok(rest.to_string())
        } else {
            Ok(raw.to_string())
        }
    } else {
        Ok(raw.to_string())
    }
}
