use std::collections::{BTreeMap, BTreeSet};

use crate::error::EvalError;
use crate::ir::{LensRef, MetaRoute, Program, ScopeMode, Stmt};
use crate::span::Span;
use crate::symbols::{ScopeId, SymbolRef};
use crate::witness::PermissionKind;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct MetaChangeRecord {
    pub kind: String,
    pub from_lens: LensRef,
    pub to_lens: LensRef,
    pub payload_ref: String,
    pub routes: Vec<MetaRoute>,
    pub synthetic_diff_id: String,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Env {
    pub differences: BTreeMap<SymbolRef, Option<String>>,
    pub buckets: BTreeSet<SymbolRef>,
    pub transforms: BTreeSet<SymbolRef>,
    pub permissions: BTreeMap<SymbolRef, (PermissionKind, Span)>,
    pub erasure_rules: BTreeMap<SymbolRef, (crate::ir::Quantity, SymbolRef, Span)>,
    pub commits: BTreeMap<SymbolRef, crate::ir::CommitValue>,
    pub constraints: Vec<(Option<SymbolRef>, crate::ir::BoolExpr, Span)>,
    pub scope_changes: Vec<(ScopeId, ScopeId, ScopeMode, Span)>,
    pub lenses: BTreeMap<String, String>,
    pub active_lens: LensRef,
    pub meta_changes: Vec<MetaChangeRecord>,
    pub constraint_meta: BTreeMap<SymbolRef, BTreeMap<String, String>>,
    /// Conflicts where the same constraint key was set to different values.
    /// Tuple: (constraint_id, key, previous_value, new_value)
    pub meta_conflicts: Vec<(SymbolRef, String, String, String)>,
}

impl Env {
    pub fn from_program(program: &Program) -> Result<Self, EvalError> {
        let mut env = Env {
            differences: BTreeMap::new(),
            buckets: BTreeSet::new(),
            transforms: BTreeSet::new(),
            permissions: BTreeMap::new(),
            erasure_rules: BTreeMap::new(),
            commits: BTreeMap::new(),
            constraints: Vec::new(),
            scope_changes: Vec::new(),
            lenses: BTreeMap::new(),
            active_lens: LensRef {
                lens_id: "lens:default@0".to_string(),
                lens_hash: "lens:default:pending".to_string(),
            },
            meta_changes: Vec::new(),
            constraint_meta: BTreeMap::new(),
            meta_conflicts: Vec::new(),
        };

        for stmt in &program.statements {
            match stmt {
                Stmt::DeclareDifference { diff, unit, .. } => {
                    env.differences.insert(diff.clone(), unit.clone());
                }
                Stmt::DeclareTransform { transform, .. } => {
                    env.transforms.insert(transform.clone());
                }
                Stmt::Persist { .. } => {}
                Stmt::ErasureRule {
                    diff,
                    cost,
                    displaced_to,
                    span,
                } => {
                    env.erasure_rules.insert(
                        diff.clone(),
                        (cost.clone(), displaced_to.clone(), span.clone()),
                    );
                    env.buckets.insert(displaced_to.clone());
                }
                Stmt::AllowErase { diff, span } => {
                    env.permissions
                        .insert(diff.clone(), (PermissionKind::Allow, span.clone()));
                }
                Stmt::DenyErase { diff, span } => {
                    env.permissions
                        .insert(diff.clone(), (PermissionKind::Deny, span.clone()));
                }
                Stmt::ScopeChange {
                    from,
                    to,
                    mode,
                    span,
                } => {
                    env.scope_changes
                        .push((from.clone(), to.clone(), mode.clone(), span.clone()));
                }
                Stmt::LensDeclaration { lens, .. } => {
                    env.lenses
                        .insert(lens.lens_id.clone(), lens.lens_hash.clone());
                    env.active_lens = lens.clone();
                }
                Stmt::MetaChange {
                    kind,
                    from_lens,
                    to_lens_id,
                    payload_ref,
                    routes,
                    span,
                } => {
                    let to_lens_hash = derive_lens_hash(&from_lens.lens_hash, kind, payload_ref);
                    let to_lens_id = to_lens_id.clone().unwrap_or_else(|| {
                        format!(
                            "lens:derived:{}@0",
                            &to_lens_hash[..12.min(to_lens_hash.len())]
                        )
                    });
                    env.lenses.insert(to_lens_id.clone(), to_lens_hash.clone());
                    let synthetic_diff_id = format!(
                        "difference:lens_change:{}->{}:{}",
                        from_lens.lens_hash, to_lens_hash, kind
                    );
                    env.meta_changes.push(MetaChangeRecord {
                        kind: kind.clone(),
                        from_lens: from_lens.clone(),
                        to_lens: LensRef {
                            lens_id: to_lens_id.clone(),
                            lens_hash: to_lens_hash.clone(),
                        },
                        payload_ref: payload_ref.clone(),
                        routes: routes.clone(),
                        synthetic_diff_id,
                        span: span.clone(),
                    });
                    env.active_lens = LensRef {
                        lens_id: to_lens_id,
                        lens_hash: to_lens_hash,
                    };
                }
                Stmt::Commit { diff, value, .. } => {
                    env.commits.insert(diff.clone(), value.clone());
                }
                Stmt::Constraint { id, expr, span } => {
                    env.constraints
                        .push((id.clone(), expr.clone(), span.clone()));
                }
                Stmt::ConstraintMeta { id, key, value, .. } => {
                    let meta = env.constraint_meta.entry(id.clone()).or_default();
                    if let Some(prev) = meta.get(key) {
                        if prev != value {
                            env.meta_conflicts.push((
                                id.clone(),
                                key.clone(),
                                prev.clone(),
                                value.clone(),
                            ));
                        }
                    }
                    meta.insert(key.clone(), value.clone());
                }
                Stmt::Query { .. } => {}
            }
        }

        Ok(env)
    }

    pub fn is_allowed(&self, diff: &SymbolRef) -> bool {
        matches!(self.permissions.get(diff), Some((PermissionKind::Allow, _)))
    }
}

fn derive_lens_hash(from_lens_hash: &str, kind: &str, payload_ref: &str) -> String {
    let payload = serde_json::json!({
        "from_lens_hash": from_lens_hash,
        "kind": kind,
        "payload_ref": payload_ref,
    });
    let mut hasher = Sha256::new();
    hasher.update(payload.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}
