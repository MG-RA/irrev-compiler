//! Provider implementation for the `deps.manifest` scope.
//!
//! Snapshot is deterministic filesystem observation over dependency manifests.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use admit_core::provider_trait::Provider;
use admit_core::provider_types::*;
use admit_core::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, WitnessBuilder, WitnessProgram,
};
use admit_core::{ModuleId, ScopeId, Span};
use sha2::{Digest, Sha256};

use crate::backend::{DEPS_MANIFEST_SCHEMA_ID, DEPS_MANIFEST_SCOPE_ID};

const RULE_MANIFEST_FILE: &str = "deps/manifest_file";
const RULE_LOCK_FILE: &str = "deps/lock_file";
const RULE_DEP: &str = "deps/dep";
const RULE_LOCK_ENTRY: &str = "deps/lock_entry";

const RULE_GIT_DEP_PRESENT: &str = "deps/git_dependency_present";
const RULE_WILDCARD_VERSION_PRESENT: &str = "deps/wildcard_version_present";
const RULE_LOCKFILE_MISSING: &str = "deps/lockfile_missing";
const RULE_UNAPPROVED_DEP: &str = "deps/unapproved_dependency";

#[derive(Debug, Clone)]
struct ManifestRecord {
    path: String,
    kind: String,
    dir: String,
}

#[derive(Debug, Clone)]
struct LockRecord {
    path: String,
    kind: String,
    dir: String,
}

#[derive(Debug, Clone)]
struct DependencyRecord {
    manifest_path: String,
    manifest_kind: String,
    section: String,
    name: String,
    package_name: Option<String>,
    version_req: Option<String>,
    source_kind: String,
}

#[derive(Debug, Clone)]
struct LockEntryRecord {
    lock_path: String,
    lock_kind: String,
    name: String,
    version: String,
    source: Option<String>,
}

/// Provider for deterministic dependency manifest extraction.
pub struct DepsManifestProvider;

impl DepsManifestProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DepsManifestProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for DepsManifestProvider {
    fn describe(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string()),
            version: 1,
            schema_ids: vec![DEPS_MANIFEST_SCHEMA_ID.to_string()],
            supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
            deterministic: true,
            closure: ClosureRequirements {
                requires_fs: true,
                ..ClosureRequirements::default()
            },
            required_approvals: vec![],
            predicates: vec![
                PredicateDescriptor {
                    name: "git_dependency_present".to_string(),
                    doc: "Triggers when dependency facts indicate git-sourced dependencies."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
                PredicateDescriptor {
                    name: "wildcard_version_present".to_string(),
                    doc: "Triggers when dependency facts indicate wildcard dependency versions."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
                PredicateDescriptor {
                    name: "lockfile_missing".to_string(),
                    doc: "Triggers when manifests are present without corresponding lockfiles."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
                PredicateDescriptor {
                    name: "unapproved_dependency".to_string(),
                    doc: "Triggers for dependency names that are not in params.allowed."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts", "allowed"],
                        "properties": {
                            "facts": { "type": "array" },
                            "allowed": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    })),
                },
            ],
        }
    }

    fn snapshot(&self, req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
        let scope_id = ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string());
        let root_str = req
            .params
            .get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: "params.root (string) is required".to_string(),
            })?;
        let root = Path::new(root_str);
        if !root.is_dir() {
            return Err(ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("root path is not a directory: {}", root_str),
            });
        }

        let files = walk_files(root).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: err,
        })?;

        let mut manifests = Vec::<ManifestRecord>::new();
        let mut locks = Vec::<LockRecord>::new();
        let mut deps = Vec::<DependencyRecord>::new();
        let mut lock_entries = Vec::<LockEntryRecord>::new();

        for file in files {
            let rel = to_rel_path(root, &file).map_err(|err| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: err,
            })?;
            let file_name = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
            match file_name {
                "Cargo.toml" => {
                    let text = std::fs::read_to_string(&file).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: format!("read '{}': {}", rel, err),
                    })?;
                    manifests.push(ManifestRecord {
                        dir: parent_dir(&rel),
                        kind: "cargo_toml".to_string(),
                        path: rel.clone(),
                    });
                    parse_cargo_manifest(&text, &rel, &mut deps).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: err,
                    })?;
                }
                "Cargo.lock" => {
                    let text = std::fs::read_to_string(&file).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: format!("read '{}': {}", rel, err),
                    })?;
                    locks.push(LockRecord {
                        dir: parent_dir(&rel),
                        kind: "cargo_lock".to_string(),
                        path: rel.clone(),
                    });
                    parse_cargo_lock(&text, &rel, &mut lock_entries).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: err,
                    })?;
                }
                "package.json" => {
                    let text = std::fs::read_to_string(&file).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: format!("read '{}': {}", rel, err),
                    })?;
                    manifests.push(ManifestRecord {
                        dir: parent_dir(&rel),
                        kind: "package_json".to_string(),
                        path: rel.clone(),
                    });
                    parse_package_json(&text, &rel, &mut deps).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: err,
                    })?;
                }
                "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => {
                    locks.push(LockRecord {
                        dir: parent_dir(&rel),
                        kind: "npm_lock".to_string(),
                        path: rel.clone(),
                    });
                }
                _ => {}
            }
        }

        manifests.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(a.path.cmp(&b.path))
                .then(a.dir.cmp(&b.dir))
        });
        locks.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(a.path.cmp(&b.path))
                .then(a.dir.cmp(&b.dir))
        });
        deps.sort_by(|a, b| dep_sort_key(a).cmp(&dep_sort_key(b)));
        lock_entries.sort_by(|a, b| lock_entry_sort_key(a).cmp(&lock_entry_sort_key(b)));

        let mut facts = Vec::<Fact>::new();
        for manifest in &manifests {
            facts.push(manifest_fact(manifest));
        }
        for lock in &locks {
            facts.push(lock_fact(lock));
        }
        for dep in &deps {
            facts.push(dep_fact(dep));
        }
        for entry in &lock_entries {
            facts.push(lock_entry_fact(entry));
        }
        facts.sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));

        let facts_value = serde_json::to_value(&facts).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("facts serialization failed: {}", err),
        })?;
        let cbor = admit_core::encode_canonical_value(&facts_value).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("facts canonical encoding failed: {}", err),
        })?;
        let mut hasher = Sha256::new();
        hasher.update(cbor);
        let snapshot_hash = Sha256Hex::new(format!("{:x}", hasher.finalize()));

        let created_at = req
            .params
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(now_rfc3339);

        let facts_bundle = FactsBundle {
            schema_id: DEPS_MANIFEST_SCHEMA_ID.to_string(),
            scope_id: scope_id.clone(),
            facts: facts.clone(),
            snapshot_hash,
            created_at: Rfc3339Timestamp::new(created_at),
        };

        let witness_program = WitnessProgram {
            module: ModuleId(format!("provider/{}", DEPS_MANIFEST_SCOPE_ID)),
            scope: scope_id,
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: Some(facts_bundle.snapshot_hash.0.clone()),
            facts_bundle_hash: None,
            ruleset_hash: None,
        };
        let witness = WitnessBuilder::new(witness_program, Verdict::Admissible, "snapshot complete")
            .with_facts(facts)
            .with_displacement_trace(DisplacementTrace {
                mode: DisplacementMode::Potential,
                totals: vec![],
                contributions: vec![],
            })
            .build();

        Ok(SnapshotResult {
            facts_bundle,
            witness,
        })
    }

    fn eval_predicate(
        &self,
        name: &str,
        params: &serde_json::Value,
    ) -> Result<PredicateResult, ProviderError> {
        let scope_id = ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string());
        let facts = decode_facts(params, &scope_id)?;
        let deps = extract_dependency_records(&facts);
        let manifests = extract_manifest_records(&facts);
        let locks = extract_lock_records(&facts);

        match name {
            "git_dependency_present" => eval_git_dependency_present(&deps),
            "wildcard_version_present" => eval_wildcard_version_present(&deps),
            "lockfile_missing" => eval_lockfile_missing(&manifests, &locks),
            "unapproved_dependency" => eval_unapproved_dependency(params, &scope_id, &deps),
            _ => Err(ProviderError {
                scope: scope_id,
                phase: ProviderPhase::Snapshot,
                message: format!("predicate '{}' not supported", name),
            }),
        }
    }
}

fn decode_facts(
    params: &serde_json::Value,
    scope_id: &ScopeId,
) -> Result<Vec<Fact>, ProviderError> {
    let value = params.get("facts").cloned().ok_or_else(|| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: "predicate requires params.facts".to_string(),
    })?;
    serde_json::from_value(value).map_err(|err| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: format!("decode params.facts: {}", err),
    })
}

fn parse_allowed_names(
    params: &serde_json::Value,
    scope_id: &ScopeId,
) -> Result<BTreeSet<String>, ProviderError> {
    let arr = params
        .get("allowed")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: "predicate requires params.allowed (array<string>)".to_string(),
        })?;
    let mut out = BTreeSet::new();
    for item in arr {
        let Some(name) = item.as_str() else {
            return Err(ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: "predicate params.allowed must contain only strings".to_string(),
            });
        };
        out.insert(name.to_string());
    }
    Ok(out)
}

fn eval_git_dependency_present(deps: &[DependencyRecord]) -> Result<PredicateResult, ProviderError> {
    let mut findings = Vec::new();
    for dep in deps {
        if dep.source_kind == "git" {
            findings.push(dep_finding(
                RULE_GIT_DEP_PRESENT,
                dep,
                format!("git dependency present: {}", dep.name),
                None,
            ));
        }
    }
    sort_findings(&mut findings);
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn eval_wildcard_version_present(
    deps: &[DependencyRecord],
) -> Result<PredicateResult, ProviderError> {
    let mut findings = Vec::new();
    for dep in deps {
        let Some(req) = dep.version_req.as_deref() else {
            continue;
        };
        if is_wildcard_req(req) {
            findings.push(dep_finding(
                RULE_WILDCARD_VERSION_PRESENT,
                dep,
                format!("wildcard dependency version: {}", dep.name),
                Some(serde_json::json!({ "version_req": req })),
            ));
        }
    }
    sort_findings(&mut findings);
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn eval_lockfile_missing(
    manifests: &[ManifestRecord],
    locks: &[LockRecord],
) -> Result<PredicateResult, ProviderError> {
    let mut findings = Vec::new();

    let cargo_manifests: Vec<&ManifestRecord> =
        manifests.iter().filter(|m| m.kind == "cargo_toml").collect();
    let has_cargo_lock = locks.iter().any(|l| l.kind == "cargo_lock");
    if !cargo_manifests.is_empty() && !has_cargo_lock {
        for manifest in &cargo_manifests {
            findings.push(admit_core::LintFinding {
                rule_id: RULE_LOCKFILE_MISSING.to_string(),
                severity: Severity::Error,
                invariant: Some("deps.lockfile".to_string()),
                path: manifest.path.clone(),
                span: span_for_path(&manifest.path),
                message: "Cargo.lock missing for Cargo.toml observation set".to_string(),
                evidence: Some(serde_json::json!({
                    "manifest_kind": manifest.kind,
                    "manifest_path": manifest.path,
                    "manifest_dir": manifest.dir,
                    "expected_lock_kind": "cargo_lock"
                })),
            });
        }
    }

    let npm_locks_by_dir: BTreeSet<String> = locks
        .iter()
        .filter(|l| l.kind == "npm_lock")
        .map(|l| l.dir.clone())
        .collect();
    for manifest in manifests.iter().filter(|m| m.kind == "package_json") {
        if !npm_locks_by_dir.contains(manifest.dir.as_str()) {
            findings.push(admit_core::LintFinding {
                rule_id: RULE_LOCKFILE_MISSING.to_string(),
                severity: Severity::Error,
                invariant: Some("deps.lockfile".to_string()),
                path: manifest.path.clone(),
                span: span_for_path(&manifest.path),
                message: "package lockfile missing next to package.json".to_string(),
                evidence: Some(serde_json::json!({
                    "manifest_kind": manifest.kind,
                    "manifest_path": manifest.path,
                    "manifest_dir": manifest.dir,
                    "expected_lock_kind": "npm_lock"
                })),
            });
        }
    }

    sort_findings(&mut findings);
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn eval_unapproved_dependency(
    params: &serde_json::Value,
    scope_id: &ScopeId,
    deps: &[DependencyRecord],
) -> Result<PredicateResult, ProviderError> {
    let allowed = parse_allowed_names(params, scope_id)?;
    let mut findings = Vec::new();
    for dep in deps {
        let package_name = dep.package_name.as_deref().unwrap_or(dep.name.as_str());
        if !allowed.contains(package_name) {
            findings.push(dep_finding(
                RULE_UNAPPROVED_DEP,
                dep,
                format!("dependency not in approved list: {}", package_name),
                Some(serde_json::json!({ "approved": false })),
            ));
        }
    }
    sort_findings(&mut findings);
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn parse_cargo_manifest(
    text: &str,
    manifest_path: &str,
    deps: &mut Vec<DependencyRecord>,
) -> Result<(), String> {
    let value: toml::Value = toml::from_str(text)
        .map_err(|err| format!("parse Cargo.toml '{}': {}", manifest_path, err))?;
    collect_cargo_dependency_tables(&value, "", manifest_path, deps);
    Ok(())
}

fn collect_cargo_dependency_tables(
    value: &toml::Value,
    table_path: &str,
    manifest_path: &str,
    deps: &mut Vec<DependencyRecord>,
) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        let next_path = if table_path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{}", table_path, key)
        };
        if is_supported_cargo_dependency_path(&next_path) {
            if let Some(dep_table) = child.as_table() {
                for (name, spec) in dep_table {
                    deps.push(parse_cargo_dependency(manifest_path, &next_path, name, spec));
                }
            }
            continue;
        }
        collect_cargo_dependency_tables(child, &next_path, manifest_path, deps);
    }
}

fn is_supported_cargo_dependency_path(path: &str) -> bool {
    match path {
        "dependencies" | "dev-dependencies" | "build-dependencies" | "workspace.dependencies" => {
            true
        }
        _ => path.starts_with("target.")
            && (path.ends_with(".dependencies")
                || path.ends_with(".dev-dependencies")
                || path.ends_with(".build-dependencies")),
    }
}

fn parse_cargo_dependency(
    manifest_path: &str,
    section: &str,
    name: &str,
    spec: &toml::Value,
) -> DependencyRecord {
    let mut package_name: Option<String> = None;
    let mut version_req: Option<String> = None;
    let mut source_kind = "unknown".to_string();

    if let Some(req) = spec.as_str() {
        version_req = Some(req.to_string());
        source_kind = "registry".to_string();
    } else if let Some(spec_table) = spec.as_table() {
        package_name = spec_table
            .get("package")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(req) = spec_table.get("version").and_then(|v| v.as_str()) {
            version_req = Some(req.to_string());
        }
        if spec_table.get("git").and_then(|v| v.as_str()).is_some() {
            source_kind = "git".to_string();
        } else if spec_table.get("path").and_then(|v| v.as_str()).is_some() {
            source_kind = "path".to_string();
        } else if spec_table
            .get("workspace")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            source_kind = "workspace".to_string();
        } else if version_req.is_some() {
            source_kind = "registry".to_string();
        }
    }

    DependencyRecord {
        manifest_path: manifest_path.to_string(),
        manifest_kind: "cargo_toml".to_string(),
        section: section.to_string(),
        name: name.to_string(),
        package_name,
        version_req,
        source_kind,
    }
}

fn parse_cargo_lock(
    text: &str,
    lock_path: &str,
    entries: &mut Vec<LockEntryRecord>,
) -> Result<(), String> {
    let value: toml::Value = toml::from_str(text)
        .map_err(|err| format!("parse Cargo.lock '{}': {}", lock_path, err))?;
    let Some(array) = value.get("package").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    for item in array {
        let Some(tbl) = item.as_table() else {
            continue;
        };
        let Some(name) = tbl.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = tbl.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        entries.push(LockEntryRecord {
            lock_path: lock_path.to_string(),
            lock_kind: "cargo_lock".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source: tbl
                .get("source")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
    }
    Ok(())
}

fn parse_package_json(
    text: &str,
    manifest_path: &str,
    deps: &mut Vec<DependencyRecord>,
) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|err| format!("parse package.json '{}': {}", manifest_path, err))?;
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(dep_obj) = obj.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, spec_value) in dep_obj {
            let Some(req) = spec_value.as_str() else {
                continue;
            };
            let source_kind = npm_source_kind(req);
            deps.push(DependencyRecord {
                manifest_path: manifest_path.to_string(),
                manifest_kind: "package_json".to_string(),
                section: section.to_string(),
                name: name.to_string(),
                package_name: None,
                version_req: Some(req.to_string()),
                source_kind,
            });
        }
    }
    Ok(())
}

fn npm_source_kind(req: &str) -> String {
    let req_lc = req.to_lowercase();
    if req_lc.starts_with("git+")
        || req_lc.starts_with("github:")
        || req_lc.contains("github.com")
        || req_lc.contains("git@")
    {
        "git".to_string()
    } else if req_lc.starts_with("file:") || req_lc.starts_with("link:") {
        "path".to_string()
    } else if req_lc.starts_with("workspace:") {
        "workspace".to_string()
    } else {
        "registry".to_string()
    }
}

fn manifest_fact(manifest: &ManifestRecord) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_MANIFEST_FILE.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: manifest.path.clone(),
        span: span_for_path(&manifest.path),
        message: format!("dependency manifest ({})", manifest.kind),
        evidence: Some(serde_json::json!({
            "manifest_kind": manifest.kind,
            "manifest_dir": manifest.dir
        })),
    }
}

fn lock_fact(lock: &LockRecord) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_LOCK_FILE.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: lock.path.clone(),
        span: span_for_path(&lock.path),
        message: format!("dependency lockfile ({})", lock.kind),
        evidence: Some(serde_json::json!({
            "lock_kind": lock.kind,
            "lock_dir": lock.dir
        })),
    }
}

fn dep_fact(dep: &DependencyRecord) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_DEP.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: dep.manifest_path.clone(),
        span: span_for_path(&dep.manifest_path),
        message: format!("dependency {} ({})", dep.name, dep.source_kind),
        evidence: Some(serde_json::json!({
            "manifest_kind": dep.manifest_kind,
            "section": dep.section,
            "name": dep.name,
            "package_name": dep.package_name,
            "version_req": dep.version_req,
            "source_kind": dep.source_kind
        })),
    }
}

fn lock_entry_fact(entry: &LockEntryRecord) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_LOCK_ENTRY.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: entry.lock_path.clone(),
        span: span_for_path(&entry.lock_path),
        message: format!("lock entry {}@{}", entry.name, entry.version),
        evidence: Some(serde_json::json!({
            "lock_kind": entry.lock_kind,
            "name": entry.name,
            "version": entry.version,
            "source": entry.source
        })),
    }
}

fn extract_dependency_records(facts: &[Fact]) -> Vec<DependencyRecord> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            path,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_DEP {
            continue;
        }
        let Some(obj) = evidence.as_object() else {
            continue;
        };
        let section = obj
            .get("section")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let manifest_kind = obj
            .get("manifest_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let source_kind = obj
            .get("source_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if name.is_empty() {
            continue;
        }
        out.push(DependencyRecord {
            manifest_path: path.clone(),
            manifest_kind,
            section,
            name,
            package_name: obj
                .get("package_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            version_req: obj
                .get("version_req")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            source_kind,
        });
    }
    out.sort_by(|a, b| dep_sort_key(a).cmp(&dep_sort_key(b)));
    out
}

fn extract_manifest_records(facts: &[Fact]) -> Vec<ManifestRecord> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            path,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_MANIFEST_FILE {
            continue;
        }
        let Some(obj) = evidence.as_object() else {
            continue;
        };
        let kind = obj
            .get("manifest_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if kind.is_empty() {
            continue;
        }
        let dir = obj
            .get("manifest_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.push(ManifestRecord {
            path: path.clone(),
            kind,
            dir,
        });
    }
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.path.cmp(&b.path))
            .then(a.dir.cmp(&b.dir))
    });
    out
}

fn extract_lock_records(facts: &[Fact]) -> Vec<LockRecord> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            path,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_LOCK_FILE {
            continue;
        }
        let Some(obj) = evidence.as_object() else {
            continue;
        };
        let kind = obj
            .get("lock_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if kind.is_empty() {
            continue;
        }
        let dir = obj
            .get("lock_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.push(LockRecord {
            path: path.clone(),
            kind,
            dir,
        });
    }
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.path.cmp(&b.path))
            .then(a.dir.cmp(&b.dir))
    });
    out
}

fn dep_finding(
    rule_id: &str,
    dep: &DependencyRecord,
    message: String,
    extra_evidence: Option<serde_json::Value>,
) -> admit_core::LintFinding {
    let mut evidence = serde_json::json!({
        "manifest_kind": dep.manifest_kind,
        "manifest_path": dep.manifest_path,
        "section": dep.section,
        "name": dep.name,
        "package_name": dep.package_name,
        "version_req": dep.version_req,
        "source_kind": dep.source_kind
    });
    if let (Some(extra), Some(base)) = (extra_evidence, evidence.as_object_mut()) {
        base.insert("detail".to_string(), extra);
    }
    admit_core::LintFinding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        invariant: Some("deps.policy".to_string()),
        path: dep.manifest_path.clone(),
        span: span_for_path(&dep.manifest_path),
        message,
        evidence: Some(evidence),
    }
}

fn is_wildcard_req(req: &str) -> bool {
    let trimmed = req.trim();
    trimmed == "*" || trimmed.eq_ignore_ascii_case("x")
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|err| format!("read_dir '{}': {}", dir.display(), err))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("read_dir entry: {}", err))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("file_type '{}': {}", path.display(), err))?;
            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }
    files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    Ok(files)
}

fn should_skip_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(
        name,
        ".git" | "target" | "out" | "node_modules" | ".venv" | ".mypy_cache" | "logs"
    )
}

fn to_rel_path(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|err| format!("strip_prefix '{}': {}", path.display(), err))?;
    let mut out = Vec::new();
    for comp in rel.components() {
        let s = comp
            .as_os_str()
            .to_str()
            .ok_or_else(|| format!("non-utf8 path component under root: {}", path.display()))?;
        out.push(s);
    }
    Ok(out.join("/"))
}

fn parent_dir(path: &str) -> String {
    let mut parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= 1 {
        return ".".to_string();
    }
    parts.pop();
    parts.join("/")
}

fn span_for_path(path: &str) -> Span {
    Span {
        file: path.to_string(),
        start: None,
        end: None,
        line: None,
        col: None,
    }
}

fn sort_findings(findings: &mut [admit_core::LintFinding]) {
    findings.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(a.path.cmp(&b.path))
            .then(a.span.file.cmp(&b.span.file))
            .then(a.span.line.unwrap_or(0).cmp(&b.span.line.unwrap_or(0)))
            .then(a.span.col.unwrap_or(0).cmp(&b.span.col.unwrap_or(0)))
            .then(a.message.cmp(&b.message))
    });
}

fn dep_sort_key(dep: &DependencyRecord) -> (String, String, String, String, String) {
    (
        dep.manifest_path.clone(),
        dep.section.clone(),
        dep.name.clone(),
        dep.package_name.clone().unwrap_or_default(),
        dep.source_kind.clone(),
    )
}

fn lock_entry_sort_key(entry: &LockEntryRecord) -> (String, String, String, String, String) {
    (
        entry.lock_path.clone(),
        entry.lock_kind.clone(),
        entry.name.clone(),
        entry.version.clone(),
        entry.source.clone().unwrap_or_default(),
    )
}

fn fact_sort_key(fact: &Fact) -> (u8, String, String, u32, u32) {
    let type_rank = match fact {
        Fact::ConstraintTriggered { .. } => 0,
        Fact::PermissionUsed { .. } => 1,
        Fact::ErasureRuleUsed { .. } => 2,
        Fact::CommitUsed { .. } => 3,
        Fact::PredicateEvaluated { .. } => 4,
        Fact::RuleEvaluated { .. } => 5,
        Fact::ScopeChangeUsed { .. } => 6,
        Fact::UnaccountedBoundaryChange { .. } => 7,
        Fact::LintFinding { .. } => 8,
    };
    let aux = match fact {
        Fact::RuleEvaluated { rule_id, .. } => rule_id.clone(),
        Fact::LintFinding { rule_id, .. } => rule_id.clone(),
        _ => String::new(),
    };
    let span = match fact {
        Fact::ConstraintTriggered { span, .. }
        | Fact::PermissionUsed { span, .. }
        | Fact::ErasureRuleUsed { span, .. }
        | Fact::CommitUsed { span, .. }
        | Fact::PredicateEvaluated { span, .. }
        | Fact::RuleEvaluated { span, .. }
        | Fact::ScopeChangeUsed { span, .. }
        | Fact::UnaccountedBoundaryChange { span, .. }
        | Fact::LintFinding { span, .. } => span,
    };
    (
        type_rank,
        aux,
        span.file.clone(),
        span.line.unwrap_or(0),
        span.col.unwrap_or(0),
    )
}

fn now_rfc3339() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", dur.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("admit-scope-deps-{}-{}", label, nanos));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn describe_returns_expected_scope() {
        let provider = DepsManifestProvider::new();
        let desc = provider.describe();
        assert_eq!(desc.scope_id.0, DEPS_MANIFEST_SCOPE_ID);
        assert!(desc.deterministic);
        assert!(desc.closure.requires_fs);
        assert_eq!(desc.schema_ids, vec![DEPS_MANIFEST_SCHEMA_ID]);
    }

    #[test]
    fn snapshot_rejects_missing_root() {
        let provider = DepsManifestProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string()),
            params: serde_json::Value::Null,
        };
        let err = provider.snapshot(&req).expect_err("missing root should fail");
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("params.root"));
    }

    #[test]
    fn snapshot_emits_manifest_dep_and_lock_facts() {
        let root = temp_dir("snapshot");
        std::fs::write(
            root.join("Cargo.toml"),
            r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
git_dep = { git = "https://example.com/repo.git" }
wild = "*"
"#,
        )
        .expect("write Cargo.toml");
        std::fs::write(
            root.join("Cargo.lock"),
            r#"
version = 3

[[package]]
name = "serde"
version = "1.0.0"
"#,
        )
        .expect("write Cargo.lock");

        let provider = DepsManifestProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string()),
            params: serde_json::json!({
                "root": root.to_string_lossy(),
                "created_at": "2026-02-11T00:00:00Z"
            }),
        };
        let out = provider.snapshot(&req).expect("snapshot");
        assert_eq!(out.facts_bundle.created_at.0, "2026-02-11T00:00:00Z");
        assert!(
            out.facts_bundle
                .facts
                .iter()
                .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_MANIFEST_FILE))
        );
        assert!(
            out.facts_bundle
                .facts
                .iter()
                .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_LOCK_FILE))
        );
        assert!(
            out.facts_bundle
                .facts
                .iter()
                .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_DEP))
        );
        assert!(
            out.facts_bundle
                .facts
                .iter()
                .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_LOCK_ENTRY))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn git_dependency_predicate_uses_fact_input() {
        let provider = DepsManifestProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: RULE_DEP.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "Cargo.toml".to_string(),
            span: span_for_path("Cargo.toml"),
            message: "dependency git_dep (git)".to_string(),
            evidence: Some(serde_json::json!({
                "manifest_kind": "cargo_toml",
                "section": "dependencies",
                "name": "git_dep",
                "package_name": null,
                "version_req": null,
                "source_kind": "git"
            })),
        }];
        let out = provider
            .eval_predicate("git_dependency_present", &serde_json::json!({ "facts": facts }))
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RULE_GIT_DEP_PRESENT);
    }

    #[test]
    fn lockfile_missing_predicate_detects_missing_cargo_lock() {
        let provider = DepsManifestProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: RULE_MANIFEST_FILE.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "Cargo.toml".to_string(),
            span: span_for_path("Cargo.toml"),
            message: "dependency manifest (cargo_toml)".to_string(),
            evidence: Some(serde_json::json!({
                "manifest_kind": "cargo_toml",
                "manifest_dir": "."
            })),
        }];
        let out = provider
            .eval_predicate("lockfile_missing", &serde_json::json!({ "facts": facts }))
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RULE_LOCKFILE_MISSING);
    }

    #[test]
    fn unapproved_dependency_respects_allowed_list() {
        let provider = DepsManifestProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: RULE_DEP.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "Cargo.toml".to_string(),
            span: span_for_path("Cargo.toml"),
            message: "dependency serde (registry)".to_string(),
            evidence: Some(serde_json::json!({
                "manifest_kind": "cargo_toml",
                "section": "dependencies",
                "name": "serde",
                "package_name": null,
                "version_req": "1.0",
                "source_kind": "registry"
            })),
        }];
        let out = provider
            .eval_predicate(
                "unapproved_dependency",
                &serde_json::json!({
                    "facts": facts,
                    "allowed": ["anyhow"]
                }),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RULE_UNAPPROVED_DEP);
    }
}
