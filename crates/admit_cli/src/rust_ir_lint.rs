use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use syn::Item;

use super::artifact::{default_artifacts_dir, store_artifact};
use super::internal::{payload_hash, sha256_hex, RUST_IR_LINT_WITNESS_SCHEMA_ID};
use super::registry::resolve_meta_registry;
use super::types::{
    DeclareCostError, RustIrLintEvent, RustIrLintPayload, RustIrLintViolation, RustIrLintWitness,
};

const RUST_IR_LINT_WITNESS_KIND: &str = "rust_ir_lint_witness";
const RUST_IR_LINT_SCOPE_ID: &str = "scope:rust.ir_lint";
const RUST_IR_LINT_RULE_PACK: &str = "core";
const RUST_IR_LINT_RULES: [&str; 6] = [
    "IR-RS-02", "IR-RS-03", "IR-RS-04", "IR-RS-05", "IR-RS-08", "IR-RS-13",
];

#[derive(Debug, Clone)]
pub struct RustIrLintInput {
    pub root: PathBuf,
    pub timestamp: String,
    pub tool_version: String,
    pub artifacts_root: Option<PathBuf>,
    pub meta_registry_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RustIrLintRunOutput {
    pub event: RustIrLintEvent,
    pub witness: RustIrLintWitness,
}

#[derive(Debug, Clone)]
struct RustFileInput {
    rel_path: String,
    text: String,
    sha256: String,
}

pub fn run_rust_ir_lint(input: RustIrLintInput) -> Result<RustIrLintRunOutput, DeclareCostError> {
    if !input.root.exists() {
        return Err(DeclareCostError::Io(format!(
            "lint path does not exist: {}",
            input.root.display()
        )));
    }

    let registry_resolved = resolve_meta_registry(input.meta_registry_path.as_deref())?;
    let registry_ref = registry_resolved.as_ref().map(|r| &r.registry);
    let registry_hash = registry_resolved.as_ref().map(|r| r.hash.clone());

    let files = load_rust_files(&input.root)?;

    let mut violations = Vec::new();
    for file in &files {
        violations.extend(scan_core_violations(file));
    }
    violations.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(a.file.cmp(&b.file))
            .then(a.line.unwrap_or(0).cmp(&b.line.unwrap_or(0)))
            .then(a.message.cmp(&b.message))
    });
    violations.dedup();

    let mut input_manifest = Vec::with_capacity(files.len());
    let mut input_ids = Vec::with_capacity(files.len());
    for file in &files {
        input_ids.push(file.sha256.clone());
        input_manifest.push(json!({
            "path": file.rel_path,
            "sha256": file.sha256
        }));
    }
    let input_manifest_cbor =
        admit_core::encode_canonical_value(&serde_json::Value::Array(input_manifest))
            .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let input_id = sha256_hex(&input_manifest_cbor);

    let config = json!({
        "rule_pack": RUST_IR_LINT_RULE_PACK,
        "rules": RUST_IR_LINT_RULES
    });
    let config_cbor = admit_core::encode_canonical_value(&config)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let config_hash = sha256_hex(&config_cbor);

    let witness = RustIrLintWitness {
        schema_id: RUST_IR_LINT_WITNESS_SCHEMA_ID.to_string(),
        schema_version: 1,
        created_at: input.timestamp.clone(),
        scope_id: RUST_IR_LINT_SCOPE_ID.to_string(),
        engine_version: input.tool_version,
        input_root: normalize_path(&input.root),
        input_id,
        input_ids,
        config_hash,
        rule_pack: RUST_IR_LINT_RULE_PACK.to_string(),
        rules: RUST_IR_LINT_RULES
            .iter()
            .map(|r| (*r).to_string())
            .collect(),
        files_scanned: files.len() as u64,
        violations: violations.clone(),
        passed: violations.is_empty(),
    };

    let witness_value =
        serde_json::to_value(&witness).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let witness_cbor = admit_core::encode_canonical_value(&witness_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let witness_json =
        serde_json::to_vec(&witness).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let artifacts_root = input.artifacts_root.unwrap_or_else(default_artifacts_dir);
    let witness_ref = store_artifact(
        &artifacts_root,
        RUST_IR_LINT_WITNESS_KIND,
        RUST_IR_LINT_WITNESS_SCHEMA_ID,
        &witness_cbor,
        "cbor",
        Some(witness_json),
        registry_ref,
    )?;

    let payload = RustIrLintPayload {
        event_type: "rust.ir_lint.completed".to_string(),
        timestamp: input.timestamp.clone(),
        witness: witness_ref.clone(),
        scope_id: RUST_IR_LINT_SCOPE_ID.to_string(),
        rule_pack: RUST_IR_LINT_RULE_PACK.to_string(),
        rules: RUST_IR_LINT_RULES
            .iter()
            .map(|r| (*r).to_string())
            .collect(),
        files_scanned: witness.files_scanned,
        violations: witness.violations.len() as u64,
        passed: witness.passed,
        registry_hash: registry_hash.clone(),
    };
    let event_id = payload_hash(&payload)?;
    let event = RustIrLintEvent {
        event_type: payload.event_type,
        event_id,
        timestamp: input.timestamp,
        witness: witness_ref,
        scope_id: payload.scope_id,
        rule_pack: payload.rule_pack,
        rules: payload.rules,
        files_scanned: payload.files_scanned,
        violations: payload.violations,
        passed: payload.passed,
        registry_hash,
    };

    Ok(RustIrLintRunOutput { event, witness })
}

pub fn append_rust_ir_lint_event(
    ledger_path: &Path,
    event: &RustIrLintEvent,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

fn load_rust_files(root: &Path) -> Result<Vec<RustFileInput>, DeclareCostError> {
    let mut files = Vec::new();
    let root_canon = root
        .canonicalize()
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;
    collect_rust_paths(&root_canon, &mut files)?;
    files.sort();

    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let bytes = fs::read(&path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let rel = path
            .strip_prefix(&root_canon)
            .ok()
            .map(normalize_path)
            .unwrap_or_else(|| normalize_path(&path));
        out.push(RustFileInput {
            rel_path: rel,
            text,
            sha256: sha256_hex(&bytes),
        });
    }
    Ok(out)
}

fn collect_rust_paths(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), DeclareCostError> {
    if path.is_file() {
        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }

    if !path.is_dir() {
        return Ok(());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|err| DeclareCostError::Io(err.to_string()))? {
        let entry = entry.map_err(|err| DeclareCostError::Io(err.to_string()))?;
        entries.push(entry.path());
    }
    entries.sort();

    for entry_path in entries {
        if entry_path.is_dir() {
            let skip = entry_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(should_skip_dir_name);
            if skip {
                continue;
            }
            collect_rust_paths(&entry_path, out)?;
        } else if entry_path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn should_skip_dir_name(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "out"
    )
}

fn normalize_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn scan_core_violations(file: &RustFileInput) -> Vec<RustIrLintViolation> {
    let mut violations = Vec::new();
    let path_lower = file.rel_path.to_ascii_lowercase();
    let text_lower = file.text.to_ascii_lowercase();

    // IR-RS-02: No silent deletes in projection code.
    if (path_lower.contains("projection") || path_lower.contains("surreal"))
        && !path_lower.contains("vacuum")
    {
        let lines: Vec<&str> = file.text.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let lower = line.to_ascii_lowercase();
            let has_delete =
                lower.contains("delete ") && (line.contains('"') || line.contains('\''));
            if has_delete && !lower.contains("vacuum") && !has_delete_justification(&lines, idx) {
                violations.push(RustIrLintViolation {
                    rule_id: "IR-RS-02".to_string(),
                    severity: "error".to_string(),
                    file: file.rel_path.clone(),
                    line: Some((idx + 1) as u32),
                    message: "DELETE detected outside explicit vacuum path".to_string(),
                });
            }
        }
    }

    // IR-RS-03: Projection writes should carry projection_run_id.
    let has_projection_write = file.text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        if line_is_comment(&lower) {
            return false;
        }
        let is_likely_query_literal = line.contains('"') || line.contains('\'');
        let has_write_verb = lower.contains("insert ")
            || lower.contains("update ")
            || lower.contains("create ")
            || lower.contains("relate ")
            || lower.contains("upsert ");
        is_likely_query_literal && has_write_verb
    });
    if (path_lower.contains("projection") || path_lower.contains("surreal"))
        && has_projection_write
        && !text_lower.contains("projection_run_id")
    {
        violations.push(RustIrLintViolation {
            rule_id: "IR-RS-03".to_string(),
            severity: "error".to_string(),
            file: file.rel_path.clone(),
            line: None,
            message: "projection write path missing projection_run_id attribution".to_string(),
        });
    }

    // IR-RS-04: Engine code should avoid nondeterministic primitives.
    let is_engine_context = path_lower.contains("engine")
        || path_lower.contains("court")
        || path_lower.contains("witness")
        || path_lower.contains("plan");
    if is_engine_context {
        for (idx, line) in file.text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("hashmap<") || lower.contains("std::collections::hashmap") {
                violations.push(RustIrLintViolation {
                    rule_id: "IR-RS-04".to_string(),
                    severity: "error".to_string(),
                    file: file.rel_path.clone(),
                    line: Some((idx + 1) as u32),
                    message: "HashMap usage in engine context may introduce nondeterministic order"
                        .to_string(),
                });
            }
            if lower.contains("rand::") || lower.contains("thread_rng(") {
                violations.push(RustIrLintViolation {
                    rule_id: "IR-RS-04".to_string(),
                    severity: "error".to_string(),
                    file: file.rel_path.clone(),
                    line: Some((idx + 1) as u32),
                    message: "randomness used in engine context".to_string(),
                });
            }
            if lower.contains("utc::now(") {
                violations.push(RustIrLintViolation {
                    rule_id: "IR-RS-04".to_string(),
                    severity: "error".to_string(),
                    file: file.rel_path.clone(),
                    line: Some((idx + 1) as u32),
                    message: "time source used in engine context".to_string(),
                });
            }
        }
    }

    // IR-RS-05: Witness structs must be self-describing.
    if let Ok(parsed) = syn::parse_file(&file.text) {
        for item in parsed.items {
            if let Item::Struct(def) = item {
                let name = def.ident.to_string();
                if !name.ends_with("Witness") {
                    continue;
                }
                let field_names: BTreeSet<String> = match def.fields {
                    syn::Fields::Named(named) => named
                        .named
                        .iter()
                        .filter_map(|f| f.ident.as_ref().map(|i| i.to_string()))
                        .collect(),
                    _ => BTreeSet::new(),
                };
                if field_names.is_empty() {
                    continue;
                }
                let has_schema_id = field_names.contains("schema_id");
                let has_created = field_names.iter().any(|name| {
                    name == "timestamp"
                        || name == "created_at"
                        || name.ends_with("_created_at")
                        || name.contains("created_at_")
                });
                let has_engine_version = field_names.contains("engine_version")
                    || field_names.contains("court_version")
                    || field_names.contains("tool_version")
                    || field_names.contains("compiler")
                    || field_names.contains("producer");
                let has_input = field_names.contains("input_id")
                    || field_names.contains("input_ids")
                    || field_names.contains("config_hash")
                    || field_names.contains("snapshot_hash")
                    || field_names.contains("inputs")
                    || field_names.contains("input");

                let mut missing = Vec::new();
                if !has_schema_id {
                    missing.push("schema_id");
                }
                if !has_created {
                    missing.push("created_at/timestamp");
                }
                if !has_engine_version {
                    missing.push("engine_version/tool_version/compiler");
                }
                if !has_input {
                    missing.push("input_id(s)/config_hash");
                }
                if !missing.is_empty() {
                    violations.push(RustIrLintViolation {
                        rule_id: "IR-RS-05".to_string(),
                        severity: "error".to_string(),
                        file: file.rel_path.clone(),
                        line: find_struct_line(&file.text, &name),
                        message: format!(
                            "{} missing required witness fields: {}",
                            name,
                            missing.join(", ")
                        ),
                    });
                }
            }
        }
    }

    // IR-RS-08: batch_hash should not depend on batch index.
    if (path_lower.contains("projection") || path_lower.contains("surreal"))
        && text_lower.contains("batch_hash")
    {
        for (idx, line) in file.text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let uses_index = lower.contains("batch_index")
                || lower.contains("batch_idx")
                || (lower.contains("batch") && lower.contains("index"));
            let looks_like_binding_or_assign =
                lower.contains("batch_hash") && (line.contains('=') || line.contains(':'));
            if looks_like_binding_or_assign && uses_index {
                violations.push(RustIrLintViolation {
                    rule_id: "IR-RS-08".to_string(),
                    severity: "error".to_string(),
                    file: file.rel_path.clone(),
                    line: Some((idx + 1) as u32),
                    message: "batch_hash appears to depend on batch index".to_string(),
                });
            }
        }
    }

    // IR-RS-13: Protected modules must not couple directly to adapter crates/modules.
    if ir_rs_13_protected_path(&path_lower) {
        for (idx, line) in file.text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if line_is_comment(&lower) {
                continue;
            }
            let adapter_ref = lower.contains("admit_scope_obsidian::")
                || lower.contains("use admit_scope_obsidian")
                || lower.contains("mod obsidian_adapter")
                || lower.contains("obsidian_adapter::");
            if adapter_ref {
                violations.push(RustIrLintViolation {
                    rule_id: "IR-RS-13".to_string(),
                    severity: "error".to_string(),
                    file: file.rel_path.clone(),
                    line: Some((idx + 1) as u32),
                    message: "adapter coupling in protected module; move dependency to explicit Obsidian adapter wiring".to_string(),
                });
            }
        }
    }

    violations
}

fn ir_rs_13_protected_path(path_lower: &str) -> bool {
    if ir_rs_13_allowed_adapter_path(path_lower) {
        return false;
    }
    path_lower.starts_with("crates/admit_core/src/")
        || path_lower.starts_with("crates/admit_surrealdb/src/")
        || path_lower.starts_with("crates/admit_cli/src/")
}

fn ir_rs_13_allowed_adapter_path(path_lower: &str) -> bool {
    path_lower == "crates/admit_cli/src/main.rs"
        || path_lower == "crates/admit_cli/src/obsidian_adapter.rs"
        || path_lower == "crates/admit_cli/src/ingest_dir.rs"
        || path_lower == "crates/admit_cli/src/vault_prefix.rs"
        || path_lower == "crates/admit_cli/src/rust_ir_lint.rs"
}

fn find_struct_line(text: &str, struct_name: &str) -> Option<u32> {
    let needle = format!("struct {}", struct_name);
    for (idx, line) in text.lines().enumerate() {
        if line.contains(&needle) {
            return Some((idx + 1) as u32);
        }
    }
    None
}

fn line_is_comment(lower_trimmed: &str) -> bool {
    let trimmed = lower_trimmed.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("/*")
}

fn has_delete_justification(lines: &[&str], idx: usize) -> bool {
    let current = lines
        .get(idx)
        .map(|line| line.to_ascii_lowercase())
        .unwrap_or_default();
    if current.contains("ir-delete-justified") || current.contains("replacement semantics") {
        return true;
    }
    let prev = idx.saturating_sub(25);
    for line in lines.iter().take(idx).skip(prev) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("ir-delete-justified") || lower.contains("replacement semantics") {
            return true;
        }
    }
    false
}
