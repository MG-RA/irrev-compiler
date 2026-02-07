//! Lint command implementations

use std::path::Path;

use admit_cli::{
    append_rust_ir_lint_event, default_artifacts_dir, default_ledger_path,
    resolve_scope_enablement, run_rust_ir_lint, scope_operation_human_hint, RustIrLintInput,
    ScopeOperation,
};

use crate::LintRustArgs;

pub fn run_lint_rust(args: LintRustArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let scope_enablement = resolve_scope_enablement(&args.path)?;
    if !scope_enablement.allows(ScopeOperation::RustIrLint) {
        let source = scope_enablement
            .source
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "default scopes".to_string());
        return Err(format!(
            "scope {} is disabled by {} (enable it under [scopes].enabled)",
            scope_operation_human_hint(ScopeOperation::RustIrLint),
            source
        ));
    }

    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let tool_version = args
        .tool_version
        .unwrap_or_else(|| format!("admit-cli {}", env!("CARGO_PKG_VERSION")));
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let output = run_rust_ir_lint(RustIrLintInput {
        root: args.path,
        timestamp: created_at,
        tool_version,
        artifacts_root: Some(artifacts_dir.clone()),
        meta_registry_path: args.meta_registry,
    })
    .map_err(|err| err.to_string())?;

    if !args.dry_run {
        append_rust_ir_lint_event(&ledger_path, &output.event).map_err(|err| err.to_string())?;
    }

    if args.json {
        let json = serde_json::to_string(&serde_json::json!({
            "event": &output.event,
            "witness": &output.witness,
            "ledger": ledger_path,
            "artifacts_dir": artifacts_dir,
            "dry_run": args.dry_run
        }))
        .map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", output.event.event_id);
        println!("witness_sha256={}", output.event.witness.sha256);
        println!("scope_id={}", output.event.scope_id);
        println!("rule_pack={}", output.event.rule_pack);
        println!("files_scanned={}", output.event.files_scanned);
        println!("violations={}", output.event.violations);
        println!("passed={}", output.event.passed);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
        for violation in output.witness.violations.iter().take(200) {
            let line = violation
                .line
                .map(|line| line.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "violation rule_id={} severity={} file={} line={} message={}",
                violation.rule_id, violation.severity, violation.file, line, violation.message
            );
        }
        if output.witness.violations.len() > 200 {
            println!(
                "violation_truncated=true shown=200 total={}",
                output.witness.violations.len()
            );
        }
    }

    if output.event.passed {
        Ok(())
    } else {
        Err(format!(
            "rust ir lint found {} violation(s)",
            output.event.violations
        ))
    }
}
