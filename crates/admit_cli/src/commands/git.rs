//! Git command implementations

use std::path::{Path, PathBuf};

use sha2::Digest;

use admit_cli::{default_artifacts_dir, store_value_artifact};

use crate::{
    GitArgs, GitCommands, GitDiffArgs, GitInstallPlanHookArgs, GitProvenanceArgs,
    GitSnapshotArgs, GitVerifyCommitPlanArgs,
};

pub fn run_git(args: GitArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    match args.command {
        GitCommands::Snapshot(snapshot_args) => run_git_snapshot(snapshot_args),
        GitCommands::Diff(diff_args) => run_git_diff(diff_args),
        GitCommands::Provenance(provenance_args) => run_git_provenance(provenance_args),
        GitCommands::VerifyCommitPlan(verify_args) => run_git_verify_commit_plan(verify_args),
        GitCommands::InstallPlanHook(hook_args) => run_git_install_plan_hook(hook_args),
    }
}

fn run_git_snapshot(args: GitSnapshotArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let metadata = build_git_metadata(args.source_ref, args.purpose);
    let head_commit_oid = git_resolve_commit_oid(&repo, &args.head)?;
    let is_clean = git_is_clean_worktree(&repo)?;
    let tracked_files = git_snapshot_tracked_files(&repo, &head_commit_oid)?;
    let submodules = if args.include_submodules {
        git_snapshot_submodules(&repo)?
    } else {
        Vec::new()
    };
    let working_tree_manifest_sha256 = if args.include_working_tree_manifest {
        Some(git_working_tree_manifest_sha256(&repo)?)
    } else {
        None
    };

    let witness = admit_core::git_snapshot(
        admit_core::GitSnapshotInput {
            head_commit_oid,
            is_clean,
            tracked_files,
            submodules,
            working_tree_manifest_sha256,
        },
        created_at,
        metadata,
    )
    .map_err(|e| e.to_string())?;
    let witness_id =
        admit_core::compute_git_snapshot_witness_id(&witness).map_err(|e| e.to_string())?;

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let artifact_ref = if args.no_store {
        None
    } else {
        let witness_value =
            serde_json::to_value(&witness).map_err(|e| format!("snapshot witness json: {}", e))?;
        Some(
            store_value_artifact(
                &artifacts_dir,
                "git_snapshot_witness",
                "git-snapshot-witness/0",
                &witness_value,
            )
            .map_err(|e| e.to_string())?,
        )
    };

    if let Some(out_path) = args.out.as_ref() {
        write_json_pretty(out_path, &witness)?;
    }

    if args.json {
        let output = serde_json::json!({
            "witness_id": witness_id,
            "artifact_ref": artifact_ref,
            "witness": witness
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("witness_id={}", witness_id);
        println!("schema_id=git-snapshot-witness/0");
        println!("head_commit_oid={}", witness.head_commit_oid);
        println!("is_clean={}", witness.is_clean);
        println!("tracked_files={}", witness.tracked_files.len());
        if let Some(submodules) = witness.submodules.as_ref() {
            println!("submodules={}", submodules.len());
        }
        if let Some(artifact_ref) = artifact_ref.as_ref() {
            println!("artifact_sha256={}", artifact_ref.sha256);
            println!(
                "artifact_path={}",
                artifact_ref.path.as_deref().unwrap_or("")
            );
            println!("artifacts_dir={}", artifacts_dir.display());
        } else {
            println!("stored=false");
        }
        if let Some(out_path) = args.out.as_ref() {
            println!("out={}", out_path.display());
        }
    }

    Ok(())
}

fn run_git_diff(args: GitDiffArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let metadata = build_git_metadata(args.source_ref, args.purpose);
    let base_commit_oid = git_resolve_commit_oid(&repo, &args.base)?;
    let head_commit_oid = git_resolve_commit_oid(&repo, &args.head)?;
    let changes = git_diff_changes(&repo, &base_commit_oid, &head_commit_oid)?;

    let witness = admit_core::git_diff(
        admit_core::GitDiffInput {
            base_commit_oid,
            head_commit_oid,
            changes,
        },
        created_at,
        metadata,
    )
    .map_err(|e| e.to_string())?;
    let witness_id =
        admit_core::compute_git_diff_witness_id(&witness).map_err(|e| e.to_string())?;

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let artifact_ref = if args.no_store {
        None
    } else {
        let witness_value =
            serde_json::to_value(&witness).map_err(|e| format!("diff witness json: {}", e))?;
        Some(
            store_value_artifact(
                &artifacts_dir,
                "git_diff_witness",
                "git-diff-witness/0",
                &witness_value,
            )
            .map_err(|e| e.to_string())?,
        )
    };

    if let Some(out_path) = args.out.as_ref() {
        write_json_pretty(out_path, &witness)?;
    }

    if args.json {
        let output = serde_json::json!({
            "witness_id": witness_id,
            "artifact_ref": artifact_ref,
            "witness": witness
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("witness_id={}", witness_id);
        println!("schema_id=git-diff-witness/0");
        println!("base_commit_oid={}", witness.base_commit_oid);
        println!("head_commit_oid={}", witness.head_commit_oid);
        println!("changes={}", witness.changes.len());
        if let Some(artifact_ref) = artifact_ref.as_ref() {
            println!("artifact_sha256={}", artifact_ref.sha256);
            println!(
                "artifact_path={}",
                artifact_ref.path.as_deref().unwrap_or("")
            );
            println!("artifacts_dir={}", artifacts_dir.display());
        } else {
            println!("stored=false");
        }
        if let Some(out_path) = args.out.as_ref() {
            println!("out={}", out_path.display());
        }
    }

    Ok(())
}

fn run_git_provenance(args: GitProvenanceArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let metadata = build_git_metadata(args.source_ref, args.purpose);

    let base_commit_oid = match args.base.as_ref() {
        Some(base_ref) => Some(git_resolve_commit_oid(&repo, base_ref)?),
        None => None,
    };
    let head_commit_oid = git_resolve_commit_oid(&repo, &args.head)?;
    let repository_id = args
        .repository_id
        .unwrap_or_else(|| default_repository_id(&repo));

    let artifact_bindings: Vec<admit_core::GitArtifactBinding> = match args.artifact_bindings_file {
        Some(path) => read_json_file(&path)?,
        None => Vec::new(),
    };
    let registry_bindings: Vec<admit_core::GitRegistryBinding> = match args.registry_bindings_file {
        Some(path) => read_json_file(&path)?,
        None => Vec::new(),
    };

    let mut signature_map: std::collections::BTreeMap<String, admit_core::GitSignatureAttestation> =
        std::collections::BTreeMap::new();
    if args.signatures_from_git {
        for attestation in
            git_collect_signature_attestations(&repo, base_commit_oid.as_deref(), &head_commit_oid)?
        {
            signature_map.insert(attestation.commit_oid.clone(), attestation);
        }
    }
    let explicit_signatures: Vec<admit_core::GitSignatureAttestation> =
        match args.signature_attestations_file {
            Some(path) => read_json_file(&path)?,
            None => Vec::new(),
        };
    for attestation in explicit_signatures {
        signature_map.insert(attestation.commit_oid.clone(), attestation);
    }
    let signature_attestations = signature_map.into_values().collect::<Vec<_>>();

    let witness = admit_core::git_provenance(
        admit_core::GitProvenanceInput {
            repository_id,
            base_commit_oid,
            head_commit_oid,
            artifact_bindings,
            registry_bindings,
            signature_attestations,
        },
        created_at,
        metadata,
    )
    .map_err(|e| e.to_string())?;
    let witness_id =
        admit_core::compute_git_provenance_witness_id(&witness).map_err(|e| e.to_string())?;

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let artifact_ref = if args.no_store {
        None
    } else {
        let witness_value = serde_json::to_value(&witness)
            .map_err(|e| format!("provenance witness json: {}", e))?;
        Some(
            store_value_artifact(
                &artifacts_dir,
                "git_provenance_witness",
                "git-provenance-witness/0",
                &witness_value,
            )
            .map_err(|e| e.to_string())?,
        )
    };

    if let Some(out_path) = args.out.as_ref() {
        write_json_pretty(out_path, &witness)?;
    }

    if args.json {
        let output = serde_json::json!({
            "witness_id": witness_id,
            "artifact_ref": artifact_ref,
            "witness": witness
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("witness_id={}", witness_id);
        println!("schema_id=git-provenance-witness/0");
        println!("repository_id={}", witness.repository_id);
        println!("head_commit_oid={}", witness.head_commit_oid);
        println!("artifact_bindings={}", witness.artifact_bindings.len());
        println!("registry_bindings={}", witness.registry_bindings.len());
        println!(
            "signature_attestations={}",
            witness.signature_attestations.len()
        );
        if let Some(artifact_ref) = artifact_ref.as_ref() {
            println!("artifact_sha256={}", artifact_ref.sha256);
            println!(
                "artifact_path={}",
                artifact_ref.path.as_deref().unwrap_or("")
            );
            println!("artifacts_dir={}", artifacts_dir.display());
        } else {
            println!("stored=false");
        }
        if let Some(out_path) = args.out.as_ref() {
            println!("out={}", out_path.display());
        }
    }

    Ok(())
}

fn run_git_verify_commit_plan(args: GitVerifyCommitPlanArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let artifacts_dir = resolve_artifacts_dir(&repo, args.artifacts_dir);

    let (source, message) = if let Some(path) = args.message_file.as_ref() {
        let message_path = if path.is_absolute() {
            path.clone()
        } else {
            repo.join(path)
        };
        let message = std::fs::read_to_string(&message_path)
            .map_err(|e| format!("read {}: {}", message_path.display(), e))?;
        (format!("message_file:{}", message_path.display()), message)
    } else {
        let message = read_commit_message_from_ref(&repo, &args.commit)?;
        (format!("commit:{}", args.commit), message)
    };

    let plan_witness_hash = extract_plan_witness_hash_from_message(&message)?;
    let artifact_present = plan_witness_artifact_exists(&artifacts_dir, &plan_witness_hash);
    if !artifact_present && !args.allow_missing_artifact {
        return Err(format!(
            "plan witness artifact not found for hash {} (expected {} or {})",
            plan_witness_hash,
            artifacts_dir
                .join("plan_witness")
                .join(format!("{}.cbor", plan_witness_hash))
                .display(),
            artifacts_dir
                .join("plan_witness")
                .join(format!("{}.json", plan_witness_hash))
                .display()
        ));
    }

    if args.json {
        let output = serde_json::json!({
            "valid": true,
            "plan_witness_hash": plan_witness_hash,
            "artifact_present": artifact_present,
            "source": source,
            "artifacts_dir": artifacts_dir.display().to_string(),
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("valid=true");
        println!("plan_witness_hash={}", plan_witness_hash);
        println!("artifact_present={}", artifact_present);
        println!("source={}", source);
        println!("artifacts_dir={}", artifacts_dir.display());
    }

    Ok(())
}

fn run_git_install_plan_hook(args: GitInstallPlanHookArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let artifacts_dir = resolve_artifacts_dir(&repo, args.artifacts_dir);
    let git_dir = resolve_git_dir(&repo)?;
    let hooks_dir = git_dir.join("hooks");
    if !hooks_dir.exists() {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create hooks dir {}: {}", hooks_dir.display(), e))?;
    }
    let hook_path = hooks_dir.join("commit-msg");
    if hook_path.exists() && !args.force {
        return Err(format!(
            "hook already exists at {} (use --force to overwrite)",
            hook_path.display()
        ));
    }

    let repo_text = repo.display().to_string().replace('\\', "/");
    let artifacts_text = artifacts_dir.display().to_string().replace('\\', "/");
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str("set -eu\n");
    script.push_str(&format!(
        "ADMIT_CLI_BIN=\"${{ADMIT_CLI_BIN:-{}}}\"\n",
        args.admit_cli_bin
    ));
    script.push_str(&format!(
        "\"$ADMIT_CLI_BIN\" git verify-commit-plan --repo {} --message-file \"$1\" --artifacts-dir {}",
        shell_single_quote(&repo_text),
        shell_single_quote(&artifacts_text)
    ));
    if args.allow_missing_artifact {
        script.push_str(" --allow-missing-artifact");
    }
    script.push('\n');

    std::fs::write(&hook_path, script)
        .map_err(|e| format!("write hook {}: {}", hook_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)
            .map_err(|e| format!("metadata {}: {}", hook_path.display(), e))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)
            .map_err(|e| format!("chmod {}: {}", hook_path.display(), e))?;
    }

    println!("hook_installed={}", hook_path.display());
    println!("repo={}", repo.display());
    println!("artifacts_dir={}", artifacts_dir.display());
    if args.allow_missing_artifact {
        println!("allow_missing_artifact=true");
    }
    Ok(())
}

fn read_commit_message_from_ref(repo: &Path, reference: &str) -> Result<String, String> {
    git_output(
        repo,
        &[
            String::from("show"),
            String::from("-s"),
            String::from("--format=%B"),
            reference.to_string(),
        ],
    )
}

fn extract_plan_witness_hash_from_message(message: &str) -> Result<String, String> {
    let mut found: Option<String> = None;
    for (line_idx, line) in message.lines().enumerate() {
        match parse_plan_hash_from_line(line) {
            Ok(Some(hash)) => {
                if let Some(existing) = found.as_ref() {
                    if existing != &hash {
                        return Err(format!(
                            "multiple plan hashes found in commit message: {} and {}",
                            existing, hash
                        ));
                    }
                } else {
                    found = Some(hash);
                }
            }
            Ok(None) => {}
            Err(err) => {
                return Err(format!(
                    "invalid plan witness hash on line {}: {}",
                    line_idx + 1,
                    err
                ))
            }
        }
    }
    found.ok_or_else(|| {
        "missing plan witness hash in commit message (add `Plan-Witness: <64-hex>`)".to_string()
    })
}

fn parse_plan_hash_from_line(line: &str) -> Result<Option<String>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    for sep in [':', '='] {
        if let Some((label, value)) = trimmed.split_once(sep) {
            let normalized = normalize_plan_label(label);
            if normalized != "planwitness" && normalized != "planid" && normalized != "planhash" {
                continue;
            }
            let token = value
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|ch: char| ",.;)]}".contains(ch));
            if token.is_empty() {
                return Err("missing hash value after plan label".to_string());
            }
            if !is_valid_sha256_hex(token) {
                return Err(format!(
                    "expected 64 hex characters after plan label, got `{}`",
                    token
                ));
            }
            return Ok(Some(token.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

fn normalize_plan_label(label: &str) -> String {
    label
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect::<String>()
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn resolve_artifacts_dir(repo: &Path, artifacts_dir: Option<PathBuf>) -> PathBuf {
    let dir = artifacts_dir.unwrap_or_else(default_artifacts_dir);
    if dir.is_absolute() {
        dir
    } else {
        repo.join(dir)
    }
}

fn plan_witness_artifact_exists(artifacts_dir: &Path, plan_hash: &str) -> bool {
    let kind_dir = artifacts_dir.join("plan_witness");
    let cbor = kind_dir.join(format!("{}.cbor", plan_hash));
    let json = kind_dir.join(format!("{}.json", plan_hash));
    cbor.exists() || json.exists()
}

fn resolve_git_dir(repo: &Path) -> Result<PathBuf, String> {
    let git_dir_text = git_output(
        repo,
        &[String::from("rev-parse"), String::from("--git-dir")],
    )?;
    let git_dir = PathBuf::from(git_dir_text.trim());
    if git_dir.is_absolute() {
        Ok(git_dir)
    } else {
        Ok(repo.join(git_dir))
    }
}

fn shell_single_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

fn resolve_repo_path(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(format!("repo path not found: {}", path.display()));
    }
    let repo = path
        .canonicalize()
        .map_err(|e| format!("canonicalize repo path: {}", e))?;
    if !repo.is_dir() {
        return Err(format!("repo path must be a directory: {}", repo.display()));
    }
    Ok(repo)
}

fn build_git_metadata(
    source_ref: Option<String>,
    purpose: Option<String>,
) -> Option<admit_core::GitWitnessMetadata> {
    if source_ref.is_none() && purpose.is_none() {
        None
    } else {
        Some(admit_core::GitWitnessMetadata {
            source_ref,
            purpose,
        })
    }
}

fn default_repository_id(repo: &Path) -> String {
    if let Some(name) = repo.file_name().and_then(|n| n.to_str()) {
        format!("repo:{}", name)
    } else {
        format!("repo:{}", repo.display().to_string().replace('\\', "/"))
    }
}

fn git_resolve_commit_oid(repo: &Path, reference: &str) -> Result<String, String> {
    let oid = git_output(repo, &[String::from("rev-parse"), reference.to_string()])?;
    let oid = oid.trim().to_string();
    if oid.is_empty() {
        return Err(format!("git rev-parse {} returned empty oid", reference));
    }
    Ok(oid)
}

fn git_is_clean_worktree(repo: &Path) -> Result<bool, String> {
    let status = git_output(
        repo,
        &[String::from("status"), String::from("--porcelain=1")],
    )?;
    Ok(status.trim().is_empty())
}

fn git_snapshot_tracked_files(
    repo: &Path,
    head_commit_oid: &str,
) -> Result<Vec<admit_core::GitSnapshotFile>, String> {
    let tree = git_output(
        repo,
        &[
            String::from("ls-tree"),
            String::from("-r"),
            String::from("--full-tree"),
            head_commit_oid.to_string(),
        ],
    )?;
    let mut files = Vec::new();
    for line in tree.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (left, path) = line
            .split_once('\t')
            .ok_or_else(|| format!("unexpected ls-tree line: {}", line))?;
        let mut left_parts = left.split_whitespace();
        let _mode = left_parts.next();
        let kind = left_parts.next();
        let oid = left_parts.next();
        if kind != Some("blob") {
            continue;
        }
        let Some(blob_oid) = oid else {
            return Err(format!("missing blob oid in ls-tree line: {}", line));
        };
        files.push(admit_core::GitSnapshotFile {
            path: normalize_repo_path(path),
            blob_oid: blob_oid.to_string(),
        });
    }
    Ok(files)
}

fn git_snapshot_submodules(repo: &Path) -> Result<Vec<admit_core::GitSubmoduleState>, String> {
    let output = git_command(
        repo,
        &[
            String::from("submodule"),
            String::from("status"),
            String::from("--recursive"),
        ],
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.contains("No submodule mapping found")
            || stderr.contains("not initialized")
            || stderr.contains("No url found")
        {
            return Ok(Vec::new());
        }
        return Err(format!("git submodule status failed: {}", stderr));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|e| format!("utf8 decode: {}", e))?;
    let mut submodules = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(raw_oid) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else {
            continue;
        };
        let commit_oid = raw_oid.trim_start_matches(['-', '+', 'U', ' ']).to_string();
        submodules.push(admit_core::GitSubmoduleState {
            path: normalize_repo_path(path),
            commit_oid,
        });
    }
    Ok(submodules)
}

fn git_working_tree_manifest_sha256(repo: &Path) -> Result<String, String> {
    let output = git_command(
        repo,
        &[
            String::from("ls-files"),
            String::from("--cached"),
            String::from("--others"),
            String::from("--exclude-standard"),
            String::from("-z"),
        ],
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("git ls-files manifest failed: {}", stderr));
    }
    let mut paths = Vec::new();
    for entry in output
        .stdout
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
    {
        let path = String::from_utf8(entry.to_vec()).map_err(|e| format!("utf8 decode: {}", e))?;
        paths.push(normalize_repo_path(&path));
    }
    paths.sort();
    paths.dedup();
    let manifest_value = serde_json::Value::Array(
        paths
            .into_iter()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>(),
    );
    let cbor = admit_core::encode_canonical_value(&manifest_value).map_err(|e| e.to_string())?;
    Ok(hex::encode(sha2::Sha256::digest(cbor)))
}

fn git_diff_changes(
    repo: &Path,
    base_commit_oid: &str,
    head_commit_oid: &str,
) -> Result<Vec<admit_core::GitDiffFileChange>, String> {
    let status = git_output(
        repo,
        &[
            String::from("diff"),
            String::from("--name-status"),
            String::from("--find-renames"),
            String::from("--find-copies"),
            base_commit_oid.to_string(),
            head_commit_oid.to_string(),
        ],
    )?;
    let mut changes = Vec::new();
    for line in status.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cols = line.split('\t').collect::<Vec<_>>();
        if cols.is_empty() {
            continue;
        }
        let status_code = cols[0];
        let kind = map_git_change_kind(status_code);
        let (old_path, new_path, path) =
            if status_code.starts_with('R') || status_code.starts_with('C') {
                if cols.len() < 3 {
                    return Err(format!("unexpected rename/copy diff line: {}", line));
                }
                let old_path = normalize_repo_path(cols[1]);
                let new_path = normalize_repo_path(cols[2]);
                let path = new_path.clone();
                (Some(old_path), Some(new_path), path)
            } else {
                if cols.len() < 2 {
                    return Err(format!("unexpected diff line: {}", line));
                }
                let p = normalize_repo_path(cols[1]);
                (Some(p.clone()), Some(p.clone()), p)
            };

        let old_blob_oid = match kind {
            admit_core::GitDiffChangeKind::Added => None,
            admit_core::GitDiffChangeKind::Renamed | admit_core::GitDiffChangeKind::Copied => {
                if let Some(old_path) = old_path.as_ref() {
                    git_blob_oid_at_commit(repo, base_commit_oid, old_path)?
                } else {
                    None
                }
            }
            _ => {
                if let Some(path_for_old) = old_path.as_ref() {
                    git_blob_oid_at_commit(repo, base_commit_oid, path_for_old)?
                } else {
                    None
                }
            }
        };

        let new_blob_oid = match kind {
            admit_core::GitDiffChangeKind::Deleted => None,
            admit_core::GitDiffChangeKind::Renamed | admit_core::GitDiffChangeKind::Copied => {
                if let Some(new_path) = new_path.as_ref() {
                    git_blob_oid_at_commit(repo, head_commit_oid, new_path)?
                } else {
                    None
                }
            }
            _ => {
                if let Some(path_for_new) = new_path.as_ref() {
                    git_blob_oid_at_commit(repo, head_commit_oid, path_for_new)?
                } else {
                    None
                }
            }
        };

        changes.push(admit_core::GitDiffFileChange {
            path,
            change_kind: kind,
            old_blob_oid,
            new_blob_oid,
            additions: None,
            deletions: None,
        });
    }
    Ok(changes)
}

fn map_git_change_kind(status_code: &str) -> admit_core::GitDiffChangeKind {
    if status_code.starts_with('A') {
        admit_core::GitDiffChangeKind::Added
    } else if status_code.starts_with('M') {
        admit_core::GitDiffChangeKind::Modified
    } else if status_code.starts_with('D') {
        admit_core::GitDiffChangeKind::Deleted
    } else if status_code.starts_with('R') {
        admit_core::GitDiffChangeKind::Renamed
    } else if status_code.starts_with('C') {
        admit_core::GitDiffChangeKind::Copied
    } else if status_code.starts_with('T') {
        admit_core::GitDiffChangeKind::TypeChanged
    } else if status_code.starts_with('U') {
        admit_core::GitDiffChangeKind::Unmerged
    } else {
        admit_core::GitDiffChangeKind::Unknown
    }
}

fn git_blob_oid_at_commit(
    repo: &Path,
    commit_oid: &str,
    path: &str,
) -> Result<Option<String>, String> {
    let spec = format!("{}:{}", commit_oid, path);
    let output = git_command(repo, &[String::from("rev-parse"), spec])?;
    if output.status.success() {
        let oid = String::from_utf8(output.stdout)
            .map_err(|e| format!("utf8 decode: {}", e))?
            .trim()
            .to_string();
        if oid.is_empty() {
            Ok(None)
        } else {
            Ok(Some(oid))
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr.contains("unknown revision or path")
            || stderr.contains("exists on disk, but not in")
            || stderr.contains("path '")
        {
            Ok(None)
        } else {
            Err(format!("git rev-parse {} failed: {}", path, stderr.trim()))
        }
    }
}

fn git_collect_signature_attestations(
    repo: &Path,
    base_commit_oid: Option<&str>,
    head_commit_oid: &str,
) -> Result<Vec<admit_core::GitSignatureAttestation>, String> {
    let rev_range = match base_commit_oid {
        Some(base) => format!("{}..{}", base, head_commit_oid),
        None => head_commit_oid.to_string(),
    };
    let commits_text = git_output(
        repo,
        &[
            String::from("rev-list"),
            String::from("--reverse"),
            rev_range,
        ],
    )?;
    let mut attestations = Vec::new();
    for commit_oid in commits_text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
    {
        let verify_out = git_command(
            repo,
            &[String::from("verify-commit"), commit_oid.to_string()],
        )?;
        let signer = git_output(
            repo,
            &[
                String::from("show"),
                String::from("-s"),
                String::from("--format=%GS"),
                commit_oid.to_string(),
            ],
        )
        .unwrap_or_default()
        .trim()
        .to_string();
        let signer = if signer.is_empty() {
            None
        } else {
            Some(signer)
        };
        let verification = if verify_out.status.success() {
            admit_core::GitSignatureVerification::Verified
        } else if signer.is_some() {
            admit_core::GitSignatureVerification::Unverified
        } else {
            admit_core::GitSignatureVerification::Unknown
        };
        attestations.push(admit_core::GitSignatureAttestation {
            commit_oid: commit_oid.to_string(),
            verification,
            signer,
        });
    }
    Ok(attestations)
}

fn normalize_repo_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    if let Some(stripped) = path.strip_prefix("./") {
        stripped.to_string()
    } else {
        path
    }
}

fn git_output(repo: &Path, args: &[String]) -> Result<String, String> {
    let output = git_command(repo, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("git {} failed: {}", args.join(" "), stderr));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("utf8 decode: {}", e))
}

fn git_command(repo: &Path, args: &[String]) -> Result<std::process::Output, String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute git: {}", e))
}

pub(crate) fn write_json_pretty<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create out dir: {}", e))?;
        }
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("json encode: {}", e))?;
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {}", path.display(), e))
}

pub(crate) fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("decode {}: {}", path.display(), e))
}
