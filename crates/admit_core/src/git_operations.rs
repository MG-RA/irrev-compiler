use crate::error::EvalError;
use crate::git_witness::{
    normalize_repo_path, GitArtifactBinding, GitDiffFileChange, GitDiffWitness,
    GitProvenanceWitness, GitRegistryBinding, GitSignatureAttestation, GitSnapshotFile,
    GitSnapshotWitness, GitSubmoduleState, GitWitnessMetadata,
};

#[derive(Debug, Clone)]
pub struct GitSnapshotInput {
    pub head_commit_oid: String,
    pub is_clean: bool,
    pub tracked_files: Vec<GitSnapshotFile>,
    pub submodules: Vec<GitSubmoduleState>,
    pub working_tree_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GitDiffInput {
    pub base_commit_oid: String,
    pub head_commit_oid: String,
    pub changes: Vec<GitDiffFileChange>,
}

#[derive(Debug, Clone)]
pub struct GitProvenanceInput {
    pub repository_id: String,
    pub base_commit_oid: Option<String>,
    pub head_commit_oid: String,
    pub artifact_bindings: Vec<GitArtifactBinding>,
    pub registry_bindings: Vec<GitRegistryBinding>,
    pub signature_attestations: Vec<GitSignatureAttestation>,
}

pub fn git_snapshot(
    input: GitSnapshotInput,
    created_at_utc: String,
    metadata: Option<GitWitnessMetadata>,
) -> Result<GitSnapshotWitness, EvalError> {
    let mut tracked_files = input.tracked_files;
    for file in &mut tracked_files {
        file.path = normalize_repo_path(&file.path);
    }
    tracked_files.sort_by(|a, b| a.path.cmp(&b.path));
    ensure_unique_by(
        tracked_files.iter().map(|file| file.path.as_str()),
        "tracked_files.path",
    )?;

    let mut submodules = input.submodules;
    for submodule in &mut submodules {
        submodule.path = normalize_repo_path(&submodule.path);
    }
    submodules.sort_by(|a, b| a.path.cmp(&b.path));
    ensure_unique_by(
        submodules.iter().map(|submodule| submodule.path.as_str()),
        "submodules.path",
    )?;

    let witness = GitSnapshotWitness {
        schema_id: "git-snapshot-witness/0".to_string(),
        schema_version: 0,
        engine_version: None,
        input_id: None,
        config_hash: None,
        head_commit_oid: input.head_commit_oid,
        is_clean: input.is_clean,
        tracked_files,
        submodules: if submodules.is_empty() {
            None
        } else {
            Some(submodules)
        },
        working_tree_manifest_sha256: input.working_tree_manifest_sha256,
        created_at_utc,
        metadata,
    };
    witness.validate()?;
    Ok(witness)
}

pub fn git_diff(
    input: GitDiffInput,
    created_at_utc: String,
    metadata: Option<GitWitnessMetadata>,
) -> Result<GitDiffWitness, EvalError> {
    let mut changes = input.changes;
    for change in &mut changes {
        change.path = normalize_repo_path(&change.path);
    }
    changes.sort_by(|a, b| {
        let a_key = (&a.path, change_kind_order(&a.change_kind));
        let b_key = (&b.path, change_kind_order(&b.change_kind));
        a_key.cmp(&b_key)
    });
    ensure_unique_by(
        changes
            .iter()
            .map(|change| (change.path.as_str(), change_kind_order(&change.change_kind))),
        "changes.(path, change_kind)",
    )?;

    let witness = GitDiffWitness {
        schema_id: "git-diff-witness/0".to_string(),
        schema_version: 0,
        engine_version: None,
        input_id: None,
        config_hash: None,
        base_commit_oid: input.base_commit_oid,
        head_commit_oid: input.head_commit_oid,
        changes,
        created_at_utc,
        metadata,
    };
    witness.validate()?;
    Ok(witness)
}

pub fn git_provenance(
    input: GitProvenanceInput,
    created_at_utc: String,
    metadata: Option<GitWitnessMetadata>,
) -> Result<GitProvenanceWitness, EvalError> {
    if input.repository_id.trim().is_empty() {
        return Err(EvalError("repository_id must not be empty".into()));
    }

    let mut artifact_bindings = input.artifact_bindings;
    for binding in &mut artifact_bindings {
        if let Some(path) = binding.path.as_ref() {
            binding.path = Some(normalize_repo_path(path));
        }
    }
    artifact_bindings.sort_by(|a, b| {
        let a_key = (&a.artifact_kind, &a.artifact_sha256, &a.commit_oid);
        let b_key = (&b.artifact_kind, &b.artifact_sha256, &b.commit_oid);
        a_key.cmp(&b_key)
    });
    ensure_unique_by(
        artifact_bindings.iter().map(|binding| {
            (
                &binding.artifact_kind,
                &binding.artifact_sha256,
                &binding.commit_oid,
            )
        }),
        "artifact_bindings.(artifact_kind, artifact_sha256, commit_oid)",
    )?;

    let mut registry_bindings = input.registry_bindings;
    registry_bindings.sort_by(|a, b| {
        let a_key = (
            registry_entry_kind_order(a.entry_kind),
            &a.entry_id,
            a.entry_version,
            &a.introduced_in_commit_oid,
        );
        let b_key = (
            registry_entry_kind_order(b.entry_kind),
            &b.entry_id,
            b.entry_version,
            &b.introduced_in_commit_oid,
        );
        a_key.cmp(&b_key)
    });
    ensure_unique_by(
        registry_bindings.iter().map(|binding| {
            (
                registry_entry_kind_order(binding.entry_kind),
                &binding.entry_id,
                binding.entry_version,
                &binding.introduced_in_commit_oid,
            )
        }),
        "registry_bindings.(entry_kind, entry_id, entry_version, introduced_in_commit_oid)",
    )?;

    let mut signature_attestations = input.signature_attestations;
    signature_attestations.sort_by(|a, b| a.commit_oid.cmp(&b.commit_oid));
    ensure_unique_by(
        signature_attestations
            .iter()
            .map(|attestation| &attestation.commit_oid),
        "signature_attestations.commit_oid",
    )?;

    let witness = GitProvenanceWitness {
        schema_id: "git-provenance-witness/0".to_string(),
        schema_version: 0,
        engine_version: None,
        input_id: None,
        config_hash: None,
        repository_id: input.repository_id,
        base_commit_oid: input.base_commit_oid,
        head_commit_oid: input.head_commit_oid,
        artifact_bindings,
        registry_bindings,
        signature_attestations,
        created_at_utc,
        metadata,
    };
    witness.validate()?;
    Ok(witness)
}

fn ensure_unique_by<T>(items: impl Iterator<Item = T>, field_name: &str) -> Result<(), EvalError>
where
    T: Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = std::collections::HashSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(EvalError(format!(
                "duplicate {} entry found after normalization/sort",
                field_name
            )));
        }
    }
    Ok(())
}

fn registry_entry_kind_order(kind: crate::git_witness::GitRegistryEntryKind) -> u8 {
    match kind {
        crate::git_witness::GitRegistryEntryKind::Scope => 0,
        crate::git_witness::GitRegistryEntryKind::Schema => 1,
        crate::git_witness::GitRegistryEntryKind::Stdlib => 2,
    }
}

fn change_kind_order(kind: &crate::git_witness::GitDiffChangeKind) -> u8 {
    match kind {
        crate::git_witness::GitDiffChangeKind::Added => 0,
        crate::git_witness::GitDiffChangeKind::Modified => 1,
        crate::git_witness::GitDiffChangeKind::Deleted => 2,
        crate::git_witness::GitDiffChangeKind::Renamed => 3,
        crate::git_witness::GitDiffChangeKind::Copied => 4,
        crate::git_witness::GitDiffChangeKind::TypeChanged => 5,
        crate::git_witness::GitDiffChangeKind::Unmerged => 6,
        crate::git_witness::GitDiffChangeKind::Unknown => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_witness::{
        GitDiffChangeKind, GitRegistryBinding, GitRegistryEntryKind, GitSignatureAttestation,
        GitSignatureVerification, GitWitnessMetadata,
    };

    #[test]
    fn git_snapshot_normalizes_and_sorts_paths() {
        let witness = git_snapshot(
            GitSnapshotInput {
                head_commit_oid: "a".repeat(40),
                is_clean: true,
                tracked_files: vec![
                    GitSnapshotFile {
                        path: r".\src\main.rs".to_string(),
                        blob_oid: "c".repeat(40),
                    },
                    GitSnapshotFile {
                        path: "./Cargo.toml".to_string(),
                        blob_oid: "b".repeat(40),
                    },
                ],
                submodules: vec![],
                working_tree_manifest_sha256: None,
            },
            "2026-02-07T00:00:00Z".to_string(),
            Some(GitWitnessMetadata {
                source_ref: Some("repo:main".to_string()),
                purpose: Some("test".to_string()),
            }),
        )
        .unwrap();
        assert_eq!(witness.tracked_files[0].path, "Cargo.toml");
        assert_eq!(witness.tracked_files[1].path, "src/main.rs");
    }

    #[test]
    fn git_diff_rejects_duplicate_changes_after_normalization() {
        let err = git_diff(
            GitDiffInput {
                base_commit_oid: "a".repeat(40),
                head_commit_oid: "b".repeat(40),
                changes: vec![
                    GitDiffFileChange {
                        path: r".\src\main.rs".to_string(),
                        change_kind: GitDiffChangeKind::Modified,
                        old_blob_oid: Some("c".repeat(40)),
                        new_blob_oid: Some("d".repeat(40)),
                        additions: Some(1),
                        deletions: Some(0),
                    },
                    GitDiffFileChange {
                        path: "./src/main.rs".to_string(),
                        change_kind: GitDiffChangeKind::Modified,
                        old_blob_oid: Some("c".repeat(40)),
                        new_blob_oid: Some("d".repeat(40)),
                        additions: Some(1),
                        deletions: Some(0),
                    },
                ],
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap_err();
        assert!(err.0.contains("duplicate changes.(path, change_kind)"));
    }

    #[test]
    fn git_diff_enforces_added_deleted_blob_constraints() {
        let added_bad = git_diff(
            GitDiffInput {
                base_commit_oid: "a".repeat(40),
                head_commit_oid: "b".repeat(40),
                changes: vec![GitDiffFileChange {
                    path: "src/new.rs".to_string(),
                    change_kind: GitDiffChangeKind::Added,
                    old_blob_oid: Some("c".repeat(40)),
                    new_blob_oid: Some("d".repeat(40)),
                    additions: Some(10),
                    deletions: Some(0),
                }],
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap_err();
        assert!(added_bad
            .0
            .contains("added change requires new_blob_oid and forbids old_blob_oid"));

        let deleted_bad = git_diff(
            GitDiffInput {
                base_commit_oid: "a".repeat(40),
                head_commit_oid: "b".repeat(40),
                changes: vec![GitDiffFileChange {
                    path: "src/old.rs".to_string(),
                    change_kind: GitDiffChangeKind::Deleted,
                    old_blob_oid: Some("c".repeat(40)),
                    new_blob_oid: Some("d".repeat(40)),
                    additions: Some(0),
                    deletions: Some(10),
                }],
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap_err();
        assert!(deleted_bad
            .0
            .contains("deleted change requires old_blob_oid and forbids new_blob_oid"));
    }

    #[test]
    fn git_provenance_normalizes_paths_and_sorts_bindings() {
        let witness = git_provenance(
            GitProvenanceInput {
                repository_id: "repo:irrev-compiler".to_string(),
                base_commit_oid: Some("a".repeat(40)),
                head_commit_oid: "b".repeat(40),
                artifact_bindings: vec![
                    GitArtifactBinding {
                        artifact_kind: "text_chunk".to_string(),
                        artifact_sha256: "d".repeat(64),
                        commit_oid: "b".repeat(40),
                        path: Some(r".\src\lib.rs".to_string()),
                    },
                    GitArtifactBinding {
                        artifact_kind: "dir_parse".to_string(),
                        artifact_sha256: "c".repeat(64),
                        commit_oid: "b".repeat(40),
                        path: Some("./src/main.rs".to_string()),
                    },
                ],
                registry_bindings: vec![
                    GitRegistryBinding {
                        entry_kind: GitRegistryEntryKind::Schema,
                        entry_id: "git-provenance-witness/0".to_string(),
                        entry_version: 0,
                        introduced_in_commit_oid: "b".repeat(40),
                    },
                    GitRegistryBinding {
                        entry_kind: GitRegistryEntryKind::Scope,
                        entry_id: "scope:git.provenance".to_string(),
                        entry_version: 0,
                        introduced_in_commit_oid: "b".repeat(40),
                    },
                ],
                signature_attestations: vec![GitSignatureAttestation {
                    commit_oid: "b".repeat(40),
                    verification: GitSignatureVerification::Verified,
                    signer: Some("key:abc123".to_string()),
                }],
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap();

        assert_eq!(witness.artifact_bindings[0].artifact_kind, "dir_parse");
        assert_eq!(
            witness.artifact_bindings[0].path.as_deref(),
            Some("src/main.rs")
        );
        assert_eq!(
            witness.registry_bindings[0].entry_kind,
            GitRegistryEntryKind::Scope
        );
    }

    #[test]
    fn git_provenance_rejects_duplicate_artifact_keys() {
        let err = git_provenance(
            GitProvenanceInput {
                repository_id: "repo:irrev-compiler".to_string(),
                base_commit_oid: None,
                head_commit_oid: "b".repeat(40),
                artifact_bindings: vec![
                    GitArtifactBinding {
                        artifact_kind: "text_chunk".to_string(),
                        artifact_sha256: "d".repeat(64),
                        commit_oid: "b".repeat(40),
                        path: Some(r".\src\lib.rs".to_string()),
                    },
                    GitArtifactBinding {
                        artifact_kind: "text_chunk".to_string(),
                        artifact_sha256: "d".repeat(64),
                        commit_oid: "b".repeat(40),
                        path: Some("./src/lib.rs".to_string()),
                    },
                ],
                registry_bindings: vec![],
                signature_attestations: vec![],
            },
            "2026-02-07T00:00:00Z".to_string(),
            None,
        )
        .unwrap_err();

        assert!(err.0.contains("duplicate artifact_bindings."));
    }
}
