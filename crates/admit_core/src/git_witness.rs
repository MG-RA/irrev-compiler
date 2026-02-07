use crate::cbor::encode_canonical_value;
use crate::error::EvalError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSnapshotFile {
    pub path: String,
    pub blob_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSubmoduleState {
    pub path: String,
    pub commit_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitWitnessMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSnapshotWitness {
    pub schema_id: String,
    pub schema_version: u32,
    pub head_commit_oid: String,
    pub is_clean: bool,
    pub tracked_files: Vec<GitSnapshotFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submodules: Option<Vec<GitSubmoduleState>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_tree_manifest_sha256: Option<String>,
    pub created_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GitWitnessMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitDiffChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    TypeChanged,
    Unmerged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitDiffFileChange {
    pub path: String,
    pub change_kind: GitDiffChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_blob_oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_blob_oid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletions: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitDiffWitness {
    pub schema_id: String,
    pub schema_version: u32,
    pub base_commit_oid: String,
    pub head_commit_oid: String,
    pub changes: Vec<GitDiffFileChange>,
    pub created_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GitWitnessMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitRegistryEntryKind {
    Scope,
    Schema,
    Stdlib,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitRegistryBinding {
    pub entry_kind: GitRegistryEntryKind,
    pub entry_id: String,
    pub entry_version: u32,
    pub introduced_in_commit_oid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitSignatureVerification {
    Verified,
    Unverified,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSignatureAttestation {
    pub commit_oid: String,
    pub verification: GitSignatureVerification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitArtifactBinding {
    pub artifact_kind: String,
    pub artifact_sha256: String,
    pub commit_oid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitProvenanceWitness {
    pub schema_id: String,
    pub schema_version: u32,
    pub repository_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_commit_oid: Option<String>,
    pub head_commit_oid: String,
    pub artifact_bindings: Vec<GitArtifactBinding>,
    pub registry_bindings: Vec<GitRegistryBinding>,
    pub signature_attestations: Vec<GitSignatureAttestation>,
    pub created_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GitWitnessMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GitSnapshotWitnessIdPayload<'a> {
    schema_id: &'a str,
    schema_version: u32,
    head_commit_oid: &'a str,
    is_clean: bool,
    tracked_files: &'a [GitSnapshotFile],
    submodules: &'a Option<Vec<GitSubmoduleState>>,
    working_tree_manifest_sha256: &'a Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GitDiffWitnessIdPayload<'a> {
    schema_id: &'a str,
    schema_version: u32,
    base_commit_oid: &'a str,
    head_commit_oid: &'a str,
    changes: &'a [GitDiffFileChange],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GitProvenanceWitnessIdPayload<'a> {
    schema_id: &'a str,
    schema_version: u32,
    repository_id: &'a str,
    base_commit_oid: &'a Option<String>,
    head_commit_oid: &'a str,
    artifact_bindings: &'a [GitArtifactBinding],
    registry_bindings: &'a [GitRegistryBinding],
    signature_attestations: &'a [GitSignatureAttestation],
}

impl GitSnapshotWitness {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.schema_id != "git-snapshot-witness/0" {
            return Err(EvalError(format!(
                "unsupported schema_id: {}",
                self.schema_id
            )));
        }
        if self.schema_version != 0 {
            return Err(EvalError(format!(
                "unsupported schema_version: {}",
                self.schema_version
            )));
        }
        if !is_valid_git_oid(&self.head_commit_oid) {
            return Err(EvalError(format!(
                "invalid head_commit_oid: {}",
                self.head_commit_oid
            )));
        }
        validate_utc_timestamp(&self.created_at_utc, "created_at_utc")?;
        validate_sorted_unique_snapshot_files(&self.tracked_files)?;
        if let Some(submodules) = &self.submodules {
            validate_sorted_unique_submodules(submodules)?;
        }
        if let Some(manifest_sha256) = &self.working_tree_manifest_sha256 {
            if !is_valid_sha256_hex(manifest_sha256) {
                return Err(EvalError(format!(
                    "working_tree_manifest_sha256 must be 64-char lowercase hex: {}",
                    manifest_sha256
                )));
            }
        }
        Ok(())
    }
}

impl GitDiffWitness {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.schema_id != "git-diff-witness/0" {
            return Err(EvalError(format!(
                "unsupported schema_id: {}",
                self.schema_id
            )));
        }
        if self.schema_version != 0 {
            return Err(EvalError(format!(
                "unsupported schema_version: {}",
                self.schema_version
            )));
        }
        if !is_valid_git_oid(&self.base_commit_oid) {
            return Err(EvalError(format!(
                "invalid base_commit_oid: {}",
                self.base_commit_oid
            )));
        }
        if !is_valid_git_oid(&self.head_commit_oid) {
            return Err(EvalError(format!(
                "invalid head_commit_oid: {}",
                self.head_commit_oid
            )));
        }
        validate_utc_timestamp(&self.created_at_utc, "created_at_utc")?;
        validate_sorted_unique_diff_changes(&self.changes)?;
        Ok(())
    }
}

impl GitProvenanceWitness {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.schema_id != "git-provenance-witness/0" {
            return Err(EvalError(format!(
                "unsupported schema_id: {}",
                self.schema_id
            )));
        }
        if self.schema_version != 0 {
            return Err(EvalError(format!(
                "unsupported schema_version: {}",
                self.schema_version
            )));
        }
        if self.repository_id.trim().is_empty() {
            return Err(EvalError("repository_id must not be empty".into()));
        }
        if let Some(base_commit_oid) = self.base_commit_oid.as_ref() {
            if !is_valid_git_oid(base_commit_oid) {
                return Err(EvalError(format!(
                    "invalid base_commit_oid: {}",
                    base_commit_oid
                )));
            }
        }
        if !is_valid_git_oid(&self.head_commit_oid) {
            return Err(EvalError(format!(
                "invalid head_commit_oid: {}",
                self.head_commit_oid
            )));
        }
        validate_utc_timestamp(&self.created_at_utc, "created_at_utc")?;
        validate_sorted_unique_artifact_bindings(&self.artifact_bindings)?;
        validate_sorted_unique_registry_bindings(&self.registry_bindings)?;
        validate_sorted_unique_signature_attestations(&self.signature_attestations)?;
        Ok(())
    }
}

pub fn compute_git_snapshot_witness_id(witness: &GitSnapshotWitness) -> Result<String, EvalError> {
    let payload = GitSnapshotWitnessIdPayload {
        schema_id: &witness.schema_id,
        schema_version: witness.schema_version,
        head_commit_oid: &witness.head_commit_oid,
        is_clean: witness.is_clean,
        tracked_files: &witness.tracked_files,
        submodules: &witness.submodules,
        working_tree_manifest_sha256: &witness.working_tree_manifest_sha256,
    };
    let value = serde_json::to_value(&payload)
        .map_err(|e| EvalError(format!("serialize git snapshot id payload: {}", e)))?;
    let bytes = encode_canonical_value(&value)?;
    Ok(sha256_hex(&bytes))
}

pub fn compute_git_diff_witness_id(witness: &GitDiffWitness) -> Result<String, EvalError> {
    let payload = GitDiffWitnessIdPayload {
        schema_id: &witness.schema_id,
        schema_version: witness.schema_version,
        base_commit_oid: &witness.base_commit_oid,
        head_commit_oid: &witness.head_commit_oid,
        changes: &witness.changes,
    };
    let value = serde_json::to_value(&payload)
        .map_err(|e| EvalError(format!("serialize git diff id payload: {}", e)))?;
    let bytes = encode_canonical_value(&value)?;
    Ok(sha256_hex(&bytes))
}

pub fn compute_git_provenance_witness_id(
    witness: &GitProvenanceWitness,
) -> Result<String, EvalError> {
    let payload = GitProvenanceWitnessIdPayload {
        schema_id: &witness.schema_id,
        schema_version: witness.schema_version,
        repository_id: &witness.repository_id,
        base_commit_oid: &witness.base_commit_oid,
        head_commit_oid: &witness.head_commit_oid,
        artifact_bindings: &witness.artifact_bindings,
        registry_bindings: &witness.registry_bindings,
        signature_attestations: &witness.signature_attestations,
    };
    let value = serde_json::to_value(&payload)
        .map_err(|e| EvalError(format!("serialize git provenance id payload: {}", e)))?;
    let bytes = encode_canonical_value(&value)?;
    Ok(sha256_hex(&bytes))
}

pub fn encode_git_snapshot_witness(witness: &GitSnapshotWitness) -> Result<Vec<u8>, EvalError> {
    let value = serde_json::to_value(witness)
        .map_err(|e| EvalError(format!("serialize git snapshot witness: {}", e)))?;
    encode_canonical_value(&value)
}

pub fn encode_git_diff_witness(witness: &GitDiffWitness) -> Result<Vec<u8>, EvalError> {
    let value = serde_json::to_value(witness)
        .map_err(|e| EvalError(format!("serialize git diff witness: {}", e)))?;
    encode_canonical_value(&value)
}

pub fn encode_git_provenance_witness(witness: &GitProvenanceWitness) -> Result<Vec<u8>, EvalError> {
    let value = serde_json::to_value(witness)
        .map_err(|e| EvalError(format!("serialize git provenance witness: {}", e)))?;
    encode_canonical_value(&value)
}

pub(crate) fn normalize_repo_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    if let Some(stripped) = path.strip_prefix("./") {
        stripped.to_string()
    } else {
        path
    }
}

pub(crate) fn is_valid_git_oid(oid: &str) -> bool {
    (oid.len() == 40 || oid.len() == 64)
        && oid
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub(crate) fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

pub(crate) fn validate_utc_timestamp(ts: &str, field: &str) -> Result<(), EvalError> {
    if ts.len() < 20 || !ts.contains('T') || !ts.ends_with('Z') {
        return Err(EvalError(format!(
            "{} must be ISO-8601 UTC (example: 2026-02-07T00:00:00Z)",
            field
        )));
    }
    Ok(())
}

fn validate_sorted_unique_snapshot_files(files: &[GitSnapshotFile]) -> Result<(), EvalError> {
    if !files.windows(2).all(|w| w[0].path < w[1].path) {
        return Err(EvalError(
            "tracked_files must be sorted ascending and unique by path".into(),
        ));
    }
    for file in files {
        if file.path.trim().is_empty() {
            return Err(EvalError("tracked_files.path must not be empty".into()));
        }
        if !is_valid_git_oid(&file.blob_oid) {
            return Err(EvalError(format!(
                "tracked_files.blob_oid must be lowercase hex git oid: {}",
                file.blob_oid
            )));
        }
    }
    Ok(())
}

fn validate_sorted_unique_submodules(submodules: &[GitSubmoduleState]) -> Result<(), EvalError> {
    if !submodules.windows(2).all(|w| w[0].path < w[1].path) {
        return Err(EvalError(
            "submodules must be sorted ascending and unique by path".into(),
        ));
    }
    for submodule in submodules {
        if submodule.path.trim().is_empty() {
            return Err(EvalError("submodules.path must not be empty".into()));
        }
        if !is_valid_git_oid(&submodule.commit_oid) {
            return Err(EvalError(format!(
                "submodules.commit_oid must be lowercase hex git oid: {}",
                submodule.commit_oid
            )));
        }
    }
    Ok(())
}

fn validate_sorted_unique_diff_changes(changes: &[GitDiffFileChange]) -> Result<(), EvalError> {
    if !changes.windows(2).all(|w| {
        let a = (&w[0].path, kind_order(&w[0].change_kind));
        let b = (&w[1].path, kind_order(&w[1].change_kind));
        a < b
    }) {
        return Err(EvalError(
            "changes must be sorted ascending by (path, change_kind) and unique".into(),
        ));
    }
    for change in changes {
        if change.path.trim().is_empty() {
            return Err(EvalError("changes.path must not be empty".into()));
        }
        if let Some(old_blob_oid) = &change.old_blob_oid {
            if !is_valid_git_oid(old_blob_oid) {
                return Err(EvalError(format!(
                    "changes.old_blob_oid must be lowercase hex git oid: {}",
                    old_blob_oid
                )));
            }
        }
        if let Some(new_blob_oid) = &change.new_blob_oid {
            if !is_valid_git_oid(new_blob_oid) {
                return Err(EvalError(format!(
                    "changes.new_blob_oid must be lowercase hex git oid: {}",
                    new_blob_oid
                )));
            }
        }
        match change.change_kind {
            GitDiffChangeKind::Added => {
                if change.old_blob_oid.is_some() || change.new_blob_oid.is_none() {
                    return Err(EvalError(
                        "added change requires new_blob_oid and forbids old_blob_oid".into(),
                    ));
                }
            }
            GitDiffChangeKind::Deleted => {
                if change.old_blob_oid.is_none() || change.new_blob_oid.is_some() {
                    return Err(EvalError(
                        "deleted change requires old_blob_oid and forbids new_blob_oid".into(),
                    ));
                }
            }
            _ => {
                if change.old_blob_oid.is_none() && change.new_blob_oid.is_none() {
                    return Err(EvalError(
                        "non-add/delete change requires old_blob_oid or new_blob_oid".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_sorted_unique_artifact_bindings(
    bindings: &[GitArtifactBinding],
) -> Result<(), EvalError> {
    if !bindings.windows(2).all(|w| {
        let a = (&w[0].artifact_kind, &w[0].artifact_sha256, &w[0].commit_oid);
        let b = (&w[1].artifact_kind, &w[1].artifact_sha256, &w[1].commit_oid);
        a < b
    }) {
        return Err(EvalError(
            "artifact_bindings must be sorted ascending by (artifact_kind, artifact_sha256, commit_oid) and unique".into(),
        ));
    }
    for binding in bindings {
        if binding.artifact_kind.trim().is_empty() {
            return Err(EvalError(
                "artifact_bindings.artifact_kind must not be empty".into(),
            ));
        }
        if !is_valid_sha256_hex(&binding.artifact_sha256) {
            return Err(EvalError(format!(
                "artifact_bindings.artifact_sha256 must be lowercase sha256 hex: {}",
                binding.artifact_sha256
            )));
        }
        if !is_valid_git_oid(&binding.commit_oid) {
            return Err(EvalError(format!(
                "artifact_bindings.commit_oid must be lowercase git oid: {}",
                binding.commit_oid
            )));
        }
        if let Some(path) = binding.path.as_ref() {
            if path.trim().is_empty() {
                return Err(EvalError("artifact_bindings.path must not be empty".into()));
            }
        }
    }
    Ok(())
}

fn validate_sorted_unique_registry_bindings(
    bindings: &[GitRegistryBinding],
) -> Result<(), EvalError> {
    if !bindings.windows(2).all(|w| {
        let a = (
            registry_kind_order(w[0].entry_kind),
            &w[0].entry_id,
            w[0].entry_version,
            &w[0].introduced_in_commit_oid,
        );
        let b = (
            registry_kind_order(w[1].entry_kind),
            &w[1].entry_id,
            w[1].entry_version,
            &w[1].introduced_in_commit_oid,
        );
        a < b
    }) {
        return Err(EvalError(
            "registry_bindings must be sorted ascending by (entry_kind, entry_id, entry_version, introduced_in_commit_oid) and unique".into(),
        ));
    }
    for binding in bindings {
        if binding.entry_id.trim().is_empty() {
            return Err(EvalError(
                "registry_bindings.entry_id must not be empty".into(),
            ));
        }
        if !is_valid_git_oid(&binding.introduced_in_commit_oid) {
            return Err(EvalError(format!(
                "registry_bindings.introduced_in_commit_oid must be lowercase git oid: {}",
                binding.introduced_in_commit_oid
            )));
        }
        match binding.entry_kind {
            GitRegistryEntryKind::Scope => {
                if !binding.entry_id.starts_with("scope:") {
                    return Err(EvalError(format!(
                        "scope registry entry_id must start with scope:: {}",
                        binding.entry_id
                    )));
                }
            }
            GitRegistryEntryKind::Schema => {
                if !binding.entry_id.contains('/') {
                    return Err(EvalError(format!(
                        "schema registry entry_id must include '/': {}",
                        binding.entry_id
                    )));
                }
            }
            GitRegistryEntryKind::Stdlib => {
                if !binding.entry_id.starts_with("module:") {
                    return Err(EvalError(format!(
                        "stdlib registry entry_id must start with module:: {}",
                        binding.entry_id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_sorted_unique_signature_attestations(
    attestations: &[GitSignatureAttestation],
) -> Result<(), EvalError> {
    if !attestations
        .windows(2)
        .all(|w| w[0].commit_oid < w[1].commit_oid)
    {
        return Err(EvalError(
            "signature_attestations must be sorted ascending and unique by commit_oid".into(),
        ));
    }
    for attestation in attestations {
        if !is_valid_git_oid(&attestation.commit_oid) {
            return Err(EvalError(format!(
                "signature_attestations.commit_oid must be lowercase git oid: {}",
                attestation.commit_oid
            )));
        }
        if matches!(attestation.verification, GitSignatureVerification::Verified)
            && attestation
                .signer
                .as_ref()
                .is_none_or(|signer| signer.trim().is_empty())
        {
            return Err(EvalError(
                "verified signature_attestations require non-empty signer".into(),
            ));
        }
    }
    Ok(())
}

fn kind_order(kind: &GitDiffChangeKind) -> u8 {
    match kind {
        GitDiffChangeKind::Added => 0,
        GitDiffChangeKind::Modified => 1,
        GitDiffChangeKind::Deleted => 2,
        GitDiffChangeKind::Renamed => 3,
        GitDiffChangeKind::Copied => 4,
        GitDiffChangeKind::TypeChanged => 5,
        GitDiffChangeKind::Unmerged => 6,
        GitDiffChangeKind::Unknown => 7,
    }
}

fn registry_kind_order(kind: GitRegistryEntryKind) -> u8 {
    match kind {
        GitRegistryEntryKind::Scope => 0,
        GitRegistryEntryKind::Schema => 1,
        GitRegistryEntryKind::Stdlib => 2,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_witness_id_excludes_created_at_and_metadata() {
        let mut witness = GitSnapshotWitness {
            schema_id: "git-snapshot-witness/0".to_string(),
            schema_version: 0,
            head_commit_oid: "a".repeat(40),
            is_clean: true,
            tracked_files: vec![GitSnapshotFile {
                path: "src/lib.rs".to_string(),
                blob_oid: "b".repeat(40),
            }],
            submodules: None,
            working_tree_manifest_sha256: None,
            created_at_utc: "2026-02-07T00:00:00Z".to_string(),
            metadata: None,
        };
        let a = compute_git_snapshot_witness_id(&witness).unwrap();
        witness.created_at_utc = "2026-02-07T23:59:59Z".to_string();
        witness.metadata = Some(GitWitnessMetadata {
            source_ref: Some("repo:main".to_string()),
            purpose: Some("capture".to_string()),
        });
        let b = compute_git_snapshot_witness_id(&witness).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn diff_witness_id_excludes_created_at_and_metadata() {
        let mut witness = GitDiffWitness {
            schema_id: "git-diff-witness/0".to_string(),
            schema_version: 0,
            base_commit_oid: "a".repeat(40),
            head_commit_oid: "b".repeat(40),
            changes: vec![GitDiffFileChange {
                path: "src/lib.rs".to_string(),
                change_kind: GitDiffChangeKind::Modified,
                old_blob_oid: Some("c".repeat(40)),
                new_blob_oid: Some("d".repeat(40)),
                additions: Some(5),
                deletions: Some(1),
            }],
            created_at_utc: "2026-02-07T00:00:00Z".to_string(),
            metadata: None,
        };
        let a = compute_git_diff_witness_id(&witness).unwrap();
        witness.created_at_utc = "2026-02-07T23:59:59Z".to_string();
        witness.metadata = Some(GitWitnessMetadata {
            source_ref: Some("repo:main".to_string()),
            purpose: Some("capture".to_string()),
        });
        let b = compute_git_diff_witness_id(&witness).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn provenance_witness_id_excludes_created_at_and_metadata() {
        let mut witness = GitProvenanceWitness {
            schema_id: "git-provenance-witness/0".to_string(),
            schema_version: 0,
            repository_id: "repo:irrev-compiler".to_string(),
            base_commit_oid: Some("a".repeat(40)),
            head_commit_oid: "b".repeat(40),
            artifact_bindings: vec![GitArtifactBinding {
                artifact_kind: "text_chunk".to_string(),
                artifact_sha256: "c".repeat(64),
                commit_oid: "b".repeat(40),
                path: Some("src/lib.rs".to_string()),
            }],
            registry_bindings: vec![GitRegistryBinding {
                entry_kind: GitRegistryEntryKind::Scope,
                entry_id: "scope:git.provenance".to_string(),
                entry_version: 0,
                introduced_in_commit_oid: "b".repeat(40),
            }],
            signature_attestations: vec![GitSignatureAttestation {
                commit_oid: "b".repeat(40),
                verification: GitSignatureVerification::Verified,
                signer: Some("key:f00dbabe".to_string()),
            }],
            created_at_utc: "2026-02-07T00:00:00Z".to_string(),
            metadata: None,
        };
        let a = compute_git_provenance_witness_id(&witness).unwrap();
        witness.created_at_utc = "2026-02-07T23:59:59Z".to_string();
        witness.metadata = Some(GitWitnessMetadata {
            source_ref: Some("repo:main".to_string()),
            purpose: Some("capture".to_string()),
        });
        let b = compute_git_provenance_witness_id(&witness).unwrap();
        assert_eq!(a, b);
    }
}
