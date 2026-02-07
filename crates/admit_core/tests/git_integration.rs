use admit_core::{
    compute_git_diff_witness_id, compute_git_provenance_witness_id,
    compute_git_snapshot_witness_id, encode_git_diff_witness, encode_git_provenance_witness,
    encode_git_snapshot_witness, git_diff, git_provenance, git_snapshot, GitArtifactBinding,
    GitDiffChangeKind, GitDiffFileChange, GitDiffInput, GitProvenanceInput, GitRegistryBinding,
    GitRegistryEntryKind, GitSignatureAttestation, GitSignatureVerification, GitSnapshotFile,
    GitSnapshotInput, GitWitnessMetadata,
};

#[test]
fn git_snapshot_witness_is_canonical_and_hash_addressable() {
    let witness = git_snapshot(
        GitSnapshotInput {
            head_commit_oid: "a".repeat(40),
            is_clean: true,
            tracked_files: vec![
                GitSnapshotFile {
                    path: "src/lib.rs".to_string(),
                    blob_oid: "b".repeat(40),
                },
                GitSnapshotFile {
                    path: "Cargo.toml".to_string(),
                    blob_oid: "c".repeat(40),
                },
            ],
            submodules: vec![],
            working_tree_manifest_sha256: Some("d".repeat(64)),
        },
        "2026-02-07T00:00:00Z".to_string(),
        Some(GitWitnessMetadata {
            source_ref: Some("repo:main".to_string()),
            purpose: Some("baseline".to_string()),
        }),
    )
    .unwrap();
    let bytes = encode_git_snapshot_witness(&witness).unwrap();
    let id = compute_git_snapshot_witness_id(&witness).unwrap();
    assert!(!bytes.is_empty());
    assert_eq!(id.len(), 64);
}

#[test]
fn git_diff_witness_is_canonical_and_hash_addressable() {
    let witness = git_diff(
        GitDiffInput {
            base_commit_oid: "a".repeat(40),
            head_commit_oid: "b".repeat(40),
            changes: vec![
                GitDiffFileChange {
                    path: "src/new.rs".to_string(),
                    change_kind: GitDiffChangeKind::Added,
                    old_blob_oid: None,
                    new_blob_oid: Some("c".repeat(40)),
                    additions: Some(10),
                    deletions: Some(0),
                },
                GitDiffFileChange {
                    path: "src/old.rs".to_string(),
                    change_kind: GitDiffChangeKind::Deleted,
                    old_blob_oid: Some("d".repeat(40)),
                    new_blob_oid: None,
                    additions: Some(0),
                    deletions: Some(8),
                },
            ],
        },
        "2026-02-07T00:00:00Z".to_string(),
        None,
    )
    .unwrap();
    let bytes = encode_git_diff_witness(&witness).unwrap();
    let id = compute_git_diff_witness_id(&witness).unwrap();
    assert!(!bytes.is_empty());
    assert_eq!(id.len(), 64);
}

#[test]
fn git_snapshot_witness_id_is_stable_across_metadata_and_created_at() {
    let a = git_snapshot(
        GitSnapshotInput {
            head_commit_oid: "a".repeat(40),
            is_clean: false,
            tracked_files: vec![GitSnapshotFile {
                path: "src/lib.rs".to_string(),
                blob_oid: "b".repeat(40),
            }],
            submodules: vec![],
            working_tree_manifest_sha256: None,
        },
        "2026-02-07T00:00:00Z".to_string(),
        None,
    )
    .unwrap();
    let b = git_snapshot(
        GitSnapshotInput {
            head_commit_oid: "a".repeat(40),
            is_clean: false,
            tracked_files: vec![GitSnapshotFile {
                path: "src/lib.rs".to_string(),
                blob_oid: "b".repeat(40),
            }],
            submodules: vec![],
            working_tree_manifest_sha256: None,
        },
        "2026-02-07T23:59:59Z".to_string(),
        Some(GitWitnessMetadata {
            source_ref: Some("repo:main".to_string()),
            purpose: Some("audit".to_string()),
        }),
    )
    .unwrap();
    let id_a = compute_git_snapshot_witness_id(&a).unwrap();
    let id_b = compute_git_snapshot_witness_id(&b).unwrap();
    assert_eq!(id_a, id_b);
}

#[test]
fn git_provenance_witness_is_canonical_and_hash_addressable() {
    let witness = git_provenance(
        GitProvenanceInput {
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
                signer: Some("key:abc123".to_string()),
            }],
        },
        "2026-02-07T00:00:00Z".to_string(),
        None,
    )
    .unwrap();

    let bytes = encode_git_provenance_witness(&witness).unwrap();
    let id = compute_git_provenance_witness_id(&witness).unwrap();
    assert!(!bytes.is_empty());
    assert_eq!(id.len(), 64);
}
