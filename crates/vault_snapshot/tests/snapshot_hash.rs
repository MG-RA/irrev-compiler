use std::fs;
use std::path::PathBuf;

use vault_snapshot::{canonical_json_bytes, load_snapshot_with_hash};

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vault-snapshot-{}", name))
}

#[test]
fn canonical_json_is_stable() {
    let value = serde_json::json!({
        "b": 1,
        "a": {
            "d": [3, 2],
            "c": "text"
        }
    });
    let bytes = canonical_json_bytes(&value).expect("canonical bytes");
    let text = String::from_utf8(bytes).expect("utf8");
    assert_eq!(text, "{\"a\":{\"c\":\"text\",\"d\":[3,2]},\"b\":1}");
}

#[test]
fn load_snapshot_hashes_canonical_bytes() {
    let snapshot = r#"{
        "schema_id":"vault-snapshot/0",
        "schema_version":0,
        "concepts":[],
        "diagnostics":[],
        "domains":[],
        "projections":[],
        "papers":[],
        "meta":[],
        "support":[],
        "rulesets":[]
    }"#;
    let path = temp_path("schema.json");
    fs::write(&path, snapshot).expect("write snapshot");
    let loaded = load_snapshot_with_hash(&path).expect("load snapshot");
    assert_eq!(loaded.snapshot.schema_id, "vault-snapshot/0");
    assert_eq!(loaded.snapshot.schema_version, 0);
    assert!(!loaded.sha256.is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn fixture_snapshot_hash_matches() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("snapshot");
    let snapshot_path = base.join("snapshot.json");
    let hash_path = base.join("snapshot.json.sha256");

    let loaded = load_snapshot_with_hash(&snapshot_path).expect("load fixture snapshot");
    let expected = fs::read_to_string(&hash_path)
        .expect("read fixture hash")
        .trim()
        .to_string();
    assert_eq!(loaded.sha256, expected);
}
