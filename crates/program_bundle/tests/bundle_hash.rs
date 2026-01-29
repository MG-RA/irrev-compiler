use std::fs;
use std::path::PathBuf;

use program_bundle::{canonical_json_bytes, load_bundle_with_hash};

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("program-bundle-{}", name))
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
fn load_bundle_hashes_canonical_bytes() {
    let bundle = r#"{
        "schema_id":"program-bundle/0",
        "schema_version":0,
        "programs":[],
        "dependencies":[],
        "provenance":{
            "source":"vault",
            "generator_id":"vault-projection/0",
            "generator_hash":"abc",
            "snapshot_hash":"snap"
        }
    }"#;
    let path = temp_path("bundle.json");
    fs::write(&path, bundle).expect("write bundle");
    let loaded = load_bundle_with_hash(&path).expect("load bundle");
    assert_eq!(loaded.bundle.schema_id, "program-bundle/0");
    assert_eq!(loaded.bundle.schema_version, 0);
    assert!(!loaded.sha256.is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn fixture_bundle_hash_matches() {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("bundle");
    let bundle_path = base.join("program-bundle.json");
    let hash_path = base.join("program-bundle.json.sha256");

    let loaded = load_bundle_with_hash(&bundle_path).expect("load fixture bundle");
    let expected = fs::read_to_string(&hash_path)
        .expect("read fixture hash")
        .trim()
        .to_string();
    assert_eq!(loaded.sha256, expected);
}
