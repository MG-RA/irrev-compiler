use std::path::PathBuf;

use facts_bundle::{load_bundle_with_hash, observe_regex, ObservationPattern};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("facts")
        .join(name)
}

fn compiler_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize compiler root")
}

#[test]
fn facts_bundle_hash_matches_fixture() {
    let bundle_path = fixture_path("facts-bundle.json");
    let loaded = load_bundle_with_hash(&bundle_path).expect("load facts bundle");
    let expected_hash = std::fs::read_to_string(fixture_path("facts-bundle.json.sha256"))
        .expect("read hash")
        .trim()
        .to_string();
    assert_eq!(loaded.sha256, expected_hash);
}

#[test]
fn observe_regex_matches_fixture() {
    let root = compiler_root();
    let input = root.join("testdata").join("facts").join("prescriptive.md");
    let patterns = vec![ObservationPattern {
        diff: "difference:prescriptive_claims".to_string(),
        regex: r"\bshould\b|\bmust\b".to_string(),
        unit: Some("count".to_string()),
    }];
    let bundle =
        observe_regex(&[input], &patterns, true, None, Some(&root)).expect("observe regex");
    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_path("facts-bundle.json")).expect("read fixture"),
    )
    .expect("parse fixture");
    let actual = serde_json::to_value(&bundle).expect("bundle to value");
    assert_eq!(actual, expected);
}
