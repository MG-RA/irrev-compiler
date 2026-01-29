use std::path::PathBuf;

use admit_cli::list_artifacts;

fn artifacts_root() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base.join("..")
        .join("..")
        .join("testdata")
        .join("artifacts")
}

#[test]
fn list_artifacts_includes_witness_fixture() {
    let entries = list_artifacts(&artifacts_root()).expect("list artifacts");
    assert!(entries.iter().any(|entry| {
        entry.kind == "witness"
            && entry.sha256 == "5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151"
    }));
}
