use std::path::PathBuf;

use admit_cli::verify_ledger;

fn testdata_path(name: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base.join("..").join("..").join("testdata").join(name)
}

#[test]
fn verify_ledger_fixtures_pass() {
    let ledger_path = testdata_path("ledger/ledger.jsonl");
    let artifacts_root = testdata_path("artifacts");
    let report =
        verify_ledger(&ledger_path, Some(artifacts_root.as_path())).expect("verify fixtures");
    assert!(report.issues.is_empty());
}
