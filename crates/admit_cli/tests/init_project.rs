use std::fs;
use std::path::PathBuf;

use admit_cli::{init_project, InitProjectInput};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-init-{}-{}", label, nanos))
}

#[test]
fn init_project_creates_expected_scaffold() {
    let dir = temp_dir("create");

    let out = init_project(InitProjectInput { root: dir.clone() }).expect("init project");

    assert_eq!(out.root, dir);
    assert!(dir.join("admit.toml").exists(), "missing admit.toml");
    assert!(
        dir.join("out").join(".gitignore").exists(),
        "missing out/.gitignore"
    );
    assert!(
        dir.join("meta").join("rules").join("README.md").exists(),
        "missing meta/rules/README.md"
    );
    assert!(
        dir.join("meta")
            .join("fixtures")
            .join("mini_vault")
            .join("README.md")
            .exists(),
        "missing mini fixture readme"
    );
    let admit_toml = fs::read_to_string(dir.join("admit.toml")).expect("read admit.toml");
    assert!(
        admit_toml.contains("[scopes]"),
        "admit.toml should include [scopes] section"
    );
    assert!(
        admit_toml.contains("rust.ir_lint"),
        "admit.toml should enable rust.ir_lint by default"
    );
}

#[test]
fn init_project_is_idempotent_and_does_not_overwrite_existing_files() {
    let dir = temp_dir("idempotent");
    fs::create_dir_all(&dir).expect("create temp dir");

    let custom = "[project]\nroot = \"custom\"\n";
    fs::write(dir.join("admit.toml"), custom).expect("write custom config");

    let first = init_project(InitProjectInput { root: dir.clone() }).expect("first init");
    let second = init_project(InitProjectInput { root: dir.clone() }).expect("second init");

    let current = fs::read_to_string(dir.join("admit.toml")).expect("read config");
    assert_eq!(current, custom, "init must not overwrite existing config");

    assert!(
        first.existing.iter().any(|x| x == "admit.toml"),
        "first run should report pre-existing admit.toml"
    );
    assert!(
        second.created.is_empty(),
        "second run should not create anything new"
    );
}
