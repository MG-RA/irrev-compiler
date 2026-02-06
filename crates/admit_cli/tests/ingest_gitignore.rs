use std::process::Command;

use tempfile::tempdir;

#[test]
fn ingest_dir_respects_gitignore_when_git_available() {
    if Command::new("git").arg("--version").output().is_err() {
        return;
    }

    let dir = tempdir().expect("tempdir");
    let status = Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["init", "-q"])
        .status()
        .expect("git init");
    if !status.success() {
        return;
    }

    std::fs::write(dir.path().join(".gitignore"), "*.log\n").expect("write .gitignore");
    std::fs::write(dir.path().join("keep.txt"), "ok\n").expect("write keep.txt");
    std::fs::write(dir.path().join("ignored.log"), "nope\n").expect("write ignored.log");

    let artifacts_root = dir.path().join("artifacts");
    let output = admit_cli::ingest_dir(dir.path(), Some(&artifacts_root)).expect("ingest_dir");
    let files: Vec<&str> = output.files.iter().map(|f| f.rel_path.as_str()).collect();

    assert!(files.contains(&"keep.txt"));
    assert!(!files.contains(&"ignored.log"));
}

#[test]
fn ingest_dir_respects_gitignore_without_git_repo() {
    // Force the ingest path to avoid `git ls-files` so we exercise `.gitignore` handling
    // in the fallback walker.
    std::env::set_var("ADMIT_INGEST_DISABLE_GIT", "1");
    struct Unset;
    impl Drop for Unset {
        fn drop(&mut self) {
            std::env::remove_var("ADMIT_INGEST_DISABLE_GIT");
        }
    }
    let _unset = Unset;

    let dir = tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".gitignore"), "*.log\n").expect("write .gitignore");
    std::fs::write(dir.path().join("keep.txt"), "ok\n").expect("write keep.txt");
    std::fs::write(dir.path().join("ignored.log"), "nope\n").expect("write ignored.log");

    let artifacts_root = dir.path().join("artifacts");
    let output = admit_cli::ingest_dir(dir.path(), Some(&artifacts_root)).expect("ingest_dir");
    let files: Vec<&str> = output.files.iter().map(|f| f.rel_path.as_str()).collect();

    assert!(files.contains(&"keep.txt"));
    assert!(!files.contains(&"ignored.log"));
}
