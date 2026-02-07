use std::collections::BTreeSet;

use tempfile::tempdir;

#[test]
fn ingest_incremental_cache_tracks_changes_and_dependencies() {
    std::env::set_var("ADMIT_INGEST_DISABLE_GIT", "1");
    struct Unset;
    impl Drop for Unset {
        fn drop(&mut self) {
            std::env::remove_var("ADMIT_INGEST_DISABLE_GIT");
        }
    }
    let _unset = Unset;

    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    std::fs::write(root.join("A.md"), "# A\n\nLink to [[B#Heading]]\n").expect("write A.md");
    std::fs::write(root.join("B.md"), "# B\n\n## Heading\nContent\n").expect("write B.md");
    std::fs::write(root.join("note.txt"), "plain text").expect("write note.txt");

    let artifacts_dir = tempdir().expect("artifacts dir");
    let cache_dir = tempdir().expect("cache dir");
    let cache_path = cache_dir.path().join("ingest-cache.json");

    let first =
        admit_cli::ingest_dir_with_cache(root, Some(artifacts_dir.path()), Some(&cache_path))
            .expect("ingest_dir first");
    let inc = first.incremental.as_ref().expect("incremental");
    assert!(inc.enabled);
    assert_eq!(inc.files_parsed, 3);
    assert_eq!(inc.files_cached, 0);
    assert_eq!(inc.chunks_parsed, 4);
    assert_eq!(inc.chunks_cached, 0);
    let mut expected: BTreeSet<String> = ["A.md".to_string(), "B.md".to_string()]
        .into_iter()
        .collect();
    let actual: BTreeSet<String> = inc.docs_to_resolve_links.iter().cloned().collect();
    assert_eq!(actual, expected);

    let second =
        admit_cli::ingest_dir_with_cache(root, Some(artifacts_dir.path()), Some(&cache_path))
            .expect("ingest_dir second");
    let inc = second.incremental.as_ref().expect("incremental second");
    assert!(inc.enabled);
    assert_eq!(inc.files_parsed, 0);
    assert_eq!(inc.files_cached, 3);
    assert_eq!(inc.chunks_parsed, 0);
    assert_eq!(inc.chunks_cached, 4);
    assert!(inc.docs_to_resolve_links.is_empty());

    std::fs::write(root.join("B.md"), "# B\n\n## Heading2\nContent\n").expect("write B.md v2");
    let third =
        admit_cli::ingest_dir_with_cache(root, Some(artifacts_dir.path()), Some(&cache_path))
            .expect("ingest_dir third");
    let inc = third.incremental.as_ref().expect("incremental third");
    assert!(inc.enabled);
    assert_eq!(inc.files_parsed, 1);
    assert_eq!(inc.files_cached, 2);
    assert_eq!(inc.chunks_parsed, 2);
    assert_eq!(inc.chunks_cached, 2);
    expected = ["A.md".to_string(), "B.md".to_string()]
        .into_iter()
        .collect();
    let actual: BTreeSet<String> = inc.docs_to_resolve_links.iter().cloned().collect();
    assert_eq!(actual, expected);
}
