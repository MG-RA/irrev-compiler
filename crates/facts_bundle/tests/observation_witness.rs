use std::path::PathBuf;

use admit_core::cbor::encode_canonical;
use admit_core::{
    eval, BoolExpr, CmpOp, DisplacementMode, EvalOpts, FloatPolicy, ModuleId, Predicate, Program,
    Quantity, Query, ScopeId, Span, Stmt, SymbolNamespace, SymbolRef, Verdict, Witness,
};
use facts_bundle::{bundle_with_hash, facts_to_commits, observe_regex, ObservationPattern};
use sha2::{Digest, Sha256};

fn compiler_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize compiler root")
}

fn golden_fixture_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
        .join("golden-witness")
        .join(filename)
}

fn symbol(ns: SymbolNamespace, name: &str) -> SymbolRef {
    SymbolRef {
        ns,
        name: name.to_string(),
    }
}

fn base_program() -> Program {
    let diff = symbol(SymbolNamespace::Difference, "prescriptive_claims");
    let constraint = Stmt::Constraint {
        id: None,
        expr: BoolExpr::Pred {
            pred: Predicate::CommitCmp {
                diff: diff.clone(),
                op: CmpOp::Gt,
                value: Quantity {
                    value: 2.0,
                    unit: "count".to_string(),
                },
            },
        },
        span: Span {
            file: "facts.adm".to_string(),
            start: Some(0),
            end: Some(0),
            line: Some(1),
            col: Some(1),
        },
    };

    Program {
        module: ModuleId("module:test@1".to_string()),
        scope: ScopeId("scope:main".to_string()),
        dependencies: vec![ModuleId("module:irrev_std@1".to_string())],
        statements: vec![
            Stmt::DeclareDifference {
                diff: diff.clone(),
                unit: Some("count".to_string()),
                span: Span {
                    file: "facts.adm".to_string(),
                    start: Some(0),
                    end: Some(0),
                    line: Some(1),
                    col: Some(1),
                },
            },
            constraint,
        ],
    }
}

fn observe_bundle() -> facts_bundle::FactsBundle {
    let root = compiler_root();
    let input = root.join("testdata").join("facts").join("prescriptive.md");
    let patterns = vec![ObservationPattern {
        diff: "difference:prescriptive_claims".to_string(),
        regex: r"\bshould\b|\bmust\b".to_string(),
        unit: Some("count".to_string()),
    }];
    observe_regex(&[input], &patterns, true, None, Some(&root)).expect("observe regex")
}

fn witness_from_observation() -> Witness {
    let bundle = observe_bundle();
    let bundle_with_hash = bundle_with_hash(bundle).expect("hash bundle");
    let mut program = base_program();
    let commits = facts_to_commits(&bundle_with_hash.bundle).expect("facts to commits");
    program.statements.extend(commits);

    let mut witness = eval(
        &program,
        Query::Admissible,
        EvalOpts {
            displacement_mode: DisplacementMode::Potential,
            float_policy: FloatPolicy::Ban,
        },
    )
    .expect("eval");
    witness.program.facts_bundle_hash = Some(bundle_with_hash.sha256);
    witness
}

fn canonical_hash(witness: &Witness) -> String {
    let bytes = encode_canonical(witness).expect("canonical cbor");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[test]
fn observation_witness_matches_golden() {
    let witness = witness_from_observation();
    assert_eq!(witness.verdict, Verdict::Inadmissible);

    let actual_json = serde_json::to_string_pretty(&witness).expect("serialize witness to JSON");
    let expected_json =
        std::fs::read_to_string(golden_fixture_path("facts-prescriptive-count.json"))
            .expect("read golden JSON");
    let expected_json = expected_json.trim_end_matches(|c| c == '\n' || c == '\r');
    assert_eq!(actual_json, expected_json);

    let actual_hash = canonical_hash(&witness);
    let expected_hash =
        std::fs::read_to_string(golden_fixture_path("facts-prescriptive-count.cbor.sha256"))
            .expect("read golden hash")
            .trim()
            .to_string();
    assert_eq!(actual_hash, expected_hash);
}

#[test]
#[ignore]
fn dump_observation_goldens() {
    let witness = witness_from_observation();
    let json = serde_json::to_string_pretty(&witness).expect("serialize witness");
    let hash = canonical_hash(&witness);
    std::fs::write(golden_fixture_path("facts-prescriptive-count.json"), &json)
        .expect("write golden json");
    std::fs::write(golden_fixture_path("facts-prescriptive-count.cbor.sha256"), &hash)
        .expect("write golden hash");
    println!("WROTE facts-prescriptive-count: hash={}", hash);
}
