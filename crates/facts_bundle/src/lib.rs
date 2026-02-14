use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use admit_core::{CommitValue, Quantity, Span, Stmt, SymbolNamespace, SymbolRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum FactsError {
    Io(String),
    Utf8(String),
    Json(String),
    Canonical(String),
    Regex(String),
    DiffFormat(String),
    Span(String),
}

impl std::fmt::Display for FactsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FactsError::Io(err) => write!(f, "io error: {}", err),
            FactsError::Utf8(err) => write!(f, "utf8 error: {}", err),
            FactsError::Json(err) => write!(f, "json error: {}", err),
            FactsError::Canonical(err) => write!(f, "canonical json error: {}", err),
            FactsError::Regex(err) => write!(f, "regex error: {}", err),
            FactsError::DiffFormat(err) => write!(f, "diff format error: {}", err),
            FactsError::Span(err) => write!(f, "span error: {}", err),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactsBundle {
    pub schema_id: String,
    pub schema_version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    pub sources: Vec<FactSource>,
    pub facts: Vec<FactCommit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactSource {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactCommit {
    pub diff: String,
    pub value: CommitValue,
    pub span: Span,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<FactSourceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactSourceRef {
    pub path: String,
    pub count: u64,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FactsBundleWithHash {
    pub bundle: FactsBundle,
    pub sha256: String,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ObservationPattern {
    pub diff: String,
    pub regex: String,
    pub unit: Option<String>,
}

pub fn load_bundle_with_hash(path: &Path) -> Result<FactsBundleWithHash, FactsError> {
    let bytes = fs::read(path).map_err(|err| FactsError::Io(err.to_string()))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|err| FactsError::Json(err.to_string()))?;
    let canonical_bytes = canonical_json_bytes(&value)?;
    let sha256 = sha256_hex(&canonical_bytes);
    let bundle: FactsBundle =
        serde_json::from_value(value).map_err(|err| FactsError::Json(err.to_string()))?;
    Ok(FactsBundleWithHash {
        bundle,
        sha256,
        canonical_bytes,
    })
}

pub fn bundle_with_hash(bundle: FactsBundle) -> Result<FactsBundleWithHash, FactsError> {
    let value = serde_json::to_value(&bundle).map_err(|err| FactsError::Json(err.to_string()))?;
    let canonical_bytes = canonical_json_bytes(&value)?;
    let sha256 = sha256_hex(&canonical_bytes);
    Ok(FactsBundleWithHash {
        bundle,
        sha256,
        canonical_bytes,
    })
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, FactsError> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out.into_bytes())
}

pub fn observe_regex(
    paths: &[PathBuf],
    patterns: &[ObservationPattern],
    case_insensitive: bool,
    generated_at: Option<String>,
    source_root: Option<&Path>,
) -> Result<FactsBundle, FactsError> {
    let mut sources = Vec::new();
    let mut totals: BTreeMap<String, (u64, Option<String>)> = BTreeMap::new();
    let mut fact_sources: BTreeMap<String, Vec<FactSourceRef>> = BTreeMap::new();

    let mut compiled = Vec::new();
    for pattern in patterns {
        compiled.push(CompiledPattern::from_pattern(pattern)?);
    }

    let mut sorted_paths = paths.to_vec();
    sorted_paths.sort();

    for path in sorted_paths {
        let bytes = fs::read(&path).map_err(|err| FactsError::Io(err.to_string()))?;
        let sha = sha256_hex(&bytes);
        let text = String::from_utf8(bytes).map_err(|err| FactsError::Utf8(err.to_string()))?;
        let path_str = source_root
            .and_then(|root| path.strip_prefix(root).ok())
            .map(|rel| rel.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string_lossy().to_string())
            .replace('\\', "/");
        sources.push(FactSource {
            path: path_str.clone(),
            sha256: sha,
        });

        for pattern in &compiled {
            let matches = find_matches(&text, pattern, case_insensitive);
            let count = matches.len() as u64;
            let mut first_span: Option<Span> = None;
            if let Some((start, end)) = matches.first().copied() {
                let (line, col) = line_col_for_offset(&text, start);
                first_span = Some(Span {
                    file: path_str.clone(),
                    start: Some(to_u32(start)?),
                    end: Some(to_u32(end)?),
                    line: Some(line),
                    col: Some(col),
                });
            }
            if count > 0 {
                let unit = pattern.unit.clone();
                let entry = totals.entry(pattern.diff.clone()).or_insert((0u64, unit));
                entry.0 += count;
                let span = first_span.unwrap_or_else(|| Span {
                    file: path_str.clone(),
                    start: Some(0),
                    end: Some(0),
                    line: Some(1),
                    col: Some(1),
                });
                fact_sources
                    .entry(pattern.diff.clone())
                    .or_default()
                    .push(FactSourceRef {
                        path: path_str.clone(),
                        count,
                        span,
                    });
            }
        }
    }

    sources.sort_by(|a, b| a.path.cmp(&b.path));

    let mut facts = Vec::new();
    for (diff, (count, unit)) in totals {
        let sources_for_diff = fact_sources.get(&diff).cloned().unwrap_or_default();
        let span = sources_for_diff
            .iter()
            .min_by(|a, b| a.path.cmp(&b.path))
            .map(|s| s.span.clone())
            .unwrap_or_else(|| Span {
                file: "unknown".to_string(),
                start: Some(0),
                end: Some(0),
                line: Some(1),
                col: Some(1),
            });
        let unit = unit.unwrap_or_else(|| "count".to_string());
        let value = CommitValue::Quantity(Quantity {
            value: count as f64,
            unit,
        });
        let mut sources_for_diff = sources_for_diff;
        sources_for_diff.sort_by(|a, b| a.path.cmp(&b.path));
        facts.push(FactCommit {
            diff,
            value,
            span,
            sources: sources_for_diff,
        });
    }

    facts.sort_by(|a, b| a.diff.cmp(&b.diff));

    Ok(FactsBundle {
        schema_id: "facts-bundle/0".to_string(),
        schema_version: 0,
        generated_at,
        sources,
        facts,
    })
}

pub fn facts_to_commits(bundle: &FactsBundle) -> Result<Vec<Stmt>, FactsError> {
    let mut commits = Vec::new();
    for fact in &bundle.facts {
        let diff = parse_diff(&fact.diff)?;
        commits.push(Stmt::Commit {
            diff,
            value: fact.value.clone(),
            span: fact.span.clone(),
        });
    }
    Ok(commits)
}

fn parse_diff(diff: &str) -> Result<SymbolRef, FactsError> {
    if let Some(name) = diff.strip_prefix("difference:") {
        Ok(SymbolRef {
            ns: SymbolNamespace::Difference,
            name: name.to_string(),
        })
    } else {
        Err(FactsError::DiffFormat(format!(
            "expected difference:<name>, got {}",
            diff
        )))
    }
}

#[derive(Debug, Clone)]
struct CompiledPattern {
    diff: String,
    unit: Option<String>,
    terms: Vec<PatternTerm>,
}

#[derive(Debug, Clone)]
enum PatternTerm {
    Word(String),
    Substring(String),
}

impl CompiledPattern {
    fn from_pattern(pattern: &ObservationPattern) -> Result<Self, FactsError> {
        let parts: Vec<_> = pattern
            .regex
            .split('|')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .collect();
        if parts.is_empty() {
            return Err(FactsError::Regex("empty pattern".to_string()));
        }
        let mut terms = Vec::new();
        for part in parts {
            if let Some(term) = part.strip_prefix("\\b").and_then(|t| t.strip_suffix("\\b")) {
                terms.push(PatternTerm::Word(term.to_string()));
            } else {
                terms.push(PatternTerm::Substring(part.to_string()));
            }
        }
        Ok(Self {
            diff: pattern.diff.clone(),
            unit: pattern.unit.clone(),
            terms,
        })
    }
}

fn find_matches(
    text: &str,
    pattern: &CompiledPattern,
    case_insensitive: bool,
) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
    for term in &pattern.terms {
        match term {
            PatternTerm::Word(word) => {
                matches.extend(find_term_matches(text, word, case_insensitive, true));
            }
            PatternTerm::Substring(sub) => {
                matches.extend(find_term_matches(text, sub, case_insensitive, false));
            }
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

fn find_term_matches(
    text: &str,
    needle: &str,
    case_insensitive: bool,
    word_boundary: bool,
) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
    if needle.is_empty() {
        return matches;
    }
    let hay = text.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.len() > hay.len() {
        return matches;
    }
    let last = hay.len() - needle_bytes.len();
    for start in 0..=last {
        if bytes_match(
            &hay[start..start + needle_bytes.len()],
            needle_bytes,
            case_insensitive,
        ) {
            let end = start + needle_bytes.len();
            if !word_boundary || is_word_boundary_bytes(hay, start, end) {
                matches.push((start, end));
            }
        }
    }
    matches
}

fn bytes_match(hay: &[u8], needle: &[u8], case_insensitive: bool) -> bool {
    if case_insensitive {
        hay.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    } else {
        hay == needle
    }
}

fn is_word_boundary_bytes(hay: &[u8], start: usize, end: usize) -> bool {
    let before = if start == 0 {
        None
    } else {
        Some(hay[start - 1])
    };
    let after = if end >= hay.len() {
        None
    } else {
        Some(hay[end])
    };
    let before_is_word = before.map(is_word_char_byte).unwrap_or(false);
    let after_is_word = after.map(is_word_char_byte).unwrap_or(false);
    !before_is_word && !after_is_word
}

fn is_word_char_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn line_col_for_offset(text: &str, offset: usize) -> (u32, u32) {
    let mut line = 1u32;
    let mut col = 1u32;
    for (idx, ch) in text.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

fn to_u32(value: usize) -> Result<u32, FactsError> {
    u32::try_from(value).map_err(|_| FactsError::Span("offset out of range".to_string()))
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), FactsError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            let s = serde_json::to_string(value)
                .map_err(|err| FactsError::Canonical(err.to_string()))?;
            out.push_str(&s);
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let key_json = serde_json::to_string(key)
                    .map_err(|err| FactsError::Canonical(err.to_string()))?;
                out.push_str(&key_json);
                out.push(':');
                if let Some(val) = map.get(*key) {
                    write_canonical_json(val, out)?;
                }
            }
            out.push('}');
            Ok(())
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
