//! Pure syn-based structural fact extraction.
//!
//! Parses Rust source files and emits deterministic `Fact::LintFinding` observations.
//! All `rust/*` rule_ids are non-normative (Severity::Info). Normativity is the
//! responsibility of separate constraint packs.

use admit_core::witness::{Fact, Severity};
use admit_core::Span;
use serde_json::{Map, Value};
use syn::{Attribute, Fields, ImplItem, Item, Meta, TraitItem, Type, UseTree, Visibility};

use crate::file_walker::RustSourceFile;

/// Extract structural facts from a single Rust source file.
///
/// Returns an empty vec (not an error) if the file cannot be parsed,
/// plus a single `rust/parse_error` warning fact.
pub fn extract_facts(file: &RustSourceFile) -> Vec<Fact> {
    let mut facts = Vec::new();

    match syn::parse_file(&file.content) {
        Ok(parsed) => {
            for item in &parsed.items {
                extract_item_facts(item, &file.rel_path, None, &mut facts);
            }
        }
        Err(e) => {
            facts.push(Fact::LintFinding {
                rule_id: "rust/parse_error".to_string(),
                severity: Severity::Warning,
                invariant: None,
                path: file.rel_path.clone(),
                span: Span {
                    file: file.rel_path.clone(),
                    start: None,
                    end: None,
                    line: None,
                    col: None,
                },
                message: "failed to parse Rust source".to_string(),
                evidence: Some(serde_json::json!({
                    "error_message": e.to_string(),
                    "file_sha256": file.sha256
                })),
            });
        }
    }

    // Attach source hash provenance to every emitted finding.
    for fact in &mut facts {
        attach_source_hash(fact, &file.sha256);
    }

    facts
}

fn attach_source_hash(fact: &mut Fact, file_sha256: &str) {
    if let Fact::LintFinding { evidence, .. } = fact {
        let mut obj = match evidence.take() {
            Some(Value::Object(map)) => map,
            Some(other) => {
                let mut map = Map::new();
                map.insert("value".to_string(), other);
                map
            }
            None => Map::new(),
        };
        obj.entry("file_sha256".to_string())
            .or_insert(Value::String(file_sha256.to_string()));
        *evidence = Some(Value::Object(obj));
    }
}

fn extract_item_facts(
    item: &Item,
    file_path: &str,
    enclosing_fn: Option<&str>,
    facts: &mut Vec<Fact>,
) {
    match item {
        Item::Fn(f) => {
            let vis = visibility_str(&f.vis);
            if !vis.is_empty() {
                let name = f.sig.ident.to_string();
                facts.push(Fact::LintFinding {
                    rule_id: "rust/pub_fn".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_ident(file_path, &f.sig.ident),
                    message: format!("{} fn {}", vis, name),
                    evidence: Some(serde_json::json!({
                        "generic_count": f.sig.generics.params.len(),
                        "is_async": f.sig.asyncness.is_some(),
                        "is_unsafe": f.sig.unsafety.is_some(),
                        "name": name,
                        "visibility": vis
                    })),
                });
            }
            // Check for unsafe fn (even if not pub)
            if f.sig.unsafety.is_some() {
                let name = f.sig.ident.to_string();
                facts.push(Fact::LintFinding {
                    rule_id: "rust/unsafe_block".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_ident(file_path, &f.sig.ident),
                    message: format!("unsafe fn {}", name),
                    evidence: Some(serde_json::json!({
                        "kind": "fn",
                        "enclosing_fn": enclosing_fn
                    })),
                });
            }
            // Scan body for unsafe blocks
            extract_unsafe_blocks(&f.block.stmts, file_path, &f.sig.ident.to_string(), facts);
        }
        Item::Struct(s) => {
            let vis = visibility_str(&s.vis);
            if !vis.is_empty() {
                let name = s.ident.to_string();
                let field_count = match &s.fields {
                    Fields::Named(n) => n.named.len(),
                    Fields::Unnamed(u) => u.unnamed.len(),
                    Fields::Unit => 0,
                };
                let mut derives = derives_from_attrs(&s.attrs);
                derives.sort();
                facts.push(Fact::LintFinding {
                    rule_id: "rust/pub_struct".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_ident(file_path, &s.ident),
                    message: format!("{} struct {} ({} fields)", vis, name, field_count),
                    evidence: Some(serde_json::json!({
                        "derives": derives,
                        "field_count": field_count,
                        "name": name,
                        "visibility": vis
                    })),
                });
            }
        }
        Item::Enum(e) => {
            let vis = visibility_str(&e.vis);
            if !vis.is_empty() {
                let name = e.ident.to_string();
                let variant_count = e.variants.len();
                let mut derives = derives_from_attrs(&e.attrs);
                derives.sort();
                facts.push(Fact::LintFinding {
                    rule_id: "rust/pub_enum".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_ident(file_path, &e.ident),
                    message: format!("{} enum {} ({} variants)", vis, name, variant_count),
                    evidence: Some(serde_json::json!({
                        "derives": derives,
                        "name": name,
                        "variant_count": variant_count,
                        "visibility": vis
                    })),
                });
            }
        }
        Item::Trait(t) => {
            let vis = visibility_str(&t.vis);
            if !vis.is_empty() {
                let name = t.ident.to_string();
                let method_count = t
                    .items
                    .iter()
                    .filter(|i| matches!(i, TraitItem::Fn(_)))
                    .count();
                let mut supertraits: Vec<String> =
                    t.supertraits.iter().map(quote_to_string).collect();
                supertraits.sort();
                facts.push(Fact::LintFinding {
                    rule_id: "rust/pub_trait".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_ident(file_path, &t.ident),
                    message: format!("{} trait {} ({} methods)", vis, name, method_count),
                    evidence: Some(serde_json::json!({
                        "method_count": method_count,
                        "name": name,
                        "supertraits": supertraits,
                        "visibility": vis
                    })),
                });
            }
            // Check for unsafe trait
            if t.unsafety.is_some() {
                facts.push(Fact::LintFinding {
                    rule_id: "rust/unsafe_block".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_ident(file_path, &t.ident),
                    message: format!("unsafe trait {}", t.ident),
                    evidence: Some(serde_json::json!({
                        "kind": "trait",
                        "enclosing_fn": enclosing_fn
                    })),
                });
            }
        }
        Item::Impl(i) => {
            let self_type = type_to_string(&i.self_ty);
            let trait_name = i.trait_.as_ref().map(|(_, path, _)| quote_to_string(path));
            let method_count = i
                .items
                .iter()
                .filter(|item| matches!(item, ImplItem::Fn(_)))
                .count();
            facts.push(Fact::LintFinding {
                rule_id: "rust/impl_block".to_string(),
                severity: Severity::Info,
                invariant: None,
                path: file_path.to_string(),
                span: span_for_type(file_path, &i.self_ty),
                message: if let Some(ref tn) = trait_name {
                    format!("impl {} for {} ({} methods)", tn, self_type, method_count)
                } else {
                    format!("impl {} ({} methods)", self_type, method_count)
                },
                evidence: Some(serde_json::json!({
                    "method_count": method_count,
                    "self_type": self_type,
                    "trait_name": trait_name
                })),
            });
            // Check for unsafe impl
            if i.unsafety.is_some() {
                facts.push(Fact::LintFinding {
                    rule_id: "rust/unsafe_block".to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: file_path.to_string(),
                    span: span_for_type(file_path, &i.self_ty),
                    message: format!("unsafe impl for {}", self_type),
                    evidence: Some(serde_json::json!({
                        "kind": "impl",
                        "enclosing_fn": enclosing_fn
                    })),
                });
            }
        }
        Item::Mod(m) => {
            let vis = visibility_str(&m.vis);
            let name = m.ident.to_string();
            let is_inline = m.content.is_some();
            facts.push(Fact::LintFinding {
                rule_id: "rust/module".to_string(),
                severity: Severity::Info,
                invariant: None,
                path: file_path.to_string(),
                span: span_for_ident(file_path, &m.ident),
                message: if vis.is_empty() {
                    format!("mod {}", name)
                } else {
                    format!("{} mod {}", vis, name)
                },
                evidence: Some(serde_json::json!({
                    "is_inline": is_inline,
                    "name": name,
                    "visibility": vis
                })),
            });
            // Recurse into inline module items
            if let Some((_, items)) = &m.content {
                for item in items {
                    extract_item_facts(item, file_path, enclosing_fn, facts);
                }
            }
        }
        Item::Use(u) => {
            let vis = visibility_str(&u.vis);
            let (path, is_glob) = use_tree_to_string(&u.tree);
            facts.push(Fact::LintFinding {
                rule_id: "rust/use_import".to_string(),
                severity: Severity::Info,
                invariant: None,
                path: file_path.to_string(),
                span: span_for_use_tree(file_path, &u.tree),
                message: format!("use {}", path),
                evidence: Some(serde_json::json!({
                    "is_glob": is_glob,
                    "path": path,
                    "visibility": vis
                })),
            });
        }
        Item::ExternCrate(ec) => {
            let name = ec.ident.to_string();
            facts.push(Fact::LintFinding {
                rule_id: "rust/extern_crate".to_string(),
                severity: Severity::Info,
                invariant: None,
                path: file_path.to_string(),
                span: span_for_ident(file_path, &ec.ident),
                message: format!("extern crate {}", name),
                evidence: Some(serde_json::json!({
                    "name": name
                })),
            });
        }
        _ => {}
    }
}

/// Scan function body statements for `unsafe` blocks.
fn extract_unsafe_blocks(
    stmts: &[syn::Stmt],
    file_path: &str,
    enclosing_fn_name: &str,
    facts: &mut Vec<Fact>,
) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                find_unsafe_in_expr(expr, file_path, enclosing_fn_name, facts);
            }
            syn::Stmt::Local(syn::Local {
                init: Some(syn::LocalInit { expr, .. }),
                ..
            }) => {
                find_unsafe_in_expr(expr, file_path, enclosing_fn_name, facts);
            }
            _ => {}
        }
    }
}

fn find_unsafe_in_expr(
    expr: &syn::Expr,
    file_path: &str,
    enclosing_fn_name: &str,
    facts: &mut Vec<Fact>,
) {
    if let syn::Expr::Unsafe(u) = expr {
        let s = u.unsafe_token.span;
        let start = s.start();
        facts.push(Fact::LintFinding {
            rule_id: "rust/unsafe_block".to_string(),
            severity: Severity::Info,
            invariant: None,
            path: file_path.to_string(),
            span: Span {
                file: file_path.to_string(),
                line: Some(start.line as u32),
                col: Some(start.column as u32),
                start: None,
                end: None,
            },
            message: format!("unsafe block in {}", enclosing_fn_name),
            evidence: Some(serde_json::json!({
                "enclosing_fn": enclosing_fn_name,
                "kind": "block"
            })),
        });
    }
    // Note: deep recursive expression walking is intentionally limited to top-level
    // unsafe blocks. A full expression visitor would be needed for nested unsafe in
    // closures, match arms, etc. This is sufficient for v0 structural facts.
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn visibility_str(vis: &Visibility) -> &'static str {
    match vis {
        Visibility::Public(_) => "pub",
        Visibility::Restricted(r) => {
            let path_str = quote_to_string(&r.path);
            match path_str.as_str() {
                "crate" => "pub(crate)",
                "super" => "pub(super)",
                "self" => "pub(self)",
                _ => "pub(restricted)",
            }
        }
        Visibility::Inherited => "",
    }
}

fn derives_from_attrs(attrs: &[Attribute]) -> Vec<String> {
    let mut derives = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        if let Meta::List(list) = &attr.meta {
            // Parse the token stream as comma-separated idents
            let tokens = list.tokens.to_string();
            for token in tokens.split(',') {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    derives.push(trimmed.to_string());
                }
            }
        }
    }
    derives.sort();
    derives
}

fn span_for_ident(file_path: &str, ident: &syn::Ident) -> Span {
    let s = ident.span();
    let start = s.start();
    Span {
        file: file_path.to_string(),
        line: Some(start.line as u32),
        col: Some(start.column as u32),
        start: None,
        end: None,
    }
}

fn span_for_type(file_path: &str, ty: &Type) -> Span {
    let s = quote::quote!(#ty).into_iter().next();
    if let Some(first_token) = s {
        let sp = first_token.span();
        let start = sp.start();
        Span {
            file: file_path.to_string(),
            line: Some(start.line as u32),
            col: Some(start.column as u32),
            start: None,
            end: None,
        }
    } else {
        Span {
            file: file_path.to_string(),
            line: None,
            col: None,
            start: None,
            end: None,
        }
    }
}

fn span_for_use_tree(file_path: &str, tree: &UseTree) -> Span {
    let s = quote::quote!(#tree).into_iter().next();
    if let Some(first_token) = s {
        let sp = first_token.span();
        let start = sp.start();
        Span {
            file: file_path.to_string(),
            line: Some(start.line as u32),
            col: Some(start.column as u32),
            start: None,
            end: None,
        }
    } else {
        Span {
            file: file_path.to_string(),
            line: None,
            col: None,
            start: None,
            end: None,
        }
    }
}

fn type_to_string(ty: &Type) -> String {
    quote::quote!(#ty).to_string().replace(' ', "")
}

fn quote_to_string(tokens: impl quote::ToTokens) -> String {
    quote::quote!(#tokens).to_string().replace(' ', "")
}

fn use_tree_to_string(tree: &UseTree) -> (String, bool) {
    match tree {
        UseTree::Path(p) => {
            let (rest, is_glob) = use_tree_to_string(&p.tree);
            (format!("{}::{}", p.ident, rest), is_glob)
        }
        UseTree::Name(n) => (n.ident.to_string(), false),
        UseTree::Rename(r) => (format!("{} as {}", r.ident, r.rename), false),
        UseTree::Glob(_) => ("*".to_string(), true),
        UseTree::Group(g) => {
            let mut parts: Vec<String> = Vec::new();
            let mut any_glob = false;
            for tree in &g.items {
                let (part, is_glob) = use_tree_to_string(tree);
                parts.push(part);
                if is_glob {
                    any_glob = true;
                }
            }
            parts.sort();
            (format!("{{{}}}", parts.join(", ")), any_glob)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_walker::sha256_hex;

    fn source_file(content: &str) -> RustSourceFile {
        RustSourceFile {
            rel_path: "test.rs".to_string(),
            content: content.to_string(),
            sha256: sha256_hex(content.as_bytes()),
        }
    }

    fn find_facts_by_rule<'a>(facts: &'a [Fact], rule_id: &str) -> Vec<&'a Fact> {
        facts
            .iter()
            .filter(|f| matches!(f, Fact::LintFinding { rule_id: rid, .. } if rid == rule_id))
            .collect()
    }

    fn evidence_of(fact: &Fact) -> serde_json::Value {
        match fact {
            Fact::LintFinding { evidence, .. } => {
                evidence.clone().unwrap_or(serde_json::Value::Null)
            }
            _ => serde_json::Value::Null,
        }
    }

    #[test]
    fn extracts_pub_fn() {
        let file = source_file("pub fn hello() {}\npub async unsafe fn danger() {}");
        let facts = extract_facts(&file);

        let pub_fns = find_facts_by_rule(&facts, "rust/pub_fn");
        assert_eq!(pub_fns.len(), 2);

        let ev0 = evidence_of(pub_fns[0]);
        assert_eq!(ev0["name"], "hello");
        assert_eq!(ev0["visibility"], "pub");
        assert_eq!(ev0["is_async"], false);
        assert_eq!(ev0["is_unsafe"], false);

        let ev1 = evidence_of(pub_fns[1]);
        assert_eq!(ev1["name"], "danger");
        assert_eq!(ev1["is_async"], true);
        assert_eq!(ev1["is_unsafe"], true);
    }

    #[test]
    fn extracts_pub_struct_with_derives() {
        let file = source_file(
            "#[derive(Debug, Clone, Serialize)]\npub struct Foo {\n    x: i32,\n    y: String,\n}",
        );
        let facts = extract_facts(&file);

        let structs = find_facts_by_rule(&facts, "rust/pub_struct");
        assert_eq!(structs.len(), 1);

        let ev = evidence_of(structs[0]);
        assert_eq!(ev["name"], "Foo");
        assert_eq!(ev["field_count"], 2);
        // Derives should be sorted
        let derives: Vec<String> = ev["derives"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(derives, vec!["Clone", "Debug", "Serialize"]);
    }

    #[test]
    fn extracts_pub_enum() {
        let file = source_file("pub enum Color { Red, Green, Blue }");
        let facts = extract_facts(&file);

        let enums = find_facts_by_rule(&facts, "rust/pub_enum");
        assert_eq!(enums.len(), 1);

        let ev = evidence_of(enums[0]);
        assert_eq!(ev["name"], "Color");
        assert_eq!(ev["variant_count"], 3);
    }

    #[test]
    fn extracts_pub_trait_with_supertraits() {
        let file =
            source_file("pub trait Foo: Send + Sync {\n    fn bar(&self);\n    fn baz(&self);\n}");
        let facts = extract_facts(&file);

        let traits = find_facts_by_rule(&facts, "rust/pub_trait");
        assert_eq!(traits.len(), 1);

        let ev = evidence_of(traits[0]);
        assert_eq!(ev["name"], "Foo");
        assert_eq!(ev["method_count"], 2);
        let supers: Vec<String> = ev["supertraits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(supers, vec!["Send", "Sync"]); // sorted
    }

    #[test]
    fn extracts_impl_block() {
        let file = source_file("struct X;\nimpl X {\n    fn foo(&self) {}\n}");
        let facts = extract_facts(&file);

        let impls = find_facts_by_rule(&facts, "rust/impl_block");
        assert_eq!(impls.len(), 1);

        let ev = evidence_of(impls[0]);
        assert_eq!(ev["self_type"], "X");
        assert_eq!(ev["trait_name"], serde_json::Value::Null);
        assert_eq!(ev["method_count"], 1);
    }

    #[test]
    fn extracts_trait_impl() {
        let file = source_file(
            "struct X;\ntrait T { fn f(&self); }\nimpl T for X {\n    fn f(&self) {}\n}",
        );
        let facts = extract_facts(&file);

        let impls = find_facts_by_rule(&facts, "rust/impl_block");
        assert_eq!(impls.len(), 1);

        let ev = evidence_of(impls[0]);
        assert_eq!(ev["self_type"], "X");
        assert_eq!(ev["trait_name"], "T");
    }

    #[test]
    fn extracts_unsafe_fn_and_block() {
        let file = source_file(
            "pub unsafe fn danger() {\n    unsafe { std::ptr::null::<u8>().read() };\n}",
        );
        let facts = extract_facts(&file);

        let unsafes = find_facts_by_rule(&facts, "rust/unsafe_block");
        // Should find: unsafe fn + unsafe block inside
        assert!(unsafes.len() >= 1);
        let kinds: Vec<String> = unsafes
            .iter()
            .map(|f| evidence_of(f)["kind"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(kinds.iter().any(|k| k == "fn"));
    }

    #[test]
    fn extracts_module() {
        let file = source_file("pub mod foo;\nmod bar { fn inner() {} }");
        let facts = extract_facts(&file);

        let mods = find_facts_by_rule(&facts, "rust/module");
        assert_eq!(mods.len(), 2);

        // foo is not inline, bar is inline
        let ev_foo = evidence_of(mods[0]);
        let ev_bar = evidence_of(mods[1]);
        // Find which is which by name
        if ev_foo["name"] == "foo" {
            assert_eq!(ev_foo["is_inline"], false);
            assert_eq!(ev_bar["is_inline"], true);
        } else {
            assert_eq!(ev_bar["is_inline"], false);
            assert_eq!(ev_foo["is_inline"], true);
        }
    }

    #[test]
    fn extracts_use_import() {
        let file = source_file("use std::collections::BTreeMap;\nuse std::io::*;");
        let facts = extract_facts(&file);

        let uses = find_facts_by_rule(&facts, "rust/use_import");
        assert_eq!(uses.len(), 2);

        let paths: Vec<String> = uses
            .iter()
            .map(|f| evidence_of(f)["path"].as_str().unwrap().to_string())
            .collect();
        assert!(paths.iter().any(|p| p.contains("BTreeMap")));

        let globs: Vec<bool> = uses
            .iter()
            .map(|f| evidence_of(f)["is_glob"].as_bool().unwrap())
            .collect();
        assert!(globs.contains(&true)); // the glob import
        assert!(globs.contains(&false)); // the non-glob
    }

    #[test]
    fn extracts_extern_crate() {
        let file = source_file("extern crate alloc;");
        let facts = extract_facts(&file);

        let externs = find_facts_by_rule(&facts, "rust/extern_crate");
        assert_eq!(externs.len(), 1);
        assert_eq!(evidence_of(externs[0])["name"], "alloc");
    }

    #[test]
    fn parse_error_emits_warning_fact() {
        let file = source_file("this is not valid rust {{{{");
        let facts = extract_facts(&file);

        let errors = find_facts_by_rule(&facts, "rust/parse_error");
        assert_eq!(errors.len(), 1);
        match errors[0] {
            Fact::LintFinding {
                severity, evidence, ..
            } => {
                assert_eq!(*severity, Severity::Warning);
                let ev = evidence.as_ref().unwrap();
                assert!(ev["error_message"].is_string());
                assert!(ev["file_sha256"].is_string());
            }
            _ => panic!("expected LintFinding"),
        }
    }

    #[test]
    fn skips_private_items() {
        let file = source_file("fn private_fn() {}\nstruct PrivateStruct;\nenum PrivateEnum { A }");
        let facts = extract_facts(&file);

        assert!(find_facts_by_rule(&facts, "rust/pub_fn").is_empty());
        assert!(find_facts_by_rule(&facts, "rust/pub_struct").is_empty());
        assert!(find_facts_by_rule(&facts, "rust/pub_enum").is_empty());
    }

    #[test]
    fn metamorphic_whitespace_invariance() {
        let compact = source_file("pub fn hello() {}");
        let spaced = RustSourceFile {
            rel_path: "test.rs".to_string(),
            content: "  pub   fn   hello  (  )   {  }  ".to_string(),
            sha256: sha256_hex(b"  pub   fn   hello  (  )   {  }  "),
        };

        let facts_compact = extract_facts(&compact);
        let facts_spaced = extract_facts(&spaced);

        // Both should produce exactly one pub_fn fact with the same evidence
        let pf_compact = find_facts_by_rule(&facts_compact, "rust/pub_fn");
        let pf_spaced = find_facts_by_rule(&facts_spaced, "rust/pub_fn");
        assert_eq!(pf_compact.len(), 1);
        assert_eq!(pf_spaced.len(), 1);

        // Evidence should be identical (name, visibility, etc.)
        let ev_compact = evidence_of(pf_compact[0]);
        let ev_spaced = evidence_of(pf_spaced[0]);
        assert_eq!(ev_compact["name"], ev_spaced["name"]);
        assert_eq!(ev_compact["visibility"], ev_spaced["visibility"]);
        assert_eq!(ev_compact["is_async"], ev_spaced["is_async"]);
        assert_eq!(ev_compact["is_unsafe"], ev_spaced["is_unsafe"]);
        assert_eq!(ev_compact["generic_count"], ev_spaced["generic_count"]);
        // Spans will differ — that's expected and correct
    }
}
