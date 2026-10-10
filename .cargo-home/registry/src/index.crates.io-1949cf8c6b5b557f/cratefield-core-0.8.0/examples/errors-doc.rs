//! Generates `docs/ERRORS.md` by scanning every `ProblemDef { .. }`
//! literal in the `src/` trees of the workspace's crates under `crates/`
//! (issue #419): core's registry and the modules' own `const ProblemDef`s,
//! which never pass through `problem_registry()`. Run without arguments
//! to write the file, or with `--check` to verify the checked-in copy has
//! no drift (CI fails the run on drift). Either mode fails on a slug
//! defined twice, and on any `ProblemDef` the scanner cannot read — a
//! silently skipped definition is the doc lying again.
//!
//! ```text
//! cargo run -p cratefield-core --example errors-doc          # write
//! cargo run -p cratefield-core --example errors-doc -- --check
//! ```
//!
//! Host-only tooling: the core library itself never touches `std::fs`,
//! and like the CLI's `doctor` this shells out to cargo; it never runs
//! inside a Worker.

use axum::http::StatusCode;
use cratefield_core::problem_registry;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprStruct, Member};

/// One `ProblemDef` literal found in source.
struct Found {
    /// The package that defines it — the doc's Crate column.
    crate_name: String,
    /// Path relative to the workspace root, for error messages.
    file: PathBuf,
    /// The literal's 1-based line, for error messages.
    line: usize,
    slug: String,
    status: u16,
    title: String,
    description: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The workspace members that live under `crates/`: core and the modules.
/// Examples and ventures mount them; they are hosts, not sources of
/// harness slugs.
fn members(root: &Path) -> Vec<(String, PathBuf)> {
    let output =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .current_dir(root)
            .output()
            .expect("cargo metadata runs");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON");
    let crates = root.join("crates");
    let mut out = Vec::new();
    for package in metadata["packages"].as_array().expect("packages array") {
        let manifest = PathBuf::from(package["manifest_path"].as_str().expect("manifest path"));
        if !manifest.starts_with(&crates) {
            continue;
        }
        out.push((
            package["name"].as_str().expect("package name").to_string(),
            manifest
                .parent()
                .expect("manifest has a parent")
                .join("src"),
        ));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Every `.rs` file under `dir`, sorted so runs are reproducible.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every `ProblemDef` literal under `crates/*/src`, and every error the
/// scan hit. Both modes fail while `errors` is non-empty: the doc may be
/// written only from a scan that read every definition.
fn scan(root: &Path) -> (Vec<Found>, Vec<String>) {
    let mut found = Vec::new();
    let mut errors = Vec::new();
    for (name, src) in members(root) {
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        for file in files {
            let source = std::fs::read_to_string(&file)
                .unwrap_or_else(|err| panic!("read {}: {err}", file.display()));
            let rel = file.strip_prefix(root).unwrap_or(&file).to_path_buf();
            let ast = match syn::parse_file(&source) {
                Ok(ast) => ast,
                Err(err) => {
                    errors.push(format!("{}: does not parse: {err}", rel.display()));
                    continue;
                }
            };
            let mut scanner = Scanner {
                crate_name: name.clone(),
                file: rel,
                found: Vec::new(),
                errors: Vec::new(),
            };
            scanner.visit_file(&ast);
            found.append(&mut scanner.found);
            errors.append(&mut scanner.errors);
        }
    }
    (found, errors)
}

/// Walks one file, collecting `ProblemDef { .. }` expressions and never
/// descending into a `#[cfg(test)]` item: definitions the harness never
/// serves are not slugs the doc lists.
struct Scanner {
    crate_name: String,
    file: PathBuf,
    found: Vec<Found>,
    errors: Vec<String>,
}

/// A literal `#[cfg(test)]` — the one `cfg` that makes an item test-only.
/// `not(test)` and `any(test, ..)` items hold non-test code too, so they
/// are scanned like everything else.
fn cfg_test(attr: &syn::Attribute) -> bool {
    let syn::Meta::List(list) = &attr.meta else {
        return false;
    };
    list.path.is_ident("cfg") && list.tokens.to_string() == "test"
}

/// The item kinds whose bodies can hold a struct-literal expression:
/// skip a `#[cfg(test)]` one entirely, descend into everything else, at
/// any nesting depth. A `struct`, `use` or `enum` body cannot contain an
/// expression, and syn never parses a macro invocation's tokens, so
/// there is nothing to visit in the other item kinds.
macro_rules! item_visits {
    ($($visit:ident => $item:ident),* $(,)?) => {$(
        fn $visit(&mut self, item: &syn::$item) {
            if item.attrs.iter().any(cfg_test) {
                return;
            }
            visit::$visit(self, item);
        }
    )*};
}

impl Scanner {
    /// A string-literal field's value. The definitions keep long lines
    /// short with a `\`-newline continuation, which `LitStr::value()`
    /// resolves.
    fn string(&mut self, expr: &Expr, line: usize, field: &str) -> Option<String> {
        let value = match expr {
            Expr::Lit(lit) => match &lit.lit {
                syn::Lit::Str(s) => return Some(s.value()),
                _ => None,
            },
            _ => None,
        };
        if value.is_none() {
            self.errors.push(format!(
                "{}:{line}: `{field}` must be a string literal",
                self.file.display()
            ));
        }
        value
    }
}

impl Visit<'_> for Scanner {
    fn visit_expr_struct(&mut self, expr: &ExprStruct) {
        if expr
            .path
            .segments
            .last()
            .is_none_or(|seg| seg.ident != "ProblemDef")
        {
            visit::visit_expr_struct(self, expr);
            return;
        }
        // A ProblemDef nests no other ProblemDef; read it, do not recurse.
        let line = expr.span().start().line;
        let (mut slug, mut title, mut description, mut status) = (None, None, None, None);
        for field in &expr.fields {
            let Member::Named(name) = &field.member else {
                self.errors.push(format!(
                    "{}:{line}: ProblemDef fields must be named",
                    self.file.display()
                ));
                return;
            };
            match name.to_string().as_str() {
                "slug" => slug = self.string(&field.expr, line, "slug"),
                "title" => title = self.string(&field.expr, line, "title"),
                "description" => description = self.string(&field.expr, line, "description"),
                "status" => match status_code(&field.expr) {
                    Some(code) => status = Some(code),
                    None => self.errors.push(format!(
                        "{}:{line}: `status` must be a `StatusCode::SOME_REASON` path the http crate knows",
                        self.file.display()
                    )),
                },
                // An unknown field leaves one of the four required ones
                // unset — the missing-field error below names the literal.
                _ => {}
            }
        }
        match (slug, title, description, status) {
            (Some(slug), Some(title), Some(description), Some(status)) => {
                self.found.push(Found {
                    crate_name: self.crate_name.clone(),
                    file: self.file.clone(),
                    line,
                    slug,
                    status,
                    title,
                    description,
                });
            }
            _ => self.errors.push(format!(
                "{}:{line}: ProblemDef literal is missing a slug, status, title or description",
                self.file.display()
            )),
        }
    }

    item_visits! {
        visit_item_const => ItemConst,
        visit_item_fn => ItemFn,
        visit_item_impl => ItemImpl,
        visit_item_mod => ItemMod,
        visit_item_static => ItemStatic,
        visit_item_trait => ItemTrait,
    }
}

/// The code behind a `StatusCode::SOME_REASON` path, matched the other
/// way — against every reason the `http` crate names (`from_u16` accepts
/// 100..=599) — so a constant this file never heard of still resolves.
fn status_code(expr: &Expr) -> Option<u16> {
    let Expr::Path(path) = expr else {
        return None;
    };
    let name = path.path.segments.last()?.ident.to_string();
    (100..=599).find(|code| {
        StatusCode::from_u16(*code)
            .ok()
            .and_then(|status| status.canonical_reason())
            .is_some_and(|reason| reason.replace([' ', '-'], "_").to_uppercase() == name)
    })
}

fn markdown(defs: &[Found]) -> String {
    let mut out = String::new();
    out.push_str("# Error taxonomy\n\n");
    out.push_str(
        "Every problem slug the harness can emit, generated by scanning every\n\
         `ProblemDef` in the workspace's crates — core's registry and the\n\
         modules' own — with `cargo run -p cratefield-core --example\n\
         errors-doc`, and checked in CI for drift and for slugs defined\n\
         twice: each slug is defined exactly once, and a module's slugs are\n\
         emitted only where that module is mounted. Responses are RFC 9457\n\
         `application/problem+json` with `instance` = the request id, and\n\
         `type` = `<public_url>/problems/<slug>`: the serving venture's own\n\
         base, from its `Venture::public_url` (`Venture::problem_base`\n\
         overrides it), so every venture names its problems under its own\n\
         domain. A venture with no public URL — and any problem rendered\n\
         outside a venture's context — carries the RFC 9457 §4.2.1 default\n\
         `about:blank` instead of a URI that would name the wrong venture.\n\
         The slug is the stable part to match on; a venture may also serve a\n\
         human-readable page at each `<public_url>/problems/<slug>`.\n\n",
    );
    out.push_str("| Slug | Status | Title | Crate | Description |\n");
    out.push_str("|---|---|---|---|\n");
    for def in defs {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | `{}` | {} |",
            def.slug, def.status, def.title, def.crate_name, def.description
        );
    }
    out
}

fn main() {
    // Canonicalised: `starts_with` compares components, and the unjoined
    // `crates/core/../..` never prefixes the manifest paths cargo emits.
    let root = std::fs::canonicalize(workspace_root()).expect("workspace root resolves");
    let path = root.join("docs/ERRORS.md");
    let (mut defs, mut errors) = scan(&root);

    // Sorted here once: the duplicate check needs slugs adjacent, and the
    // table below lists them in the same order.
    defs.sort_by(|a, b| a.slug.cmp(&b.slug));

    // A slug is the stable `type` URI callers branch on: defined twice,
    // one `type` answers two different problems and neither the caller
    // nor this doc can tell them apart. Fails write and check mode alike.
    for group in defs.chunk_by(|a, b| a.slug == b.slug) {
        if group.len() == 1 {
            continue;
        }
        let at = group
            .iter()
            .map(|def| format!("{}:{}", def.file.display(), def.line))
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "slug `{}` is defined {} times: {at}",
            group[0].slug,
            group.len()
        ));
    }

    // The doc claims core's registry, too: a `Slugs` field left out of
    // `registry()` would sit in this table without being a slug the
    // registry-driven code paths agree to publish.
    let registered: BTreeSet<&str> = problem_registry().iter().map(|def| def.slug).collect();
    let scanned: BTreeSet<&str> = defs
        .iter()
        .filter(|def| def.crate_name == "cratefield-core")
        .map(|def| def.slug.as_str())
        .collect();
    if scanned != registered {
        errors.push(format!(
            "cratefield-core: the slugs scanned from `SLUGS` do not match `problem_registry()` \
             (in SLUGS only: {:?}; in the registry only: {:?})",
            scanned.difference(&registered).collect::<Vec<_>>(),
            registered.difference(&scanned).collect::<Vec<_>>(),
        ));
    }

    if !errors.is_empty() {
        for error in &errors {
            eprintln!("errors-doc: {error}");
        }
        std::process::exit(1);
    }

    let generated = markdown(&defs);
    let check = std::env::args().any(|arg| arg == "--check");

    if check {
        let current = std::fs::read_to_string(&path).unwrap_or_default();
        if current != generated {
            eprintln!(
                "docs/ERRORS.md is stale; regenerate with `cargo run -p cratefield-core \
                 --example errors-doc` and commit it"
            );
            std::process::exit(1);
        }
        println!("docs/ERRORS.md is up to date ({} slugs)", defs.len());
        return;
    }

    std::fs::write(&path, generated).expect("write docs/ERRORS.md");
    println!("wrote {} ({} slugs)", path.display(), defs.len());
}
