//! `full` must name every capability feature the facade has.
//!
//! A `full` that quietly omits things is worse than no `full` at all: the
//! caller who picks it has explicitly said "don't make me choose", and gets a
//! build missing passkeys or a storage backend with no indication anything is
//! absent. That is not hypothetical — between #369 adding twelve features to
//! the facade and this test being written, `full` named none of them, so it
//! delivered 7 of 19 while claiming to be complete.
//!
//! Discipline demonstrably does not hold this invariant, so this asserts it.
//! The manifest is read at compile time from the facade crate itself, which
//! means a new feature added without updating `full` fails here rather than
//! reaching a release.

/// The facade's own manifest, parsed below.
const FACADE_MANIFEST: &str = include_str!("../../authkestra/Cargo.toml");

/// Features that are deliberately not capabilities and so are not expected in
/// `full`:
///
/// - `default` and `full` themselves.
/// - The `rustls-*` backends: exactly one is meant to be active, and which one
///   is a deployment choice (C toolchain vs pure Rust, `cargo-deny` policy),
///   not a capability to switch on. `default` picks one; naming both in `full`
///   would enable a combination nothing wants.
const NOT_CAPABILITIES: &[&str] = &["default", "full", "rustls-aws-lc-rs", "rustls-no-provider"];

/// Collects the feature names declared in `[features]`, and the entries `full`
/// itself lists.
fn parse_features(manifest: &str) -> (Vec<String>, Vec<String>) {
    let mut declared = Vec::new();
    let mut in_full = Vec::new();

    let features_section = manifest
        .split_once("\n[features]")
        .expect("the facade manifest must have a [features] section")
        .1;
    // Stop at the next top-level table, so [dependencies] and friends don't
    // get scanned for `name = [` lines.
    let features_section = features_section
        .split("\n[")
        .next()
        .expect("split always yields at least one element");

    let mut collecting_full = false;
    for line in features_section.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if collecting_full {
            if trimmed.starts_with(']') {
                collecting_full = false;
            } else if let Some(name) = trimmed.trim_end_matches(',').strip_prefix('"') {
                in_full.push(name.trim_end_matches('"').to_string());
            }
            continue;
        }

        let Some((name, rest)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            continue;
        }
        declared.push(name.to_string());

        if name == "full" {
            let rest = rest.trim();
            if rest == "[" {
                // Multi-line form.
                collecting_full = true;
            } else {
                // Single-line form: full = ["a", "b"].
                for chunk in rest
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                {
                    let chunk = chunk.trim().trim_matches('"');
                    if !chunk.is_empty() {
                        in_full.push(chunk.to_string());
                    }
                }
            }
        }
    }

    (declared, in_full)
}

#[test]
fn full_names_every_capability_feature() {
    let (declared, in_full) = parse_features(FACADE_MANIFEST);

    assert!(
        declared.len() > 10,
        "parser found only {} features — it has probably stopped matching the \
         manifest's shape, which would make this test vacuous. Found: {declared:?}",
        declared.len()
    );
    assert!(
        in_full.contains(&"engine".to_string()),
        "parser did not pick up `full`'s entries; found {in_full:?}"
    );

    let expected: Vec<&String> = declared
        .iter()
        .filter(|f| !NOT_CAPABILITIES.contains(&f.as_str()))
        .collect();

    let missing: Vec<&&String> = expected.iter().filter(|f| !in_full.contains(f)).collect();

    assert!(
        missing.is_empty(),
        "`full` does not name every capability feature. Missing: {missing:?}.\n\
         Either add them to `full` in crates/authkestra/Cargo.toml, or — if one \
         genuinely is not a capability (a backend *choice* like the rustls \
         features) — add it to NOT_CAPABILITIES here with the reason."
    );
}

#[test]
fn full_names_nothing_that_does_not_exist() {
    let (declared, in_full) = parse_features(FACADE_MANIFEST);

    let unknown: Vec<&String> = in_full.iter().filter(|f| !declared.contains(f)).collect();

    assert!(
        unknown.is_empty(),
        "`full` names features the facade does not declare: {unknown:?}. \
         A removed feature left behind in `full` fails the build for anyone \
         enabling it."
    );
}
