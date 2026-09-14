//! `full` must name every capability feature the facade has.
//!
//! A `full` that quietly omits things is worse than no `full` at all: the
//! caller who picks it has explicitly said "don't make me choose", and gets a
//! build missing passkeys or the OP server with no indication anything is
//! absent. That is not hypothetical — between #369 adding twelve features to
//! the facade and this test being written, `full` named none of them, so it
//! delivered 7 of 19 while claiming to be complete.
//!
//! Omissions are allowed, but only *declared* ones: [`EXCLUDED_FROM_FULL`]
//! carries the storage backends and the reason they are left to the
//! application. The distinction this file enforces is between a decision and
//! a lapse, not between complete and incomplete.
//!
//! Discipline demonstrably does not hold this invariant, so this asserts it.
//! The manifest is read at compile time from the facade crate itself, which
//! means a new feature added without updating `full` fails here rather than
//! reaching a release.

/// The facade's own manifest, parsed below.
const FACADE_MANIFEST: &str = include_str!("../../authkestra/Cargo.toml");

/// Not capabilities at all, so not candidates for `full`: the two aggregate
/// features themselves, and the TLS backend, of which exactly one is meant to
/// be active — which one is a deployment choice (C toolchain vs pure Rust,
/// `cargo-deny` policy), and `default` makes it. Naming both in `full` would
/// enable a combination nothing wants.
const NOT_CAPABILITIES: &[&str] = &["default", "full", "rustls-aws-lc-rs", "rustls-no-provider"];

/// Capabilities that `full` deliberately does **not** enable.
///
/// The storage backends. An application runs exactly one store, so pulling a
/// Redis client and three SQL drivers into every `full` build would cost
/// compile time, binary size and audit surface for four things that go unused.
/// `full` means "every way of authenticating"; the store is named alongside it
/// (`features = ["full", "sql-postgres"]`).
///
/// This list is the reason the exclusion is a decision rather than drift —
/// which is the whole failure this test exists to prevent. Anything added here
/// needs a reason written next to it, and the test below refuses an entry that
/// is silently *also* in `full`, so the two cannot disagree.
const EXCLUDED_FROM_FULL: &[&str] = &["memory", "redis", "sql-postgres", "sql-mysql", "sql-sqlite"];

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
        .filter(|f| !EXCLUDED_FROM_FULL.contains(&f.as_str()))
        .collect();

    let missing: Vec<&&String> = expected.iter().filter(|f| !in_full.contains(f)).collect();

    assert!(
        missing.is_empty(),
        "`full` does not name every capability feature. Missing: {missing:?}.\n\
         Either add them to `full` in crates/authkestra/Cargo.toml, or — if one \
         is deliberately left out — add it to EXCLUDED_FROM_FULL here *with the \
         reason*, so the next person reads a decision instead of guessing \
         whether it was an oversight."
    );
}

/// The exclusion list and `full` must not contradict each other. An entry
/// claiming a feature is deliberately excluded, while `full` enables it
/// anyway, is worse than either choice on its own: the comment explaining the
/// exclusion becomes documentation of something that isn't true.
#[test]
fn nothing_is_both_excluded_and_included() {
    let (_declared, in_full) = parse_features(FACADE_MANIFEST);

    let contradictory: Vec<&&str> = EXCLUDED_FROM_FULL
        .iter()
        .filter(|f| in_full.contains(&f.to_string()))
        .collect();

    assert!(
        contradictory.is_empty(),
        "these are listed as deliberately excluded from `full`, but `full` \
         enables them: {contradictory:?}. Remove them from one place or the other."
    );
}

/// A feature that no longer exists must not linger in the exclusion list
/// either — a stale entry there silently stops `full` being checked for a
/// feature that may since have been re-added under the same name.
#[test]
fn the_exclusion_list_has_no_stale_entries() {
    let (declared, _in_full) = parse_features(FACADE_MANIFEST);

    let stale: Vec<&&str> = EXCLUDED_FROM_FULL
        .iter()
        .filter(|f| !declared.contains(&f.to_string()))
        .collect();

    assert!(
        stale.is_empty(),
        "EXCLUDED_FROM_FULL names features the facade no longer declares: \
         {stale:?}. Drop them, so the list keeps meaning what it says."
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
