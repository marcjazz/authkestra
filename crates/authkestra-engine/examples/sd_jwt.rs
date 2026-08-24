use authkestra_engine::token::sd_jwt::DisclosableClaim;
use authkestra_engine::TokenManager;
use std::collections::HashMap;

/// This example demonstrates the actual point of SD-JWT: an issuer mints
/// ONE token, and the holder decides -- per verifier, at presentation time
/// -- which of the issuer-vouched claims to reveal. Nothing here needs
/// network I/O, so this runs as a plain `fn main`.
///
/// See `crates/authkestra-engine/src/token/sd_jwt.rs`'s module docs for the
/// full scope, including what this module does NOT implement.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SD-JWT (Selective Disclosure) ===\n");

    // 1. Issuer mints ONE SD-JWT with five selectively-disclosable claims
    //    plus one claim ("account_type") that stays in the clear on every
    //    presentation, regardless of which Disclosures the holder forwards.
    let issuer = TokenManager::new(
        b"sd-jwt-example-secret",
        Some("https://issuer.example".to_string()),
    );

    let mut clear_claims = HashMap::new();
    clear_claims.insert(
        "account_type".to_string(),
        serde_json::Value::String("verified".to_string()),
    );

    println!("1. Issuer mints a single SD-JWT for the holder...");
    let issued = issuer.issue_sd_jwt(
        "user-42".to_string(),
        3600,
        None,
        Some("profile".to_string()),
        vec![
            DisclosableClaim::new("given_name", "Ada"),
            DisclosableClaim::new("family_name", "Lovelace"),
            DisclosableClaim::new("birthdate", "1985-12-10"),
            DisclosableClaim::new("email", "ada@example.com"),
            DisclosableClaim::new("country", "GB"),
        ],
        clear_claims,
    )?;

    println!(
        "   1 JWT ({} bytes) + {} Disclosures -> full compact form is {} bytes.",
        issued.jwt.len(),
        issued.disclosures.len(),
        issued.compact.len(),
    );
    println!("   The issuer never mints a second token for the different verifiers below.\n");

    // Disclosures are returned in the same order as `disclosable_claims`
    // above: [given_name, family_name, birthdate, email, country].
    let birthdate_disclosure = &issued.disclosures[2];
    let email_disclosure = &issued.disclosures[3];
    let country_disclosure = &issued.disclosures[4];

    // 2. Holder -> bar: only needs to prove age, so it reconstructs a
    //    presentation carrying ONLY the birthdate Disclosure, in SD-JWT
    //    compact form (`<jwt>~<disclosure>~`).
    println!("2. Holder presents to a bar, forwarding only `birthdate`...");
    let bar_presentation = format!("{}~{birthdate_disclosure}~", issued.jwt);
    let bar_view = issuer.validate_sd_jwt(&bar_presentation, None)?;
    println!(
        "   Bar's presentation is {} bytes (vs {} bytes for the full compact form).",
        bar_presentation.len(),
        issued.compact.len()
    );
    println!(
        "   Bar sees disclosed_claims = {:?}",
        sorted_keys(&bar_view.disclosed_claims)
    );
    println!(
        "   birthdate = {:?}\n",
        bar_view.disclosed_claims.get("birthdate")
    );

    // 3. Holder -> shipping form: only needs `country`, so it reconstructs a
    //    DIFFERENT presentation from the SAME issued token, carrying only
    //    the country Disclosure this time.
    println!("3. Holder presents to a shipping form, forwarding only `country`...");
    let shipping_presentation = format!("{}~{country_disclosure}~", issued.jwt);
    let shipping_view = issuer.validate_sd_jwt(&shipping_presentation, None)?;
    println!(
        "   Shipping form sees disclosed_claims = {:?}",
        sorted_keys(&shipping_view.disclosed_claims)
    );
    println!(
        "   country = {:?}\n",
        shipping_view.disclosed_claims.get("country")
    );

    // 4. Clear claims are present on EVERY verification, disclosed or not --
    //    selective disclosure only gates the claims the issuer chose to
    //    make disclosable, never the standard/clear ones.
    println!("4. Clear claims are present on every verification, regardless of disclosures:");
    println!(
        "   bar_view.claims.sub                        = {}",
        bar_view.claims.sub
    );
    println!(
        "   bar_view.claims.extra[\"account_type\"]      = {:?}",
        bar_view.claims.extra.get("account_type")
    );
    println!(
        "   shipping_view.claims.extra[\"account_type\"] = {:?}\n",
        shipping_view.claims.extra.get("account_type")
    );

    // 5. Negative demo: a Disclosure tampered with after issuance no longer
    //    hashes to anything in `_sd[]`, so verification of the WHOLE
    //    presentation is rejected -- not just the tampered claim.
    println!("5. Negative demo: a tampered Disclosure is rejected outright...");
    let mut tampered_email = email_disclosure.clone();
    let last_char = tampered_email.pop().expect("disclosure is non-empty");
    tampered_email.push(if last_char == 'A' { 'B' } else { 'A' });
    let tampered_presentation = format!("{}~{tampered_email}~", issued.jwt);
    match issuer.validate_sd_jwt(&tampered_presentation, None) {
        Ok(_) => {
            println!("   Unexpected: the tampered disclosure verified (this would be a bug!).")
        }
        Err(err) => println!("   Rejected as expected: {err}"),
    }

    println!("\nOut of scope for this module (see the sd_jwt.rs module docs):");
    println!("  - Key Binding JWT (KB-JWT) / holder proof-of-possession");
    println!("  - Array-element and recursive/nested Disclosures");
    println!("  - SD-JWT VC (`vc+sd-jwt`) type metadata");

    Ok(())
}

/// Small helper so the printed claim-name sets are in a stable order across
/// runs (`HashMap` iteration order is not deterministic).
fn sorted_keys(map: &HashMap<String, serde_json::Value>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    keys
}
