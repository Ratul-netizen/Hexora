//! `hexora detectors` — what this build actually checks for.
//!
//! Two questions a tester asks before pointing a tool at somebody's system, which
//! until now had no answer except reading the source:
//!
//! * **What does this look for?** A scanner that will not tell you what it checks is
//!   a scanner whose silence means nothing.
//! * **Which of it sends?** The difference between something safe to run against
//!   production at 3pm and something that is not.
//!
//! The list is assembled from the crates this binary links, not discovered: there is
//! no plugin mechanism, and printing a number that implied one would be worse than
//! printing two rows.

use hexora_types::Result;
use hexora_verify::Registry;

/// The checks this build has.
pub fn registry() -> Registry {
    Registry::new()
        .with(hexora_authz::checks())
        .with(hexora_scan::checks::all().iter().map(|check| check.about()))
}

/// Lists them.
pub fn list(json: bool) -> Result<()> {
    let registry = registry();
    let checks = registry.all();

    if json {
        println!(
            "{}",
            serde_json::json!({
                "detectors": checks
                    .iter()
                    .map(|check| serde_json::json!({
                        "id": check.id.to_string(),
                        "name": check.name,
                        "version": check.version,
                        "about": check.about,
                        "mode": check.mode.as_str(),
                        "sends": check.sends(),
                        "observes": check.observes,
                        "hypothesizes": check.hypothesizes,
                    }))
                    .collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    println!(
        "{:<26} {:<9} {:<8} {:<12} WHAT IT LOOKS FOR",
        "ID", "VERSION", "MODE", "PRODUCES"
    );
    for check in checks {
        println!(
            "{:<26} {:<9} {:<8} {:<12} {}",
            check.id.to_string(),
            check.version,
            check.mode.as_str(),
            produces(check),
            check.about
        );
    }

    println!();
    let sending = registry.sending().count();
    println!("{} check(s); {sending} of them send traffic.", checks.len());
    println!();
    // The two sentences the verification framework exists to make true.
    println!("An observation is a fact about traffic and reaches a report as a lead.");
    println!("A hypothesis is a suspicion, and stays one until an experiment settles it.");
    println!("Neither becomes a finding on its own.");
    println!();
    println!("  hexora scan passive <project>   runs every passive check; sends nothing");
    println!("  hexora authz <project> <id>     runs the authorization checks; sends");
    Ok(())
}

/// What a check can produce, for the registry listing.
fn produces(check: &hexora_types::verify::DetectorInfo) -> &'static str {
    match (check.observes, check.hypothesizes) {
        (true, true) => "obs + hyp",
        (true, false) => "observations",
        (false, true) => "hypotheses",
        // Nothing: a row that would be a lie if it appeared, so it says so.
        (false, false) => "nothing",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_is_not_empty_and_every_check_describes_itself() {
        let registry = registry();
        assert!(!registry.all().is_empty());
        for check in registry.all() {
            assert!(!check.id.0.is_empty());
            assert!(
                !check.about.is_empty(),
                "{} has no description, so the list would not answer the question it \
                 exists to answer",
                check.id
            );
        }
    }

    #[test]
    fn the_authorization_checks_declare_that_they_send() {
        // They replay a captured request as other identities, which is traffic on
        // somebody's system. A registry that said otherwise would be worse than none.
        let registry = registry();
        let sending: Vec<&str> = registry.sending().map(|check| check.id.0).collect();
        assert!(sending.contains(&"authz.cross_identity"), "{sending:?}");
        assert!(sending.contains(&"authz.constructed_object"), "{sending:?}");
    }

    #[test]
    fn every_passive_check_declares_that_it_does_not_send() {
        // The claim `hexora scan passive` rests on, checked against the registry
        // rather than against the documentation.
        let registry = registry();
        for check in hexora_scan::checks::all() {
            let info = check.about();
            let listed = registry
                .find(info.id.0)
                .unwrap_or_else(|| panic!("{} is not in the registry", info.id));
            assert!(
                !listed.sends(),
                "{} is registered as sending, which would make the passive pass a lie",
                info.id
            );
            assert_eq!(listed.mode.as_str(), "passive");
        }
    }

    #[test]
    fn every_check_produces_something() {
        // A check that neither observes nor hypothesises cannot do anything, and a
        // registry row claiming it exists would be the kind of padding this listing
        // is meant to prevent.
        for check in registry().all() {
            assert!(
                check.observes || check.hypothesizes,
                "{} produces nothing",
                check.id
            );
        }
    }

    #[test]
    fn listing_works_in_both_forms() {
        list(false).unwrap();
        list(true).unwrap();
    }
}
