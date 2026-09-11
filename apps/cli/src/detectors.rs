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
    Registry::new().with(hexora_authz::checks())
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
                        "version": check.version,
                        "about": check.about,
                        "sends": check.sends,
                    }))
                    .collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    println!(
        "{:<28} {:>7}  {:<6} WHAT IT LOOKS FOR",
        "ID", "VERSION", "SENDS"
    );
    for check in checks {
        println!(
            "{:<28} {:>7}  {:<6} {}",
            check.id.to_string(),
            check.version,
            if check.sends { "yes" } else { "no" },
            check.about
        );
    }

    println!();
    println!("{} check(s).", checks.len());
    println!();
    // The sentence the whole verification framework exists to make true.
    println!("A check raises a hypothesis. Only a verification turns one into a finding,");
    println!("and a hypothesis nothing supported is not recorded at all.");
    println!();
    println!("The scanner is not built yet: these are the checks the authorization");
    println!("subsystem runs, and `hexora authz` is what runs them.");
    Ok(())
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
    fn listing_works_in_both_forms() {
        list(false).unwrap();
        list(true).unwrap();
    }
}
