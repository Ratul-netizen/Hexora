//! `nullhawk matchreplace` — rules that rewrite proxied traffic.
//!
//! Burp and Caido's match-and-replace, kept as an ordered list on the project so it is part of
//! the engagement record. Rules apply only to in-scope hosts (see `core/proxy/src/rewrite.rs`),
//! and the proxy says how many are active when it starts.
//!
//! A rule is added, removed or toggled by a unique name; the proxy reads the list when it runs.

use std::path::Path;

use nullhawk_types::matchreplace::{MatchReplaceRule, RuleTarget};
use nullhawk_types::{NullhawkError, Result};

/// Prints the project's match-and-replace rules, in the order they apply.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let rules = crate::open_project(project)?
        .settings()
        .match_replace_rules()?;

    if json {
        println!("{}", serde_json::to_string(&rules).unwrap_or_default());
        return Ok(());
    }

    if rules.is_empty() {
        println!("No match-and-replace rules. Add one with `nullhawk matchreplace add`.");
        return Ok(());
    }

    println!("Match-and-replace rules (applied in order, to in-scope traffic):");
    for (index, rule) in rules.iter().enumerate() {
        println!("  {}. {}", index + 1, rule.summary());
    }
    Ok(())
}

/// Options for adding a rule.
pub struct AddArgs<'a> {
    pub project: &'a Path,
    pub name: &'a str,
    pub target: &'a str,
    pub regex: bool,
    pub pattern: &'a str,
    pub replacement: &'a str,
    pub disabled: bool,
    pub json: bool,
}

/// Adds a rule to the end of the list.
pub fn add(args: AddArgs<'_>) -> Result<()> {
    let name = args.name.trim();
    if name.is_empty() {
        return Err(NullhawkError::invalid_input(
            "--name",
            "a rule needs a name",
        ));
    }
    let target = RuleTarget::parse(args.target).ok_or_else(|| {
        NullhawkError::invalid_input(
            "--target",
            format!(
                "{:?} is not a target. Use one of: {}",
                args.target,
                RuleTarget::spellings()
            ),
        )
    })?;

    // A non-header target with an empty pattern has nothing to match. On a header target an
    // empty pattern is the "add this header" form, and the replacement must be `Name: value`.
    if args.pattern.is_empty() {
        if target.is_header() {
            if !args.replacement.contains(':') {
                return Err(NullhawkError::invalid_input(
                    "--replace",
                    "an empty pattern on a header target adds a header, so the replacement \
                     must be `Name: value`",
                ));
            }
        } else {
            return Err(NullhawkError::invalid_input(
                "--match",
                "give a pattern to match; only header targets accept an empty pattern (to add \
                 a header)",
            ));
        }
    }

    let settings = crate::open_project(args.project)?.settings();
    let mut rules = settings.match_replace_rules()?;
    if rules.iter().any(|r| r.name == name) {
        return Err(NullhawkError::invalid_input(
            "--name",
            format!("a rule named {name:?} already exists; remove it first or pick another name"),
        ));
    }

    let mut rule = MatchReplaceRule::new(
        name,
        target,
        args.regex,
        args.pattern.to_string(),
        args.replacement.to_string(),
    );
    rule.enabled = !args.disabled;

    // Compile the whole set so an invalid regex is refused here, not when the proxy runs.
    let mut candidate = rules.clone();
    candidate.push(rule.clone());
    nullhawk_proxy::Rewriter::compile(&candidate)
        .map_err(|why| NullhawkError::invalid_input("--match", why))?;

    rules.push(rule.clone());
    settings.set_match_replace_rules(&rules)?;

    if args.json {
        println!("{}", serde_json::to_string(&rule).unwrap_or_default());
    } else {
        println!("Added rule: {}", rule.summary());
        println!("It applies to in-scope traffic when the proxy runs.");
    }
    Ok(())
}

/// Removes a rule by name.
pub fn remove(project: &Path, name: &str, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut rules = settings.match_replace_rules()?;
    let before = rules.len();
    rules.retain(|r| r.name != name);
    if rules.len() == before {
        return Err(NullhawkError::not_found(
            "match-replace rule",
            name.to_string(),
        ));
    }
    settings.set_match_replace_rules(&rules)?;

    if json {
        println!("{}", serde_json::json!({ "removed": name }));
    } else {
        println!("Removed rule {name:?}.");
    }
    Ok(())
}

/// Enables or disables a rule by name, keeping it in place.
pub fn set_enabled(project: &Path, name: &str, enabled: bool, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut rules = settings.match_replace_rules()?;
    let rule = rules
        .iter_mut()
        .find(|r| r.name == name)
        .ok_or_else(|| NullhawkError::not_found("match-replace rule", name.to_string()))?;
    rule.enabled = enabled;
    let summary = rule.summary();
    settings.set_match_replace_rules(&rules)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "name": name, "enabled": enabled })
        );
    } else {
        println!(
            "{} rule {name:?}: {summary}",
            if enabled { "Enabled" } else { "Disabled" }
        );
    }
    Ok(())
}
