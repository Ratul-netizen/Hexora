//! `hexora scope` — what this engagement is authorized to touch.
//!
//! Scope is not a filter for tidiness. It is the control that decides whether an
//! automated subsystem may send anything at all: the guard refuses automated traffic
//! to hosts nobody has declared (`core/engine/src/guard.rs`), which is why a fresh
//! project cannot run an authorization matrix until somebody says what is in bounds.
//!
//! Adding a host is therefore printed back in full, every time. A tester who widens
//! scope by a keystroke should see exactly what they widened it to.

use std::path::Path;

use hexora_types::scope::{PathMatch, SchemeMatch, ScopeRule};
use hexora_types::{HexoraError, Result};

/// Prints the project's scope.
pub fn list(project: &Path, json: bool) -> Result<()> {
    let scope = crate::open_project(project)?.settings().scope()?;

    if json {
        println!("{}", serde_json::to_string(&scope).unwrap_or_default());
        return Ok(());
    }

    if scope.include.is_empty() {
        println!("Scope is empty. No automated component will send any traffic.");
        println!("Add an authorized host with `hexora scope add <host>`.");
        return Ok(());
    }

    println!("In scope:");
    for rule in &scope.include {
        println!("  {}", describe(rule));
    }
    if !scope.exclude.is_empty() {
        println!("Excluded (these win):");
        for rule in &scope.exclude {
            println!("  {}", describe(rule));
        }
    }
    Ok(())
}

/// Adds an inclusion or exclusion rule.
pub fn add(
    project: &Path,
    host: &str,
    path_prefix: Option<&str>,
    exclude: bool,
    json: bool,
) -> Result<()> {
    if host.trim().is_empty() {
        return Err(HexoraError::invalid_input("host", "host cannot be empty"));
    }

    let settings = crate::open_project(project)?.settings();
    let mut scope = settings.scope()?;
    let rule = ScopeRule {
        host: host.to_string(),
        ports: Vec::new(),
        scheme: SchemeMatch::Any,
        path: match path_prefix {
            None => PathMatch::Any,
            Some(prefix) => PathMatch::Prefix {
                value: prefix.to_string(),
            },
        },
    };

    let target = if exclude {
        &mut scope.exclude
    } else {
        &mut scope.include
    };
    if target.contains(&rule) {
        return Err(HexoraError::invalid_input(
            "host",
            format!("{host} is already in the project scope"),
        ));
    }
    target.push(rule.clone());
    settings.set_scope(&scope)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "added": describe(&rule),
                "list": if exclude { "exclude" } else { "include" },
            })
        );
    } else if exclude {
        println!(
            "Excluded {}. Exclusions win over inclusions.",
            describe(&rule)
        );
    } else {
        println!("In scope: {}", describe(&rule));
        println!("Automated components may now send traffic there.");
    }
    Ok(())
}

/// Removes every rule for a host, from both lists.
pub fn remove(project: &Path, host: &str, json: bool) -> Result<()> {
    let settings = crate::open_project(project)?.settings();
    let mut scope = settings.scope()?;

    let before = scope.include.len() + scope.exclude.len();
    scope.include.retain(|rule| rule.host != host);
    scope.exclude.retain(|rule| rule.host != host);
    let removed = before - (scope.include.len() + scope.exclude.len());

    if removed == 0 {
        return Err(HexoraError::not_found("scope rule", host.to_string()));
    }
    settings.set_scope(&scope)?;

    if json {
        println!(
            "{}",
            serde_json::json!({ "removed": removed, "host": host })
        );
    } else {
        println!("Removed {removed} rule(s) for {host}.");
    }
    Ok(())
}

/// One rule, as a line a tester can read back.
fn describe(rule: &ScopeRule) -> String {
    let scheme = match rule.scheme {
        SchemeMatch::Any => "",
        SchemeMatch::HttpOnly => "http://",
        SchemeMatch::HttpsOnly => "https://",
    };
    let path = match &rule.path {
        PathMatch::Any => String::new(),
        PathMatch::Prefix { value } => format!("{value}*"),
        PathMatch::Exact { value } => value.clone(),
    };
    let ports = if rule.ports.is_empty() {
        String::new()
    } else {
        format!(
            ":{}",
            rule.ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    format!("{scheme}{}{ports}{path}", rule.host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_rule_reads_back_as_the_host() {
        assert_eq!(describe(&ScopeRule::host("example.com")), "example.com");
    }

    #[test]
    fn a_prefix_rule_shows_the_prefix_it_covers() {
        let rule = ScopeRule {
            host: "example.com".into(),
            ports: vec![8443],
            scheme: SchemeMatch::HttpsOnly,
            path: PathMatch::Prefix {
                value: "/api".into(),
            },
        };
        assert_eq!(describe(&rule), "https://example.com:8443/api*");
    }
}
