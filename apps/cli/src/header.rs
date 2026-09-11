//! `hexora header` — the headers every request must carry.
//!
//! A bug bounty programme routinely requires a researcher to identify their traffic:
//!
//! ```text
//! Add the following headers to requests: X-HackerOne-Research: [H1 username]
//! Reports resulting in testing without headers can result in the forfeiture of
//! the eligible bounty.
//! ```
//!
//! This is the opposite of hiding. A programme that cannot tell a researcher's requests
//! from an attacker's is entitled to treat them the same way — to block the address, to
//! page somebody at two in the morning, or to hand the logs to a lawyer. The header is
//! what makes automated testing *safe to run* against somebody else's production
//! system, and it is the reason it belongs on the project rather than on an identity:
//! the requirement covers every request, and an identity covers authenticated replays
//! only.

use std::path::Path;

use hexora_types::http::Header;
use hexora_types::{HexoraError, Result};

/// Prints the headers put on every request.
pub fn list(path: &Path, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    let headers = project.settings().attached_headers()?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "headers": headers
                    .iter()
                    .map(|h| serde_json::json!({
                        "name": h.name,
                        "value": h.value_lossy(),
                    }))
                    .collect::<Vec<_>>(),
            })
        );
        return Ok(());
    }

    if headers.is_empty() {
        println!("No headers are attached to this project's requests.");
        println!();
        println!("A bug bounty programme usually requires one so it can tell your");
        println!("traffic from an attacker's:");
        println!();
        println!("  hexora header add <project> \"X-HackerOne-Research: <username>\"");
        return Ok(());
    }

    println!("On every request Hexora sends:");
    for header in &headers {
        println!("  {}: {}", header.name, header.value_lossy());
    }
    println!();
    println!("Not on a raw send — those are byte-exact, so put it in the bytes there.");
    Ok(())
}

/// Adds a header, replacing any with the same name.
pub fn add(path: &Path, header: &str, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    let parsed = parse(header)?;

    let mut headers = project.settings().attached_headers()?;
    let replaced = headers
        .iter()
        .any(|existing| existing.name.eq_ignore_ascii_case(&parsed.name));
    headers.retain(|existing| !existing.name.eq_ignore_ascii_case(&parsed.name));
    headers.push(parsed.clone());
    project.settings().set_attached_headers(&headers)?;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "name": parsed.name,
                "value": parsed.value_lossy(),
                "replaced": replaced,
                "attached": headers.len(),
            })
        );
        return Ok(());
    }

    println!(
        "{} {}: {}",
        if replaced { "Replaced" } else { "Attached" },
        parsed.name,
        parsed.value_lossy()
    );
    println!();
    println!("Every structured request this project sends will carry it: the repeater,");
    println!("the scanner's probes, the intruder's payloads, and every replay. A raw");
    println!("send will not — those are byte-exact, so put it in the bytes there.");
    Ok(())
}

/// Stops sending a header.
pub fn remove(path: &Path, name: &str, json: bool) -> Result<()> {
    let project = crate::open_project(path)?;
    let mut headers = project.settings().attached_headers()?;
    let before = headers.len();
    headers.retain(|existing| !existing.name.eq_ignore_ascii_case(name));
    let removed = before - headers.len();
    project.settings().set_attached_headers(&headers)?;

    if json {
        println!("{}", serde_json::json!({ "removed": removed }));
        return Ok(());
    }
    match removed {
        0 => println!("No header named {name} was attached."),
        _ => println!("Removed {name}. Requests will no longer carry it."),
    }
    Ok(())
}

/// Reads `Name: value`.
fn parse(header: &str) -> Result<Header> {
    let (name, value) = header.split_once(':').ok_or_else(|| {
        HexoraError::invalid_input(
            "header",
            format!("`{header}` is not a header — write it as `Name: value`"),
        )
    })?;

    // Spaces and tabs only. `str::trim` would strip a CR or LF as well, which is
    // the one thing that must not pass quietly: `X-A\r\n: b` would come back
    // looking like a perfectly ordinary header called `X-A`.
    let name = name.trim_matches([' ', '\t']);
    let value = value.trim_matches([' ', '\t']);
    if name.is_empty() {
        return Err(HexoraError::invalid_input(
            "header",
            "a header needs a name",
        ));
    }
    // A value carrying CR or LF would split every request it is spliced into, and this
    // one is spliced into all of them.
    if name.chars().chain(value.chars()).any(char::is_control) {
        return Err(HexoraError::invalid_input(
            "header",
            "a header cannot contain control characters: a value carrying CR or LF \
             would split every request it is attached to",
        ));
    }
    if name.chars().any(|c| c.is_whitespace() || c == ':') {
        return Err(HexoraError::invalid_input(
            "header",
            format!("`{name}` is not a valid header name"),
        ));
    }

    Ok(Header::new(name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_is_read_as_name_and_value() {
        let header = parse("X-HackerOne-Research: wahid_ratul").unwrap();
        assert_eq!(header.name, "X-HackerOne-Research");
        assert_eq!(header.value_lossy(), "wahid_ratul");
    }

    #[test]
    fn a_value_containing_a_colon_keeps_it() {
        let header = parse("X-Trace: a:b:c").unwrap();
        assert_eq!(header.value_lossy(), "a:b:c");
    }

    #[test]
    fn a_header_that_would_split_a_request_is_refused() {
        // This value goes onto every request the project sends. A CR in it would split
        // all of them.
        for bad in [
            "X-A: b\rX-Injected: 1",
            "X-A: b\nX-Injected: 1",
            "X-A\r\n: b",
            "X-A: b\0c",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn something_that_is_not_a_header_says_so() {
        assert!(parse("no-colon-here").is_err());
        assert!(parse(": value").is_err());
        assert!(parse("has space: value").is_err());
    }
}
