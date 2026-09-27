//! A small, honest `robots.txt` parser (RFC 9309), for CR.c.
//!
//! A crawl respects `robots.txt` by default: a path a site asked crawlers to stay out of
//! is recorded as found, never fetched. This is a courtesy the operator asked for, not a
//! security boundary — `robots.txt` is advisory and a tester can override it loudly — so
//! the parser errs toward *allowing* only when a line is genuinely empty or absent, and
//! toward the site's stated wishes otherwise.
//!
//! What it implements: user-agent group selection (most specific product-token match, else
//! the `*` group), `Allow`/`Disallow` rules with `*` wildcards and a `$` end-anchor, and
//! longest-match resolution with `Allow` winning an equal-length tie, as RFC 9309 §2.2
//! describes. What it does not: crawl-delay, sitemaps, or fetching the file — fetching is
//! the crawler's job, through the scope guard like everything else.

/// One `Allow`/`Disallow` rule from the applicable group.
#[derive(Debug, Clone)]
struct Rule {
    allow: bool,
    pattern: String,
}

/// The rules that apply to one crawler, parsed from a `robots.txt`.
#[derive(Debug, Clone, Default)]
pub struct Robots {
    rules: Vec<Rule>,
}

impl Robots {
    /// An empty policy: everything is allowed. Used when a host has no `robots.txt`
    /// (a 404), or when the fetch failed — absence is not prohibition.
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Parses `body` and keeps only the rules that apply to `user_agent`.
    ///
    /// Group selection follows RFC 9309: among the groups whose product token is a
    /// case-insensitive prefix of `user_agent`, the longest token wins; if none match, the
    /// `*` group is used; if there is no `*` group either, nothing is restricted.
    pub fn parse(body: &[u8], user_agent: &str) -> Self {
        let text = String::from_utf8_lossy(body);
        let ua = user_agent.to_ascii_lowercase();

        // Groups, in file order: each is (user-agent tokens, rules). A run of consecutive
        // `User-agent:` lines shares the rules that follow, until the next `User-agent:`
        // that comes *after* a rule starts a new group.
        let mut groups: Vec<(Vec<String>, Vec<Rule>)> = Vec::new();
        let mut expecting_agents = false;

        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let field = field.trim().to_ascii_lowercase();
            let value = value.trim();

            match field.as_str() {
                "user-agent" => {
                    if !expecting_agents || groups.is_empty() {
                        groups.push((Vec::new(), Vec::new()));
                    }
                    if let Some((agents, _)) = groups.last_mut() {
                        agents.push(value.to_ascii_lowercase());
                    }
                    expecting_agents = true;
                }
                "allow" | "disallow" => {
                    if groups.is_empty() {
                        // A rule before any `User-agent`: ignore it, per spec.
                        continue;
                    }
                    if let Some((_, rules)) = groups.last_mut() {
                        rules.push(Rule {
                            allow: field == "allow",
                            pattern: value.to_string(),
                        });
                    }
                    expecting_agents = false;
                }
                _ => {}
            }
        }

        // Pick the group: longest specific token that is a prefix of our UA, else `*`.
        let mut best_specific: Option<(usize, &Vec<Rule>)> = None;
        let mut star: Option<&Vec<Rule>> = None;
        for (agents, rules) in &groups {
            for token in agents {
                if token == "*" {
                    star = Some(rules);
                } else if ua.starts_with(token.as_str()) {
                    let better = best_specific.is_none_or(|(len, _)| token.len() > len);
                    if better {
                        best_specific = Some((token.len(), rules));
                    }
                }
            }
        }

        let chosen = best_specific.map(|(_, r)| r).or(star);
        Self {
            rules: chosen.cloned().unwrap_or_default(),
        }
    }

    /// Whether `path` may be fetched. The longest matching rule wins; on an equal-length
    /// tie `Allow` wins; with no matching rule the path is allowed.
    pub fn allows(&self, path: &str) -> bool {
        let mut best: Option<(usize, bool)> = None; // (pattern length, allow)
        for rule in &self.rules {
            // An empty `Disallow:` allows everything and matches nothing specific.
            if rule.pattern.is_empty() {
                continue;
            }
            if pattern_matches(&rule.pattern, path) {
                let len = rule.pattern.len();
                let takes = match best {
                    None => true,
                    Some((best_len, best_allow)) => {
                        len > best_len || (len == best_len && rule.allow && !best_allow)
                    }
                };
                if takes {
                    best = Some((len, rule.allow));
                }
            }
        }
        best.is_none_or(|(_, allow)| allow)
    }
}

/// Matches a robots path pattern against `path`, anchored at the start, supporting `*`
/// (any run of characters) and a trailing `$` (end-of-path anchor).
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let (pattern, anchored_end) = match pattern.strip_suffix('$') {
        Some(rest) => (rest, true),
        None => (pattern, false),
    };

    // Segments between the `*` wildcards, in order. The first must sit at position 0; each
    // later one must appear after the previous match.
    let segments: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            continue;
        }
        if i == 0 {
            // First segment is anchored to the start of the path.
            if !path[pos..].starts_with(segment) {
                return false;
            }
            pos += segment.len();
        } else {
            match path[pos..].find(segment) {
                Some(found) => pos += found + segment.len(),
                None => return false,
            }
        }
    }

    if anchored_end {
        // The pattern ended with `$`: the last thing matched must reach the path's end,
        // unless the pattern ended with `*` (an empty trailing segment lets it run on).
        let ends_with_wildcard = segments.last() == Some(&"");
        return ends_with_wildcard || pos == path.len();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn robots(body: &str) -> Robots {
        Robots::parse(body.as_bytes(), "Nullhawk")
    }

    #[test]
    fn no_robots_allows_everything() {
        assert!(Robots::allow_all().allows("/anything"));
        assert!(robots("").allows("/anything"));
    }

    #[test]
    fn a_disallow_prefix_blocks_the_subtree() {
        let r = robots("User-agent: *\nDisallow: /private");
        assert!(!r.allows("/private"));
        assert!(!r.allows("/private/x"));
        assert!(r.allows("/public"));
    }

    #[test]
    fn a_longer_allow_overrides_a_disallow() {
        let r = robots("User-agent: *\nDisallow: /private\nAllow: /private/ok");
        assert!(!r.allows("/private/secret"));
        assert!(r.allows("/private/ok"));
    }

    #[test]
    fn disallow_root_blocks_everything_and_empty_disallow_allows() {
        assert!(!robots("User-agent: *\nDisallow: /").allows("/anything"));
        assert!(robots("User-agent: *\nDisallow:").allows("/anything"));
    }

    #[test]
    fn a_specific_group_beats_the_star_group() {
        let r = robots("User-agent: *\nDisallow: /\n\nUser-agent: Nullhawk\nDisallow: /admin");
        // The Nullhawk group applies, so only /admin is blocked, not everything.
        assert!(r.allows("/public"));
        assert!(!r.allows("/admin"));
    }

    #[test]
    fn wildcards_and_end_anchor() {
        let r = robots("User-agent: *\nDisallow: /*.pdf$");
        assert!(!r.allows("/docs/report.pdf"));
        assert!(r.allows("/docs/report.pdf?v=1"));
        assert!(r.allows("/docs/reader"));
    }
}
