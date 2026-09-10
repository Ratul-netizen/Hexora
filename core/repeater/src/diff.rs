//! Comparing two responses.
//!
//! The repeater's real question is never "what did the server say?" — it is "what
//! changed when I changed that?". A tester sends a request, edits one parameter, sends
//! it again, and the useful output is the difference between the two responses.
//!
//! # Why the summary comes before the diff
//!
//! Responses to a security test are usually near-identical: the same page, with a CSRF
//! token, a timestamp and a session id that differ every time. A raw line diff of that
//! is mostly noise. So [`ResponseDiff`] answers the cheap structural questions first —
//! did the status change, did headers appear or vanish, did the length move — and only
//! then offers line-level detail.
//!
//! [`ResponseDiff::is_interesting`] exists for the same reason: a fuzzer that renders
//! 5 000 diffs needs something to sort by.

use hexora_types::http::{Headers, HttpResponse};

/// What changed between two responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseDiff {
    /// Status codes, when they differ.
    pub status: Option<(u16, u16)>,
    /// Headers present in both but with different values.
    pub changed_headers: Vec<HeaderChange>,
    /// Headers only in the second response.
    pub added_headers: Vec<String>,
    /// Headers only in the first response.
    pub removed_headers: Vec<String>,
    /// Body lengths, when they differ.
    pub body_length: Option<(usize, usize)>,
    /// Whether the bodies are byte-identical.
    pub bodies_identical: bool,
    /// Byte offset of the first difference, when the bodies differ.
    pub first_difference_at: Option<usize>,
    /// Round-trip times in milliseconds.
    pub timing: (u128, u128),
}

/// One header whose value changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderChange {
    /// The field name, as it appeared in the first response.
    pub name: String,
    /// The value before.
    pub before: String,
    /// The value after.
    pub after: String,
}

/// A round-trip difference at or above this many milliseconds is treated as signal
/// rather than jitter.
///
/// Any threshold here is a judgement call. Half a second is chosen because ordinary
/// network and server variance sits well below it, while the payloads used in
/// time-based blind injection (`SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY`) sit well
/// above — and because a response that is byte-identical but seconds slower is the
/// *only* signal such a test produces. Calling that pair "identical" would hide the
/// finding completely, which is the one outcome worth engineering against.
const TIMING_SIGNIFICANT_MS: u128 = 500;

/// Headers whose values differ on every response and mean nothing on their own.
///
/// Not hidden — [`ResponseDiff::changed_headers`] still lists them — but excluded from
/// [`ResponseDiff::is_interesting`], because a diff that is always "interesting" tells
/// a tester nothing.
const NOISY_HEADERS: &[&str] = &[
    "date",
    "expires",
    "age",
    "set-cookie",
    "etag",
    "last-modified",
    "x-request-id",
    "x-trace-id",
    "x-amz-cf-id",
    "cf-ray",
    "x-served-by",
    "report-to",
    "nel",
];

impl ResponseDiff {
    /// Compares two responses and their round-trip times.
    pub fn compare(before: &HttpResponse, after: &HttpResponse, timing: (u128, u128)) -> Self {
        let mut changed = Vec::new();
        let mut removed = Vec::new();

        for header in before.headers.iter() {
            let name = header.name.to_ascii_lowercase();
            match after.headers.get(&name) {
                None => removed.push(header.name.clone()),
                Some(other) => {
                    let (b, a) = (header.value_lossy(), other.value_lossy());
                    if b != a {
                        changed.push(HeaderChange {
                            name: header.name.clone(),
                            before: b.into_owned(),
                            after: a.into_owned(),
                        });
                    }
                }
            }
        }

        let added = after
            .headers
            .iter()
            .filter(|h| before.headers.get(&h.name).is_none())
            .map(|h| h.name.clone())
            .collect();

        let bodies_identical = before.body == after.body;

        Self {
            status: (before.status != after.status).then_some((before.status, after.status)),
            changed_headers: dedupe_changes(changed, &before.headers),
            added_headers: added,
            removed_headers: removed,
            body_length: (before.body.len() != after.body.len())
                .then_some((before.body.len(), after.body.len())),
            bodies_identical,
            first_difference_at: (!bodies_identical)
                .then(|| first_difference(&before.body, &after.body))
                .flatten(),
            timing,
        }
    }

    /// Whether the two messages are the same.
    ///
    /// About the message only — two identical responses can still differ by seconds,
    /// which [`Self::timing_delta_ms`] reports and [`Self::summary`] always shows.
    pub fn is_identical(&self) -> bool {
        self.status.is_none()
            && self.changed_headers.is_empty()
            && self.added_headers.is_empty()
            && self.removed_headers.is_empty()
            && self.bodies_identical
    }

    /// How much longer the second response took, in milliseconds. Negative if faster.
    pub fn timing_delta_ms(&self) -> i128 {
        self.timing.1 as i128 - self.timing.0 as i128
    }

    /// Whether the round trip moved enough to be signal rather than jitter.
    pub fn timing_is_significant(&self) -> bool {
        self.timing_delta_ms().unsigned_abs() >= TIMING_SIGNIFICANT_MS
    }

    /// Whether the difference is worth a tester's attention.
    ///
    /// A changed status, a changed body, a header appearing or disappearing, or a
    /// materially different round-trip time all count. A `Date` that moved on does
    /// not — see [`NOISY_HEADERS`].
    pub fn is_interesting(&self) -> bool {
        if self.status.is_some() || !self.bodies_identical {
            return true;
        }
        if !self.added_headers.is_empty() || !self.removed_headers.is_empty() {
            return true;
        }
        // Before the header check, because a byte-identical response that arrived
        // five seconds later is a finding, not noise.
        if self.timing_is_significant() {
            return true;
        }
        self.changed_headers
            .iter()
            .any(|c| !NOISY_HEADERS.contains(&c.name.to_ascii_lowercase().as_str()))
    }

    /// A one-line summary, for a list of many results.
    pub fn summary(&self) -> String {
        if self.is_identical() && !self.timing_is_significant() {
            return "identical".to_string();
        }

        let mut parts = Vec::new();
        if self.is_identical() {
            parts.push("identical body".to_string());
        }
        if let Some((before, after)) = self.status {
            parts.push(format!("status {before} → {after}"));
        }
        if let Some((before, after)) = self.body_length {
            let delta = after as i64 - before as i64;
            parts.push(format!("body {before} → {after} ({delta:+})"));
        } else if !self.bodies_identical {
            parts.push(format!(
                "body differs at byte {}",
                self.first_difference_at.unwrap_or(0)
            ));
        }
        let header_changes =
            self.changed_headers.len() + self.added_headers.len() + self.removed_headers.len();
        if header_changes > 0 {
            parts.push(format!("{header_changes} header changes"));
        }

        let (before, after) = self.timing;
        // Timing is always shown once anything is worth summarising at all: a
        // body-identical response that took four seconds longer is the entire signal
        // in a time-based blind injection test.
        parts.push(format!(
            "{before}ms → {after}ms ({:+}ms)",
            self.timing_delta_ms()
        ));
        parts.join(", ")
    }
}

/// Removes changes for header names that appear more than once.
///
/// Comparing duplicate headers by name is meaningless — `get` returns only the first,
/// so a request with two `Set-Cookie` fields would report a change that is really just
/// a different ordering. Duplicates are reported as a name-level change instead.
fn dedupe_changes(changes: Vec<HeaderChange>, before: &Headers) -> Vec<HeaderChange> {
    changes
        .into_iter()
        .filter(|c| before.count(&c.name) == 1)
        .collect()
}

/// The offset of the first differing byte.
fn first_difference(a: &[u8], b: &[u8]) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y).or({
        if a.len() == b.len() {
            None
        } else {
            Some(a.len().min(b.len()))
        }
    })
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use hexora_types::http::{Header, HttpVersion};

    use super::*;

    fn response(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            reason: Some("OK".into()),
            version: HttpVersion::Http11,
            headers: Headers::new(),
            body: Bytes::copy_from_slice(body.as_bytes()),
            truncated: false,
        }
    }

    #[test]
    fn two_identical_responses_diff_to_nothing() {
        let diff = ResponseDiff::compare(&response(200, "same"), &response(200, "same"), (10, 11));
        assert!(diff.is_identical());
        assert!(!diff.is_interesting());
        assert_eq!(diff.summary(), "identical");
    }

    #[test]
    fn a_status_change_is_reported() {
        let diff = ResponseDiff::compare(&response(200, "x"), &response(403, "x"), (5, 5));
        assert_eq!(diff.status, Some((200, 403)));
        assert!(diff.is_interesting());
        assert!(diff.summary().contains("200 → 403"), "{}", diff.summary());
    }

    #[test]
    fn a_body_change_reports_the_offset_of_the_first_difference() {
        // The offset is what a tester jumps to; a whole-body diff would bury it.
        let diff = ResponseDiff::compare(
            &response(200, "hello world"),
            &response(200, "hello WORLD"),
            (1, 1),
        );
        assert!(!diff.bodies_identical);
        assert_eq!(diff.first_difference_at, Some(6));
        assert_eq!(diff.body_length, None, "same length, different content");
    }

    #[test]
    fn a_length_change_reports_the_delta_with_a_sign() {
        let diff = ResponseDiff::compare(&response(200, "abc"), &response(200, "abcdef"), (1, 1));
        assert_eq!(diff.body_length, Some((3, 6)));
        assert!(diff.summary().contains("(+3)"), "{}", diff.summary());
    }

    #[test]
    fn a_truncated_body_still_diffs_from_its_longer_form() {
        let diff = ResponseDiff::compare(&response(200, "abcdef"), &response(200, "abc"), (1, 1));
        assert_eq!(diff.first_difference_at, Some(3));
    }

    #[test]
    fn added_and_removed_headers_are_reported_separately() {
        let mut before = response(200, "x");
        before.headers.append(Header::new("X-Gone", "1"));
        let mut after = response(200, "x");
        after.headers.append(Header::new("X-New", "2"));

        let diff = ResponseDiff::compare(&before, &after, (1, 1));
        assert_eq!(diff.removed_headers, vec!["X-Gone"]);
        assert_eq!(diff.added_headers, vec!["X-New"]);
        assert!(diff.is_interesting());
    }

    #[test]
    fn a_changed_header_value_carries_both_sides() {
        let mut before = response(200, "x");
        before.headers.append(Header::new("Server", "nginx"));
        let mut after = response(200, "x");
        after.headers.append(Header::new("Server", "apache"));

        let diff = ResponseDiff::compare(&before, &after, (1, 1));
        assert_eq!(
            diff.changed_headers,
            vec![HeaderChange {
                name: "Server".into(),
                before: "nginx".into(),
                after: "apache".into(),
            }]
        );
    }

    #[test]
    fn header_matching_ignores_case() {
        let mut before = response(200, "x");
        before
            .headers
            .append(Header::new("content-type", "text/html"));
        let mut after = response(200, "x");
        after
            .headers
            .append(Header::new("Content-Type", "text/html"));

        let diff = ResponseDiff::compare(&before, &after, (1, 1));
        assert!(diff.is_identical(), "{diff:?}");
    }

    #[test]
    fn a_date_that_merely_moved_on_is_not_interesting() {
        // Otherwise every diff is "interesting" and the flag means nothing.
        let mut before = response(200, "x");
        before
            .headers
            .append(Header::new("Date", "Mon, 01 Jan 2035 00:00:00 GMT"));
        let mut after = response(200, "x");
        after
            .headers
            .append(Header::new("Date", "Mon, 01 Jan 2035 00:00:01 GMT"));

        let diff = ResponseDiff::compare(&before, &after, (1, 1));
        assert!(!diff.is_identical(), "the change is still reported");
        assert!(!diff.is_interesting(), "but it is not worth attention");
    }

    #[test]
    fn a_session_cookie_changing_is_not_interesting_but_is_still_listed() {
        let mut before = response(200, "x");
        before.headers.append(Header::new("Set-Cookie", "s=aaa"));
        let mut after = response(200, "x");
        after.headers.append(Header::new("Set-Cookie", "s=bbb"));

        let diff = ResponseDiff::compare(&before, &after, (1, 1));
        assert_eq!(diff.changed_headers.len(), 1);
        assert!(!diff.is_interesting());
    }

    #[test]
    fn an_identical_body_that_arrived_seconds_later_is_a_finding_not_noise() {
        // A successful time-based blind injection produces exactly this: the same
        // bytes, much later. Reporting it as "identical" would hide the finding, so
        // the timing delta both shows up in the summary and makes the diff
        // interesting on its own.
        let diff = ResponseDiff::compare(&response(200, "x"), &response(200, "x"), (120, 4130));
        assert!(diff.is_identical(), "the messages really are the same");
        assert!(diff.is_interesting(), "but this is the whole signal");
        assert!(diff.timing_is_significant());
        assert_eq!(diff.timing_delta_ms(), 4010);
        assert!(diff.summary().contains("+4010ms"), "{}", diff.summary());
        assert!(
            diff.summary().contains("identical body"),
            "{}",
            diff.summary()
        );
    }

    #[test]
    fn ordinary_jitter_is_not_mistaken_for_a_timing_signal() {
        // If every resend read as "interesting", the flag would be worthless.
        let diff = ResponseDiff::compare(&response(200, "x"), &response(200, "x"), (120, 260));
        assert!(!diff.timing_is_significant());
        assert!(!diff.is_interesting());
        assert_eq!(diff.summary(), "identical");
    }

    #[test]
    fn a_response_that_got_much_faster_is_also_significant() {
        // Direction is not assumed: a target that suddenly answers instantly has
        // changed behaviour just as much as one that stalled.
        let diff = ResponseDiff::compare(&response(200, "x"), &response(200, "x"), (5000, 40));
        assert!(diff.timing_is_significant());
        assert_eq!(diff.timing_delta_ms(), -4960);
    }

    #[test]
    fn duplicate_headers_are_not_reported_as_a_value_change() {
        // `get` returns the first match, so comparing by name across duplicates would
        // report reordering as a change.
        let mut before = response(200, "x");
        before.headers.append(Header::new("Set-Cookie", "a=1"));
        before.headers.append(Header::new("Set-Cookie", "b=2"));
        let mut after = response(200, "x");
        after.headers.append(Header::new("Set-Cookie", "b=2"));
        after.headers.append(Header::new("Set-Cookie", "a=1"));

        let diff = ResponseDiff::compare(&before, &after, (1, 1));
        assert!(diff.changed_headers.is_empty(), "{diff:?}");
    }
}
