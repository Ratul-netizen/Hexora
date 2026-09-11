//! What a run is allowed to do to somebody's system.
//!
//! Every other limit in Hexora protects the tool — [`Limits`](hexora_types::Limits)
//! stops a decompression bomb, the scope guard stops a request going somewhere nobody
//! authorized. This one protects the *target*, and it is the first thing in the
//! codebase that does.
//!
//! That makes it a promise rather than a tuning knob. A scanner that saturated a
//! staging box during a demo is a scanner nobody is allowed to run again, and the
//! client who said yes to a security test did not say yes to a load test.
//!
//! # The shape of the promise
//!
//! ```text
//! host A  ──▶ req ──(pause)──▶ req ──(pause)──▶ req        never two at once
//! host B  ──▶ req ──(pause)──▶ req                         a different queue
//! host C  ──▶ waiting for a slot                           at most `hosts_at_once`
//! ```
//!
//! **One host never receives two Hexora requests at the same time.** Each host has one
//! sequential queue, and a [`Budget::pause`] between its requests. Different hosts are
//! worked concurrently, up to [`Budget::hosts_at_once`].
//!
//! A global semaphore would have been simpler and is the wrong promise: eight
//! concurrent requests spread over eight hosts is polite, and eight aimed at one host
//! is a small denial of service. The thing a client cares about is what *their* server
//! sees, so that is what the limit is expressed in.
//!
//! # Ceilings, and why they are not "found nothing"
//!
//! [`Budget::max_requests`] is a hard stop for the whole run and
//! [`Budget::per_hypothesis`] for one experiment. Hitting either ends the run early,
//! and the run says so — see
//! [`StoppedBecause`](crate::StoppedBecause). A truncated run that reported itself as
//! a completed one would be the worst output this crate could produce, because the
//! reader's conclusion would be "clean" rather than "unfinished".

use std::time::Duration;

/// What a run may do to the systems it tests.
///
/// The defaults are deliberately slow. A tester who needs it faster can say so and
/// has thereby made a decision; a tester who never thought about it gets the setting
/// that will not embarrass them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    /// How many hosts may be worked at the same time.
    ///
    /// Concurrency *across* targets, never within one.
    pub hosts_at_once: usize,
    /// How long to wait after one request to a host before the next to that host.
    ///
    /// Measured from the end of one request to the start of the next, so a slow
    /// endpoint is never asked faster than a quick one.
    pub pause: Duration,
    /// The most requests the whole run may send.
    pub max_requests: usize,
    /// The most requests one experiment may send.
    ///
    /// A check that wants more than this has to say so in its own terms rather than
    /// quietly looping.
    pub per_hypothesis: usize,
}

impl Budget {
    /// The slowest sensible setting: one host at a time, a second between requests.
    ///
    /// For a production system during business hours, where being boring is the whole
    /// job.
    pub fn careful() -> Self {
        Self {
            hosts_at_once: 1,
            pause: Duration::from_millis(1000),
            max_requests: 100,
            per_hypothesis: 4,
        }
    }

    /// How the budget reads in a run record and in a confirmation prompt.
    pub fn describe(&self) -> String {
        format!(
            "at most {} request(s), {} host(s) at a time, {}ms between requests to one \
             host, {} request(s) per experiment",
            self.max_requests,
            self.hosts_at_once,
            self.pause.as_millis(),
            self.per_hypothesis,
        )
    }

    /// Rejects a budget that would be rude, or that is not a budget at all.
    ///
    /// Returns the reason rather than clamping silently: a tester who typed
    /// `--concurrency 0` meant something, and quietly running with 1 answers a
    /// question they did not ask.
    pub fn check(&self) -> Result<(), String> {
        if self.hosts_at_once == 0 {
            return Err("hosts at a time must be at least 1, or nothing would be sent".into());
        }
        if self.hosts_at_once > MAX_HOSTS_AT_ONCE {
            return Err(format!(
                "hosts at a time is capped at {MAX_HOSTS_AT_ONCE}: past that this stops \
                 being a security test and starts being a load test"
            ));
        }
        if self.max_requests == 0 {
            return Err("the request ceiling must be at least 1, or nothing would be sent".into());
        }
        if self.max_requests > MAX_REQUESTS {
            return Err(format!(
                "the request ceiling is capped at {MAX_REQUESTS} in this build. Run a \
                 narrower selection rather than a longer run: a queue nobody is \
                 watching is how a tool ends up sending traffic after everyone has \
                 gone home"
            ));
        }
        if self.per_hypothesis == 0 {
            return Err("each experiment must be allowed at least 1 request".into());
        }
        Ok(())
    }
}

/// The most hosts this build will work at once, whatever it is asked for.
pub const MAX_HOSTS_AT_ONCE: usize = 8;

/// The most requests one run will send, whatever it is asked for.
pub const MAX_REQUESTS: usize = 5_000;

impl Default for Budget {
    /// Two hosts at a time, a quarter-second between requests to one host, 200
    /// requests in total.
    ///
    /// Slower than a tester on a laptop clicking through an application by hand, which
    /// is the bar a scanner's default should clear.
    fn default() -> Self {
        Self {
            hosts_at_once: 2,
            pause: Duration::from_millis(250),
            max_requests: 200,
            per_hypothesis: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_slower_than_a_person_clicking_around() {
        let budget = Budget::default();
        assert!(budget.pause >= Duration::from_millis(100));
        assert!(budget.hosts_at_once <= 2);
        assert!(budget.check().is_ok());
    }

    #[test]
    fn a_budget_that_would_send_nothing_is_refused_rather_than_clamped() {
        // Silently running with 1 would answer a question the tester did not ask.
        for budget in [
            Budget {
                hosts_at_once: 0,
                ..Budget::default()
            },
            Budget {
                max_requests: 0,
                ..Budget::default()
            },
            Budget {
                per_hypothesis: 0,
                ..Budget::default()
            },
        ] {
            assert!(budget.check().is_err(), "{budget:?}");
        }
    }

    #[test]
    fn the_ceilings_cannot_be_raised_past_the_build_limits() {
        assert!(Budget {
            hosts_at_once: MAX_HOSTS_AT_ONCE + 1,
            ..Budget::default()
        }
        .check()
        .is_err());
        assert!(Budget {
            max_requests: MAX_REQUESTS + 1,
            ..Budget::default()
        }
        .check()
        .is_err());
    }

    #[test]
    fn the_budget_says_what_it_is_in_a_sentence() {
        let described = Budget::default().describe();
        assert!(described.contains("200 request(s)"), "{described}");
        assert!(described.contains("250ms"), "{described}");
    }
}
