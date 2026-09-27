//! # hexora-sequencer
//!
//! Are these tokens actually unpredictable? Burp's Sequencer answers it for session ids, CSRF
//! tokens, password-reset tokens — anything whose security rests on being hard to guess. This
//! is the same question, answered from a set of samples a tester collected.
//!
//! ```text
//! 200 tokens, 32 chars each, charset [0-9a-f] (16)
//! entropy: 3.98 bits/char -> ~127 bits/token
//! signals: none
//! verdict: high — consistent with a random 128-bit hex token
//! ```
//!
//! # It measures, it does not certify
//!
//! Entropy from a sample is an estimate, and a sample can look random while the generator is
//! not (a counter encrypted under a fixed key looks uniform). So this reports what the bytes
//! show — per-character entropy, effective bits, obvious structure — and says plainly when the
//! sample is too small to conclude much. It never certifies a token as secure; it flags the
//! ones that are clearly *not*.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use std::collections::HashSet;

/// Below this many samples, an entropy estimate is too shaky to lean on.
pub const WEAK_SAMPLE_THRESHOLD: usize = 20;

/// What analysing a set of tokens found.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// How many tokens were analysed (blank ones dropped).
    pub samples: usize,
    /// How many of them were distinct.
    pub unique: usize,
    /// The shortest and longest token lengths (in characters).
    pub min_len: usize,
    /// The longest token length.
    pub max_len: usize,
    /// The distinct characters seen across all tokens.
    pub charset_size: usize,
    /// Shannon entropy of the character distribution, in bits per character.
    pub bits_per_char: f64,
    /// An estimate of the entropy of a whole token: `bits_per_char × mean length`.
    pub bits_per_token: f64,
    /// Heuristic notes worth a tester's eye (predictable structure, small sample, …).
    pub signals: Vec<String>,
    /// A one-word qualitative reading, always alongside the numbers, never instead of them.
    pub verdict: Verdict,
}

/// A qualitative reading of the sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Too few samples to say anything firm.
    Insufficient,
    /// Clearly predictable — sequential, tiny charset, or heavy repetition.
    Weak,
    /// Some entropy, but not obviously strong.
    Moderate,
    /// Consistent with a well-generated random token.
    Strong,
}

impl Verdict {
    /// A short label.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Insufficient => "insufficient samples",
            Verdict::Weak => "weak",
            Verdict::Moderate => "moderate",
            Verdict::Strong => "strong",
        }
    }
}

/// Analyses a set of tokens for how unpredictable they look.
pub fn analyze(tokens: &[String]) -> Report {
    let tokens: Vec<&str> = tokens
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.is_empty() {
        return Report {
            samples: 0,
            unique: 0,
            min_len: 0,
            max_len: 0,
            charset_size: 0,
            bits_per_char: 0.0,
            bits_per_token: 0.0,
            signals: vec!["no tokens to analyse".to_string()],
            verdict: Verdict::Insufficient,
        };
    }

    let samples = tokens.len();
    let unique = tokens.iter().collect::<HashSet<_>>().len();

    let lengths: Vec<usize> = tokens.iter().map(|t| t.chars().count()).collect();
    let min_len = *lengths.iter().min().unwrap();
    let max_len = *lengths.iter().max().unwrap();
    let mean_len = lengths.iter().sum::<usize>() as f64 / samples as f64;

    // Character frequency across every token, for the Shannon entropy of the charset.
    let mut freq: std::collections::HashMap<char, u64> = std::collections::HashMap::new();
    let mut total_chars = 0u64;
    for token in &tokens {
        for ch in token.chars() {
            *freq.entry(ch).or_insert(0) += 1;
            total_chars += 1;
        }
    }
    let charset_size = freq.len();
    let bits_per_char = shannon_entropy(freq.values().copied(), total_chars);
    let bits_per_token = bits_per_char * mean_len;

    let mut signals = Vec::new();

    if samples < WEAK_SAMPLE_THRESHOLD {
        signals.push(format!(
            "only {samples} sample(s) — fewer than {WEAK_SAMPLE_THRESHOLD}, so any entropy \
             estimate here is weak; collect more before trusting it"
        ));
    }
    if unique < samples {
        signals.push(format!(
            "{} repeated value(s) — a token that recurs is a token that can be replayed",
            samples - unique
        ));
    }
    if charset_size <= 4 && total_chars > 0 {
        signals.push(format!(
            "only {charset_size} distinct character(s) — a very small alphabet"
        ));
    }
    let sequential = looks_sequential(&tokens);
    if sequential {
        signals.push(
            "the tokens are sequential or evenly spaced — they can be predicted from one \
             another, whatever their length"
                .to_string(),
        );
    }

    let verdict = verdict(samples, unique, bits_per_token, sequential, charset_size);

    Report {
        samples,
        unique,
        min_len,
        max_len,
        charset_size,
        bits_per_char,
        bits_per_token,
        signals,
        verdict,
    }
}

/// Shannon entropy in bits, from a set of counts and their total.
fn shannon_entropy(counts: impl Iterator<Item = u64>, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let mut h = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total;
        h -= p * p.log2();
    }
    h
}

/// Whether the tokens are a sequence: parseable as integers (decimal or hex) and evenly spaced.
///
/// This is the failure that length and charset hide — a 32-character token that is really a
/// zero-padded counter has all the entropy of the counter, which is none.
fn looks_sequential(tokens: &[&str]) -> bool {
    if tokens.len() < 3 {
        return false;
    }
    // Try decimal, then hex. Every token must parse the same way.
    for radix in [10u32, 16u32] {
        let parsed: Option<Vec<i128>> = tokens
            .iter()
            .map(|t| i128::from_str_radix(t.trim_start_matches("0x"), radix).ok())
            .collect();
        let Some(mut values) = parsed else { continue };
        values.sort_unstable();
        values.dedup();
        if values.len() < 3 {
            return true; // parsed as numbers but nearly all equal — trivially predictable
        }
        // Even spacing: all consecutive differences equal (an arithmetic progression).
        let step = values[1] - values[0];
        if step != 0 && values.windows(2).all(|w| w[1] - w[0] == step) {
            return true;
        }
        // Or a tight cluster: the whole range spans little more than the count (near-consecutive).
        let span = values[values.len() - 1] - values[0];
        if span >= 0 && span <= (values.len() as i128) * 2 {
            return true;
        }
    }
    false
}

/// The qualitative reading, kept conservative: it downgrades on any concrete predictability
/// signal and only calls a sample strong when it has both the samples and the bits to back it.
fn verdict(
    samples: usize,
    unique: usize,
    bits_per_token: f64,
    sequential: bool,
    charset_size: usize,
) -> Verdict {
    if samples < 3 {
        return Verdict::Insufficient;
    }
    if sequential || unique < samples || charset_size <= 2 {
        return Verdict::Weak;
    }
    if samples < WEAK_SAMPLE_THRESHOLD {
        // Not enough to certify strength, whatever the bits look like.
        return Verdict::Moderate;
    }
    if bits_per_token >= 64.0 {
        Verdict::Strong
    } else if bits_per_token >= 32.0 {
        Verdict::Moderate
    } else {
        Verdict::Weak
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch of pseudo-random-looking hex tokens (deterministic, for the test).
    fn hex_tokens(n: usize) -> Vec<String> {
        let mut state = 0x9e3779b97f4a7c15u64;
        (0..n)
            .map(|_| {
                // xorshift, formatted as 32 hex chars from two words.
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let a = state;
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                format!("{a:016x}{state:016x}")
            })
            .collect()
    }

    #[test]
    fn a_batch_of_random_hex_reads_as_strong() {
        let report = analyze(&hex_tokens(200));
        assert_eq!(report.samples, 200);
        assert!(report.charset_size <= 16, "hex alphabet");
        assert!(report.bits_per_token > 64.0, "{}", report.bits_per_token);
        assert_eq!(report.verdict, Verdict::Strong, "{report:?}");
        assert!(report.signals.is_empty(), "{:?}", report.signals);
    }

    #[test]
    fn an_incrementing_counter_is_weak_however_long() {
        // Zero-padded so every token is 8 chars — length and charset hide nothing.
        let tokens: Vec<String> = (1000..1100).map(|i| format!("{i:08}")).collect();
        let report = analyze(&tokens);
        assert_eq!(report.verdict, Verdict::Weak);
        assert!(
            report.signals.iter().any(|s| s.contains("sequential")),
            "{:?}",
            report.signals
        );
    }

    #[test]
    fn hex_counter_is_caught_too() {
        let tokens: Vec<String> = (0..50).map(|i| format!("{i:08x}")).collect();
        assert_eq!(analyze(&tokens).verdict, Verdict::Weak);
    }

    #[test]
    fn repeated_tokens_are_flagged_and_never_strong() {
        let mut tokens = hex_tokens(200);
        tokens[10] = tokens[9].clone(); // a collision
        let report = analyze(&tokens);
        assert!(report.unique < report.samples);
        assert_ne!(report.verdict, Verdict::Strong);
        assert!(report.signals.iter().any(|s| s.contains("repeated")));
    }

    #[test]
    fn a_tiny_sample_is_moderate_at_best() {
        let report = analyze(&hex_tokens(5));
        assert!(matches!(
            report.verdict,
            Verdict::Moderate | Verdict::Insufficient
        ));
        assert!(report.signals.iter().any(|s| s.contains("weak")));
    }

    #[test]
    fn a_two_symbol_alphabet_is_weak() {
        let tokens: Vec<String> = (0..40)
            .map(|i| {
                if i % 2 == 0 {
                    "aaaa".into()
                } else {
                    "abab".into()
                }
            })
            .collect();
        assert_eq!(analyze(&tokens).verdict, Verdict::Weak);
    }

    #[test]
    fn no_tokens_is_insufficient_not_a_panic() {
        let report = analyze(&[]);
        assert_eq!(report.verdict, Verdict::Insufficient);
        assert_eq!(report.samples, 0);
    }

    #[test]
    fn entropy_of_a_uniform_hex_char_is_about_four_bits() {
        // 16 equally likely symbols -> 4 bits/char.
        let tokens: Vec<String> = vec!["0123456789abcdef".repeat(4)];
        let report = analyze(&tokens);
        assert!(
            (report.bits_per_char - 4.0).abs() < 0.01,
            "{}",
            report.bits_per_char
        );
    }
}
