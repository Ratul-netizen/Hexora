//! Where a value came back, and which of its characters survived.
//!
//! A scanner that reports "my string appeared in the response" is the scanner people
//! have learned to filter out of their inbox, because that sentence is true of every
//! search box ever built. The useful question is two questions:
//!
//! ```text
//! {"note": "hx7a3f"}                 a JSON string        — inert
//! <div>hx7a3f</div>                  HTML text            — needs < to matter
//! <input value="hx7a3f">             an attribute         — needs " to escape
//! <script>var x = "hx7a3f"</script>  a script string      — needs " and ;
//! <a href="hx7a3f">                  a URL                — a scheme matters
//! /* hx7a3f */                       a comment            — needs */
//! ```
//!
//! Six places, six different facts, and the character that would matter is different
//! in each. So this module answers *where* ([`Context`]) and *what got through*
//! ([`Survived`]), and stops there.
//!
//! # It never says "cross-site scripting"
//!
//! Nothing here concludes that anything is exploitable. `<` arriving unencoded inside
//! an HTML text node is a fact about bytes; whether it is a vulnerability depends on a
//! Content-Security-Policy this module cannot see, a framework that may re-encode on
//! render, and a page a person has to look at. Hexora says what came back and where,
//! and the tester decides — which is the difference between a finding somebody acts on
//! and one they argue with.
//!
//! # The sandwich
//!
//! One injected value answers both questions at once:
//!
//! ```text
//! sent:      hxAAAA<"'>hxBBBB
//!            ───┬── ─┬─ ───┬──
//!            prefix  probe  suffix
//!
//! got back:  hxAAAA&lt;"'&gt;hxBBBB      → " and ' survived, < and > did not
//! ```
//!
//! The two tokens are different so that finding the prefix tells you where the value
//! starts and finding the suffix tells you where it ends, even when the middle has been
//! rewritten to something longer or shorter than what was sent. Both are alphanumeric,
//! so nothing encodes them and nothing in the middle can be mistaken for them.
//!
//! # The content type decides what the bytes mean
//!
//! `{"q": "<script>"}` is inert as `application/json` and is markup as `text/html`,
//! and the bytes are identical. So [`Probe::found_in`] is given the response's declared
//! content type rather than sniffing it: the caller has that header, guessing at it
//! would be inventing information, and the difference between those two answers is the
//! difference between a finding and a waste of somebody's afternoon.
//!
//! A body served as something else entirely — `text/plain`, an image — reports
//! [`Context::Unknown`], because this module has no opinion about how a browser will
//! treat it and neither should a report.

use serde::{Deserialize, Serialize};

/// The characters a probe carries, and what each one would break out of.
///
/// Deliberately small. Every character here is one whose *absence* from the response
/// is the interesting answer as often as its presence, and a longer list would mean
/// more of somebody's application filled with junk for the same information.
pub const PROBE_CHARACTERS: &str = "<>\"'`;()";

/// What a surviving character would let somebody out of.
///
/// Advisory, and phrased as "would matter here" rather than "is exploitable": whether
/// it is depends on a policy header, a template engine and a page, none of which is
/// visible from one response body.
pub fn why_it_matters(character: char, context: Context) -> Option<&'static str> {
    match (character, context) {
        ('<', Context::HtmlText) | ('>', Context::HtmlText) => {
            Some("an angle bracket in HTML text can start a tag of its own")
        }
        ('"', Context::HtmlAttribute { quoted: Some('"') }) => {
            Some("a double quote can close the attribute it is inside")
        }
        ('\'', Context::HtmlAttribute { quoted: Some('\'') }) => {
            Some("a single quote can close the attribute it is inside")
        }
        (_, Context::HtmlAttribute { quoted: None }) => {
            Some("an unquoted attribute ends at the first space, so almost anything ends it")
        }
        ('"', Context::ScriptString { quoted: '"' })
        | ('\'', Context::ScriptString { quoted: '\'' }) => {
            Some("a matching quote can close the string literal it is inside")
        }
        ('`', Context::ScriptString { .. }) => {
            Some("a backtick can open a template literal, which many filters do not consider")
        }
        (';', Context::Script) | ('(', Context::Script) => {
            Some("this value is already inside script source rather than a string in it")
        }
        ('>', Context::HtmlComment) => Some("`-->` ends a comment and returns to markup"),
        _ => None,
    }
}

/// How the response said it should be read.
///
/// Taken from `Content-Type` rather than sniffed from the body. The same bytes mean
/// different things under different types, and a scanner that decided for itself which
/// one applied would be reporting on a document nobody served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serving {
    /// `text/html` or `application/xhtml+xml`: the bytes are markup.
    Markup,
    /// `application/json` and its `+json` relatives: the bytes are data.
    Json,
    /// Anything else, including no `Content-Type` at all.
    ///
    /// Not an error and not a reason to guess. A value echoed into `text/plain` is a
    /// fact with no consequence this module can name.
    Other,
}

impl Serving {
    /// Reads a `Content-Type` value, parameters and all.
    pub fn of(content_type: Option<&str>) -> Self {
        let Some(value) = content_type else {
            return Self::Other;
        };
        let media = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        match media.as_str() {
            "text/html" | "application/xhtml+xml" => Self::Markup,
            other if other == "application/json" || other.ends_with("+json") => Self::Json,
            _ => Self::Other,
        }
    }
}

/// Where in a response a value came back.
///
/// Recognised by what surrounds it, which is a heuristic and is described as one: a
/// response is not parsed into a DOM here, and a document that is invalid markup —
/// which many real pages are — can be read wrongly. [`Context::Unknown`] is a normal
/// answer and a better one than a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Context {
    /// Between tags, where a `<` would start markup of its own.
    HtmlText,
    /// Inside an attribute value.
    HtmlAttribute {
        /// The quote character the attribute uses, or `None` when it is unquoted.
        quoted: Option<char>,
    },
    /// Inside `<!-- -->`.
    HtmlComment,
    /// Inside a string literal in a `<script>` block.
    ScriptString {
        /// The quote character the literal uses.
        quoted: char,
    },
    /// Inside a `<script>` block but not inside a string.
    Script,
    /// Inside a `<style>` block.
    Style,
    /// Inside a JSON string value.
    ///
    /// The common and usually inert case: an API echoing a parameter back. It becomes
    /// interesting only if the response is served as HTML, which is a property of the
    /// `Content-Type` rather than of the body.
    JsonString,
    /// Somewhere this module would rather not guess about.
    Unknown,
}

impl Context {
    /// How it reads in a finding.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HtmlText => "HTML text",
            Self::HtmlAttribute { quoted: Some('"') } => "a double-quoted HTML attribute",
            Self::HtmlAttribute { quoted: Some('\'') } => "a single-quoted HTML attribute",
            Self::HtmlAttribute { .. } => "an unquoted HTML attribute",
            Self::HtmlComment => "an HTML comment",
            Self::ScriptString { quoted: '"' } => "a double-quoted string in a script block",
            Self::ScriptString { quoted: '\'' } => "a single-quoted string in a script block",
            Self::ScriptString { .. } => "a template literal in a script block",
            Self::Script => "script source",
            Self::Style => "a style block",
            Self::JsonString => "a JSON string",
            Self::Unknown => "a place this check could not identify",
        }
    }

    /// Whether a surviving character here is worth a tester's attention.
    ///
    /// Not "is exploitable". A JSON string echoed by an API is the overwhelmingly
    /// common case and is almost always nothing; saying so is what keeps the
    /// interesting ones visible.
    pub fn worth_looking_at(&self) -> bool {
        !matches!(self, Self::JsonString | Self::Unknown)
    }
}

/// One place a marked value came back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Echo {
    /// Where in the response body it starts.
    pub offset: usize,
    /// What surrounds it.
    pub context: Context,
    /// Which probe characters came back as themselves.
    pub survived: Vec<char>,
    /// What came back between the two tokens, quoted and truncated.
    ///
    /// The evidence for the character list: a reader who disagrees with the
    /// classification can see the bytes it was made from.
    pub between: String,
}

impl Echo {
    /// The probe characters that survived *and* would matter where they landed.
    pub fn dangerous(&self) -> Vec<char> {
        self.survived
            .iter()
            .copied()
            .filter(|c| why_it_matters(*c, self.context).is_some())
            .collect()
    }
}

/// What a probe established about one response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Survived {
    /// Every place the value came back.
    pub echoes: Vec<Echo>,
}

impl Survived {
    /// Whether the value came back at all.
    pub fn reflected(&self) -> bool {
        !self.echoes.is_empty()
    }

    /// The echoes where something that would matter got through.
    pub fn notable(&self) -> impl Iterator<Item = &Echo> {
        self.echoes
            .iter()
            .filter(|echo| echo.context.worth_looking_at() && !echo.dangerous().is_empty())
    }

    /// The strongest thing that can be said, in a sentence, or `None` if nothing can.
    pub fn summary(&self) -> Option<String> {
        let echo = self.notable().next()?;
        let characters: String = echo
            .dangerous()
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let why = echo
            .dangerous()
            .first()
            .and_then(|c| why_it_matters(*c, echo.context))
            .unwrap_or("it came back as itself");
        Some(format!(
            "{characters} came back unencoded inside {} — {why}",
            echo.context.as_str()
        ))
    }
}

/// A value built to be findable in a response, carrying probe characters in the middle.
///
/// The tokens are generated per run rather than fixed, so a page that happens to
/// contain the word this build compiled in is not mistaken for a reflection. They are
/// alphanumeric and lowercase, because a value that survives percent-encoding, HTML
/// escaping and case normalisation is one whose absence means something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    prefix: String,
    suffix: String,
    characters: String,
}

impl Probe {
    /// A probe carrying [`PROBE_CHARACTERS`], seeded by `seed`.
    ///
    /// Deterministic in the seed so a test can assert on the value and a run can
    /// reproduce its own probe when it re-runs. The seed is expected to be
    /// unpredictable per run, not per request.
    pub fn seeded(seed: u64) -> Self {
        Self {
            prefix: token(seed, "a"),
            suffix: token(seed.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15, "b"),
            characters: PROBE_CHARACTERS.to_string(),
        }
    }

    /// A probe that carries no special characters.
    ///
    /// For the first question on its own — *does this come back at all* — against an
    /// application where putting punctuation into a field is not wanted.
    pub fn inert(seed: u64) -> Self {
        Self {
            characters: String::new(),
            ..Self::seeded(seed)
        }
    }

    /// The value to send.
    pub fn value(&self) -> String {
        format!("{}{}{}", self.prefix, self.characters, self.suffix)
    }

    /// The token that marks where the value starts.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The token that marks where it ends.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// Finds every place this probe came back in a response body.
    ///
    /// `serving` comes from the response's own `Content-Type`. Reads bytes as UTF-8
    /// lossily: a response is whatever the application sent, and a body that is not
    /// valid UTF-8 still has a marker in it if the marker is there.
    pub fn found_in(&self, body: &[u8], serving: Serving) -> Survived {
        let text = String::from_utf8_lossy(body);
        let mut echoes = Vec::new();
        let mut from = 0usize;

        while let Some(at) = text[from..].find(&self.prefix) {
            let start = from + at;
            let after = start + self.prefix.len();
            // The suffix has to come after the prefix, and the *nearest* one is the
            // end of this occurrence: a page that reflects twice would otherwise be
            // read as one enormous echo spanning both.
            let Some(end) = text[after..].find(&self.suffix).map(|at| after + at) else {
                from = after;
                continue;
            };

            let between = &text[after..end];
            echoes.push(Echo {
                offset: start,
                context: context_at(&text, start, serving),
                survived: self
                    .characters
                    .chars()
                    .filter(|c| between.contains(*c))
                    .collect(),
                between: truncate(between),
            });
            from = end + self.suffix.len();
        }

        Survived { echoes }
    }
}

/// The longest run of returned bytes quoted as evidence.
const BETWEEN_LIMIT: usize = 120;

fn truncate(value: &str) -> String {
    if value.chars().count() <= BETWEEN_LIMIT {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(BETWEEN_LIMIT).collect();
    cut.push('…');
    cut
}

/// A short lowercase alphanumeric token, deterministic in the seed.
///
/// Not a cryptographic identifier — it marks a position in a document somebody is
/// about to read, and the only property that matters is that an ordinary page does
/// not contain it by accident.
fn token(seed: u64, salt: &str) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = seed ^ 0x5851_f42d_4c95_7f2d;
    let mut out = String::from("hx");
    out.push_str(salt);
    for _ in 0..7 {
        // xorshift: short, dependency-free, and entirely adequate for a marker.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(ALPHABET[(state % ALPHABET.len() as u64) as usize] as char);
    }
    out
}

/// What surrounds a position in a document.
///
/// Scans backwards from the position, which is the whole technique and its whole
/// limitation: it reads the nearest structural marker rather than parsing, so a
/// document with unbalanced tags can be read wrongly. Everything ambiguous is
/// [`Context::Unknown`].
fn context_at(text: &str, at: usize, serving: Serving) -> Context {
    let before = &text[..at.min(text.len())];

    match serving {
        // Data. Whatever markup is in it is markup nobody will render — and if the
        // value broke the document's own quoting, that is worth saying on its own.
        Serving::Json => {
            return match unterminated_quote(before) {
                Some('"') => Context::JsonString,
                _ => Context::Unknown,
            }
        }
        // No opinion about how a browser treats this, and no business inventing one.
        Serving::Other => return Context::Unknown,
        Serving::Markup => {}
    }

    // A comment wins over everything: inside `<!-- -->` nothing else is structural.
    if let Some(open) = before.rfind("<!--") {
        if !before[open..].contains("-->") {
            return Context::HtmlComment;
        }
    }

    // Inside a script or style block, whatever the surrounding markup looks like.
    if let Some(kind) = enclosing_block(before) {
        return match kind {
            Block::Script => match unterminated_quote(&before[kind.body_start(before)..]) {
                Some(quote) => Context::ScriptString { quoted: quote },
                None => Context::Script,
            },
            Block::Style => Context::Style,
        };
    }

    // Inside a tag: `<a href="…` with no `>` since.
    if let Some(open) = before.rfind('<') {
        let tag = &before[open..];
        if !tag.contains('>') {
            return Context::HtmlAttribute {
                quoted: unterminated_quote(tag),
            };
        }
    }

    // Nothing structural around it, and the response said this is markup. A browser
    // parses a `text/html` body as HTML whether or not a tag happened to come first,
    // so text is text — including in a JSON-shaped body somebody served with the wrong
    // content type, which is exactly the case worth catching.
    Context::HtmlText
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Block {
    Script,
    Style,
}

impl Block {
    /// Where the block's content begins, measured in the text searched.
    fn body_start(&self, before: &str) -> usize {
        let open = match self {
            Self::Script => "<script",
            Self::Style => "<style",
        };
        match before.to_ascii_lowercase().rfind(open) {
            Some(at) => before[at..]
                .find('>')
                .map(|end| at + end + 1)
                .unwrap_or(before.len()),
            None => before.len(),
        }
    }
}

/// The script or style block a position sits inside, if any.
fn enclosing_block(before: &str) -> Option<Block> {
    let lower = before.to_ascii_lowercase();
    let script = lower.rfind("<script");
    let style = lower.rfind("<style");

    let candidate = match (script, style) {
        (Some(s), Some(t)) if s > t => (s, Block::Script),
        (Some(_), Some(t)) => (t, Block::Style),
        (Some(s), None) => (s, Block::Script),
        (None, Some(t)) => (t, Block::Style),
        (None, None) => return None,
    };

    let closing = match candidate.1 {
        Block::Script => "</script",
        Block::Style => "</style",
    };
    // Still open only if nothing closed it since.
    match lower[candidate.0..].contains(closing) {
        true => None,
        false => Some(candidate.1),
    }
}

/// The quote character of a string literal that is still open, if one is.
fn unterminated_quote(text: &str) -> Option<char> {
    let mut open: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match (open, c) {
            (_, '\\') => escaped = true,
            (None, '"') | (None, '\'') | (None, '`') => open = Some(c),
            (Some(quote), c) if c == quote => open = None,
            _ => {}
        }
    }
    open
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> Probe {
        Probe::seeded(1)
    }

    /// Places the probe's value into an HTML template at `{}`.
    fn responded(template: &str) -> (Probe, Survived) {
        served(template, Serving::Markup)
    }

    /// The same, under a stated content type.
    fn served(template: &str, serving: Serving) -> (Probe, Survived) {
        let probe = probe();
        let body = template.replace("{}", &probe.value());
        let found = probe.found_in(body.as_bytes(), serving);
        (probe, found)
    }

    // -----------------------------------------------------------------------
    // The probe itself
    // -----------------------------------------------------------------------

    #[test]
    fn the_two_tokens_differ_and_are_plain_enough_to_survive_any_encoding() {
        let probe = probe();
        assert_ne!(probe.prefix(), probe.suffix());
        for token in [probe.prefix(), probe.suffix()] {
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{token} would not survive percent-encoding intact"
            );
            assert!(
                token.len() >= 8,
                "{token} is short enough to appear by chance"
            );
        }
    }

    #[test]
    fn two_runs_get_different_tokens() {
        // A fixed marker compiled into the build would match a page that happens to
        // contain it, forever, for everybody.
        assert_ne!(Probe::seeded(1).value(), Probe::seeded(2).value());
    }

    #[test]
    fn a_value_that_does_not_come_back_establishes_nothing() {
        let found = probe().found_in(b"<html><body>nothing here</body></html>", Serving::Markup);
        assert!(!found.reflected());
        assert!(found.summary().is_none());
    }

    #[test]
    fn a_prefix_without_its_suffix_is_not_an_echo() {
        // A response that truncates the value, or reflects only part of it, has not
        // shown that the whole thing came through.
        let probe = probe();
        let body = format!("<div>{}</div>", probe.prefix());
        assert!(!probe.found_in(body.as_bytes(), Serving::Markup).reflected());
    }

    // -----------------------------------------------------------------------
    // What survived
    // -----------------------------------------------------------------------

    #[test]
    fn escaped_characters_are_reported_as_not_having_survived() {
        let probe = probe();
        let body = format!(
            "<div>{}&lt;&gt;&quot;&#39;&#96;;(){}</div>",
            probe.prefix(),
            probe.suffix()
        );
        let found = probe.found_in(body.as_bytes(), Serving::Markup);

        assert!(found.reflected());
        let survived = &found.echoes[0].survived;
        assert!(!survived.contains(&'<'), "{survived:?}");
        assert!(!survived.contains(&'>'), "{survived:?}");
        assert!(!survived.contains(&'"'), "{survived:?}");
        assert!(!survived.contains(&'\''), "{survived:?}");
        assert!(
            survived.contains(&';'),
            "the entity semicolons came through as themselves: {survived:?}"
        );
    }

    #[test]
    fn characters_that_came_back_as_themselves_are_listed() {
        let (_, found) = responded("<div>{}</div>");
        let survived = &found.echoes[0].survived;
        for expected in ['<', '>', '"', '\'', '`', ';', '(', ')'] {
            assert!(
                survived.contains(&expected),
                "{expected} was lost: {survived:?}"
            );
        }
    }

    #[test]
    fn the_returned_bytes_are_quoted_so_a_reader_can_disagree() {
        let (_, found) = responded("<div>{}</div>");
        assert_eq!(found.echoes[0].between, PROBE_CHARACTERS);
    }

    // -----------------------------------------------------------------------
    // Context
    // -----------------------------------------------------------------------

    #[test]
    fn html_text_is_recognised() {
        let (_, found) = responded("<html><body><div>{}</div></body></html>");
        assert_eq!(found.echoes[0].context, Context::HtmlText);
    }

    #[test]
    fn a_quoted_attribute_is_recognised_with_its_quote() {
        let (_, found) = responded("<html><input value=\"{}\"></html>");
        assert_eq!(
            found.echoes[0].context,
            Context::HtmlAttribute { quoted: Some('"') }
        );

        let (_, found) = responded("<html><input value='{}'></html>");
        assert_eq!(
            found.echoes[0].context,
            Context::HtmlAttribute { quoted: Some('\'') }
        );
    }

    #[test]
    fn an_unquoted_attribute_is_recognised_as_the_worse_case_it_is() {
        let (_, found) = responded("<html><input value={}></html>");
        assert_eq!(
            found.echoes[0].context,
            Context::HtmlAttribute { quoted: None }
        );
        // Nothing needs to survive for an unquoted attribute to matter — it ends at
        // the first space.
        assert!(why_it_matters('x', found.echoes[0].context).is_some());
    }

    #[test]
    fn a_string_inside_a_script_block_is_not_the_same_as_script_source() {
        let (_, found) = responded("<html><script>var x = \"{}\";</script></html>");
        assert_eq!(
            found.echoes[0].context,
            Context::ScriptString { quoted: '"' }
        );

        let (_, found) = responded("<html><script>var x = {};</script></html>");
        assert_eq!(found.echoes[0].context, Context::Script);
    }

    #[test]
    fn a_comment_wins_over_the_markup_around_it() {
        let (_, found) = responded("<html><div><!-- {} --></div></html>");
        assert_eq!(found.echoes[0].context, Context::HtmlComment);
    }

    #[test]
    fn a_style_block_is_recognised() {
        let (_, found) = responded("<html><style>.a { content: \"{}\" }</style></html>");
        assert_eq!(found.echoes[0].context, Context::Style);
    }

    #[test]
    fn a_closed_script_block_does_not_capture_what_comes_after_it() {
        let (_, found) = responded("<html><script>var a = 1;</script><div>{}</div></html>");
        assert_eq!(found.echoes[0].context, Context::HtmlText);
    }

    #[test]
    fn a_json_response_is_data_however_much_markup_is_in_the_value() {
        // The common case, and the one a scanner must not shout about: an API echoing
        // a parameter. Everything survived and it is still nothing on its own.
        let (_, found) = served(r#"{"query": "{}", "results": []}"#, Serving::Json);
        assert_eq!(found.echoes[0].context, Context::JsonString);
        assert!(!found.echoes[0].survived.is_empty());
        assert!(
            found.summary().is_none(),
            "a JSON echo must not produce a sentence that reads like a finding"
        );
    }

    #[test]
    fn the_same_bytes_served_as_html_are_a_different_fact() {
        // The reason the content type is a parameter rather than a guess. An API that
        // answers `text/html` to a JSON-shaped body is doing something a browser will
        // act on, and no amount of looking at the bytes would have told us.
        let body = r#"{"query": "{}", "results": []}"#;
        let (_, json) = served(body, Serving::Json);
        let (_, html) = served(body, Serving::Markup);

        assert_eq!(json.echoes[0].context, Context::JsonString);
        assert!(json.summary().is_none());

        assert_ne!(html.echoes[0].context, Context::JsonString);
        assert!(
            html.summary().is_some(),
            "served as markup, the same bytes are worth saying something about"
        );
    }

    #[test]
    fn a_content_type_nobody_renders_produces_no_opinion() {
        let (_, found) = served("<div>{}</div>", Serving::Other);
        assert_eq!(found.echoes[0].context, Context::Unknown);
        assert!(found.summary().is_none());
    }

    #[test]
    fn the_content_type_is_read_with_its_parameters() {
        assert_eq!(
            Serving::of(Some("text/html; charset=utf-8")),
            Serving::Markup
        );
        assert_eq!(Serving::of(Some("APPLICATION/JSON")), Serving::Json);
        assert_eq!(Serving::of(Some("application/vnd.api+json")), Serving::Json);
        assert_eq!(Serving::of(Some("text/plain")), Serving::Other);
        assert_eq!(Serving::of(None), Serving::Other);
    }

    #[test]
    fn a_place_this_cannot_identify_says_so() {
        // Served as something nobody renders. Under `text/html` the same bytes would
        // be HTML text, because a browser parses a `text/html` body as markup whether
        // or not a tag came first.
        let (_, found) = served(
            "plain text with no markup at all {} and more",
            Serving::Other,
        );
        assert_eq!(found.echoes[0].context, Context::Unknown);
        assert!(!found.echoes[0].context.worth_looking_at());

        let (_, found) = served(
            "plain text with no markup at all {} and more",
            Serving::Markup,
        );
        assert_eq!(found.echoes[0].context, Context::HtmlText);
    }

    // -----------------------------------------------------------------------
    // Several echoes
    // -----------------------------------------------------------------------

    #[test]
    fn each_place_it_came_back_is_its_own_fact() {
        let probe = probe();
        let value = probe.value();
        let body = format!(
            "<html><input value=\"{value}\"><div>{value}</div>\
             <script>var x = \"{value}\";</script></html>"
        );
        let found = probe.found_in(body.as_bytes(), Serving::Markup);

        assert_eq!(found.echoes.len(), 3, "{:#?}", found.echoes);
        assert_eq!(
            found.echoes[0].context,
            Context::HtmlAttribute { quoted: Some('"') }
        );
        assert_eq!(found.echoes[1].context, Context::HtmlText);
        assert_eq!(
            found.echoes[2].context,
            Context::ScriptString { quoted: '"' }
        );
    }

    #[test]
    fn the_summary_names_the_character_and_where_it_landed() {
        let (_, found) = responded("<html><div>{}</div></html>");
        let summary = found.summary().expect("something worth saying");
        assert!(summary.contains('<'), "{summary}");
        assert!(summary.contains("HTML text"), "{summary}");
        assert!(
            !summary.to_lowercase().contains("cross-site")
                && !summary.to_lowercase().contains("xss")
                && !summary.to_lowercase().contains("vulnerab"),
            "this module states facts about bytes, never a verdict: {summary}"
        );
    }

    #[test]
    fn an_echo_where_nothing_dangerous_survived_is_not_notable() {
        let probe = probe();
        let body = format!(
            "<div>{}&lt;&gt;&quot;&#39;{}</div>",
            probe.prefix(),
            probe.suffix()
        );
        let found = probe.found_in(body.as_bytes(), Serving::Markup);
        assert!(found.reflected());
        assert_eq!(found.notable().count(), 0, "{:#?}", found.echoes);
        assert!(found.summary().is_none());
    }

    #[test]
    fn hostile_input_does_not_panic() {
        let probe = probe();
        for body in [
            "".to_string(),
            "<".repeat(5000),
            format!("<!--{}", probe.value()),
            format!("<script>'{}", probe.value()),
            format!("<input value=\"{}", probe.value()),
            format!("{}{}", probe.value(), probe.value()),
            format!("{}{}", probe.suffix(), probe.prefix()),
        ] {
            for serving in [Serving::Markup, Serving::Json, Serving::Other] {
                let _ = probe.found_in(body.as_bytes(), serving);
            }
        }
        let _ = probe.found_in(&[0xff, 0xfe, 0x00], Serving::Markup);
    }
}
