//! # nullhawk-query
//!
//! A small query language over captured traffic — Nullhawk's answer to Burp's Bambda filters
//! and Caido's HTTPQL. A tester types a filter and the history shows only the rows that match:
//!
//! ```text
//! status >= 500
//! host:*.target.com AND resp.body:"stack trace"
//! method=POST AND (resp.header ~ "set-cookie" OR req.header:authorization)
//! NOT ext:png
//! ```
//!
//! # Shape
//!
//! A query is boolean logic over **clauses**. A clause is `field OP value`. Clauses combine
//! with `AND`, `OR`, `NOT` and parentheses; two clauses side by side are an implicit `AND`, so
//! `status=200 host:api` reads the way a tester expects. `NOT` binds tightest, then `AND`, then
//! `OR`.
//!
//! # Operators
//!
//! - `:`  — contains (case-insensitive substring). The everyday one.
//! - `=` / `!=` — equals / not equals (case-insensitive for text, numeric for numbers).
//! - `>` `<` `>=` `<=` — numeric comparison, for `status`, `port`, `req.size`, `resp.size`,
//!   `duration`.
//! - `~` / `!~` — regular expression matches / does not match.
//!
//! # Fields
//!
//! `method`, `host`, `path`, `url`, `scheme`, `port`, `ext`, `status` (alias `code`),
//! `duration`, `identity`, `origin`, `secure`, `req.size`, `resp.size`, and the header/body
//! fields `req.header`, `resp.header`, `req.body`, `resp.body`. A header field matches against
//! each `Name: value` line, so `req.header:authorization` finds a request that carries one.
//!
//! # Cost
//!
//! Bodies and the full request are expensive to read back, so a [`Query`] reports which it
//! actually needs ([`Query::uses_request_detail`], [`Query::uses_response_headers`],
//! [`Query::uses_response_body`]). A caller loads only those, and only for the rows it is about
//! to test — a query that never mentions a body never pays to read one.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use regex::Regex;

/// A field a clause can address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// The request method (`GET`, `POST`, …).
    Method,
    /// The target host.
    Host,
    /// The request path (with query string).
    Path,
    /// The full absolute URL.
    Url,
    /// `http` or `https`.
    Scheme,
    /// The target port.
    Port,
    /// The path's file extension, without the dot (`js`, `png`), empty when there is none.
    Ext,
    /// The response status code.
    Status,
    /// Round-trip time in milliseconds.
    Duration,
    /// The identity label the request was sent as.
    Identity,
    /// Which subsystem sent it (`proxy`, `scanner`, …).
    Origin,
    /// Whether the connection was TLS (`true`/`false`).
    Secure,
    /// The request body size in bytes.
    RequestSize,
    /// The response body size in bytes.
    ResponseSize,
    /// A request header line (`Name: value`).
    RequestHeader,
    /// A response header line (`Name: value`).
    ResponseHeader,
    /// The request body, as text.
    RequestBody,
    /// The response body, as text.
    ResponseBody,
}

impl Field {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "method" => Some(Field::Method),
            "host" => Some(Field::Host),
            "path" => Some(Field::Path),
            "url" => Some(Field::Url),
            "scheme" => Some(Field::Scheme),
            "port" => Some(Field::Port),
            "ext" => Some(Field::Ext),
            "status" | "code" => Some(Field::Status),
            "duration" => Some(Field::Duration),
            "identity" => Some(Field::Identity),
            "origin" => Some(Field::Origin),
            "secure" => Some(Field::Secure),
            "req.size" | "request.size" => Some(Field::RequestSize),
            "resp.size" | "response.size" => Some(Field::ResponseSize),
            "req.header" | "request.header" => Some(Field::RequestHeader),
            "resp.header" | "response.header" => Some(Field::ResponseHeader),
            "req.body" | "request.body" => Some(Field::RequestBody),
            "resp.body" | "response.body" => Some(Field::ResponseBody),
            _ => None,
        }
    }

    fn is_numeric(self) -> bool {
        matches!(
            self,
            Field::Port
                | Field::Status
                | Field::Duration
                | Field::RequestSize
                | Field::ResponseSize
        )
    }
}

/// A comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Case-insensitive substring.
    Contains,
    /// Equals (case-insensitive text, or numeric).
    Eq,
    /// Not equals.
    Ne,
    /// Greater than (numeric).
    Gt,
    /// Less than (numeric).
    Lt,
    /// Greater than or equal (numeric).
    Ge,
    /// Less than or equal (numeric).
    Le,
    /// Regular expression matches.
    Regex,
    /// Regular expression does not match.
    NotRegex,
}

/// One `field OP value` test, with any regex compiled ahead of time.
#[derive(Debug)]
struct Clause {
    field: Field,
    op: Op,
    value: String,
    regex: Option<Regex>,
}

/// A parsed query: boolean logic over clauses.
#[derive(Debug)]
enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    Clause(Clause),
}

/// A compiled query, ready to test records against.
#[derive(Debug)]
pub struct Query {
    root: Expr,
}

/// The fields of one captured exchange the evaluator reads.
///
/// The cheap fields are always set from the history row; the lazy ones ([`request_headers`],
/// [`request_body`], [`response_headers`], [`response_body`], [`origin`], [`request_size`]) are
/// filled only when the query needs them, which is why they are optional.
#[derive(Debug, Default, Clone)]
pub struct Record {
    /// The request method.
    pub method: String,
    /// The target host.
    pub host: String,
    /// The request path with query string.
    pub path: String,
    /// The full URL.
    pub url: String,
    /// `http` or `https`.
    pub scheme: String,
    /// The target port.
    pub port: u16,
    /// The response status, if any.
    pub status: Option<u16>,
    /// Round-trip time in ms, if measured.
    pub duration_ms: Option<u32>,
    /// The identity label, if sent as one.
    pub identity: Option<String>,
    /// Whether the connection was TLS.
    pub secure: bool,
    /// The response body size.
    pub response_size: u64,
    /// Which subsystem sent it (lazy).
    pub origin: Option<String>,
    /// The request body size (lazy).
    pub request_size: Option<u64>,
    /// Request header lines `Name: value` (lazy).
    pub request_headers: Option<Vec<String>>,
    /// Response header lines `Name: value` (lazy).
    pub response_headers: Option<Vec<String>>,
    /// The request body as text (lazy).
    pub request_body: Option<String>,
    /// The response body as text (lazy).
    pub response_body: Option<String>,
}

impl Record {
    /// The path's file extension without the dot, or empty.
    fn ext(&self) -> &str {
        let path = self.path.split(['?', '#']).next().unwrap_or(&self.path);
        let last = path.rsplit('/').next().unwrap_or(path);
        match last.rsplit_once('.') {
            Some((_, ext)) if !ext.is_empty() => ext,
            _ => "",
        }
    }
}

impl Query {
    /// Parses a query string, compiling any regexes so a bad pattern is reported now.
    pub fn parse(input: &str) -> Result<Query, ParseError> {
        let tokens = lex(input)?;
        let mut parser = Parser { tokens, pos: 0 };
        let root = parser.parse_or()?;
        if parser.pos != parser.tokens.len() {
            return Err(ParseError::new(format!(
                "unexpected `{}` after the query",
                parser.tokens[parser.pos].text()
            )));
        }
        Ok(Query { root })
    }

    /// Whether the query needs the full request read back (its headers, body, size, or origin).
    pub fn uses_request_detail(&self) -> bool {
        self.uses(&[
            Field::RequestHeader,
            Field::RequestBody,
            Field::RequestSize,
            Field::Origin,
        ])
    }

    /// Whether the query needs the response header block.
    pub fn uses_response_headers(&self) -> bool {
        self.uses(&[Field::ResponseHeader])
    }

    /// Whether the query needs the response body.
    pub fn uses_response_body(&self) -> bool {
        self.uses(&[Field::ResponseBody])
    }

    /// Whether the query mentions a given field anywhere.
    pub fn references(&self, field: Field) -> bool {
        self.uses(&[field])
    }

    fn uses(&self, fields: &[Field]) -> bool {
        fn walk(expr: &Expr, fields: &[Field]) -> bool {
            match expr {
                Expr::Clause(c) => fields.contains(&c.field),
                Expr::Not(inner) => walk(inner, fields),
                Expr::All(list) | Expr::Any(list) => list.iter().any(|e| walk(e, fields)),
            }
        }
        walk(&self.root, fields)
    }

    /// Whether a record matches the query.
    pub fn matches(&self, record: &Record) -> bool {
        eval(&self.root, record)
    }
}

fn eval(expr: &Expr, record: &Record) -> bool {
    match expr {
        Expr::All(list) => list.iter().all(|e| eval(e, record)),
        Expr::Any(list) => list.iter().any(|e| eval(e, record)),
        Expr::Not(inner) => !eval(inner, record),
        Expr::Clause(clause) => eval_clause(clause, record),
    }
}

fn eval_clause(clause: &Clause, record: &Record) -> bool {
    // Header fields test each `Name: value` line and pass if any line matches.
    match clause.field {
        Field::RequestHeader => {
            return match &record.request_headers {
                Some(lines) => lines.iter().any(|line| text_match(clause, line)),
                None => false,
            }
        }
        Field::ResponseHeader => {
            return match &record.response_headers {
                Some(lines) => lines.iter().any(|line| text_match(clause, line)),
                None => false,
            }
        }
        _ => {}
    }

    if clause.field.is_numeric() {
        let lhs = match clause.field {
            Field::Port => Some(i64::from(record.port)),
            Field::Status => record.status.map(i64::from),
            Field::Duration => record.duration_ms.map(i64::from),
            Field::RequestSize => record.request_size.map(|s| s as i64),
            Field::ResponseSize => Some(record.response_size as i64),
            _ => None,
        };
        return match (lhs, clause.value.parse::<i64>()) {
            (Some(lhs), Ok(rhs)) => numeric_match(clause.op, lhs, rhs),
            _ => false,
        };
    }

    // Text fields.
    let haystack: Option<String> = match clause.field {
        Field::Method => Some(record.method.clone()),
        Field::Host => Some(record.host.clone()),
        Field::Path => Some(record.path.clone()),
        Field::Url => Some(record.url.clone()),
        Field::Scheme => Some(record.scheme.clone()),
        Field::Ext => Some(record.ext().to_string()),
        Field::Identity => record.identity.clone(),
        Field::Origin => record.origin.clone(),
        Field::Secure => Some(record.secure.to_string()),
        Field::RequestBody => record.request_body.clone(),
        Field::ResponseBody => record.response_body.clone(),
        _ => None,
    };
    match haystack {
        Some(text) => text_match(clause, &text),
        None => false,
    }
}

fn numeric_match(op: Op, lhs: i64, rhs: i64) -> bool {
    match op {
        Op::Eq => lhs == rhs,
        Op::Ne => lhs != rhs,
        Op::Gt => lhs > rhs,
        Op::Lt => lhs < rhs,
        Op::Ge => lhs >= rhs,
        Op::Le => lhs <= rhs,
        // A substring or regex operator on a number tests its decimal text.
        _ => text_op(op, &lhs.to_string(), rhs.to_string().as_str(), None),
    }
}

fn text_match(clause: &Clause, haystack: &str) -> bool {
    text_op(clause.op, haystack, &clause.value, clause.regex.as_ref())
}

fn text_op(op: Op, haystack: &str, needle: &str, regex: Option<&Regex>) -> bool {
    match op {
        Op::Contains => haystack.to_lowercase().contains(&needle.to_lowercase()),
        Op::Eq => haystack.eq_ignore_ascii_case(needle),
        Op::Ne => !haystack.eq_ignore_ascii_case(needle),
        Op::Gt | Op::Lt | Op::Ge | Op::Le => false, // numeric operators on non-numeric text
        Op::Regex => regex.map(|re| re.is_match(haystack)).unwrap_or(false),
        Op::NotRegex => regex.map(|re| !re.is_match(haystack)).unwrap_or(false),
    }
}

// ---------------------------------------------------------------------------
// Lexing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Op(Op),
    Word(String),
}

impl Token {
    fn text(&self) -> String {
        match self {
            Token::LParen => "(".into(),
            Token::RParen => ")".into(),
            Token::And => "AND".into(),
            Token::Or => "OR".into(),
            Token::Not => "NOT".into(),
            Token::Op(_) => "operator".into(),
            Token::Word(w) => w.clone(),
        }
    }
}

/// A query that could not be parsed, with a human reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Why the query is invalid.
    pub message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

fn lex(input: &str) -> Result<Vec<Token>, ParseError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '"' | '\'' => {
                // A quoted string, taken verbatim to the matching quote.
                let quote = c;
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(ParseError::new(
                        "a quoted value is missing its closing quote",
                    ));
                }
                i += 1; // closing quote
                tokens.push(Token::Word(s));
            }
            ':' => {
                tokens.push(Token::Op(Op::Contains));
                i += 1;
            }
            '=' => {
                tokens.push(Token::Op(Op::Eq));
                i += 1;
            }
            '~' => {
                tokens.push(Token::Op(Op::Regex));
                i += 1;
            }
            '!' => {
                if peek(&chars, i + 1) == Some('=') {
                    tokens.push(Token::Op(Op::Ne));
                    i += 2;
                } else if peek(&chars, i + 1) == Some('~') {
                    tokens.push(Token::Op(Op::NotRegex));
                    i += 2;
                } else {
                    tokens.push(Token::Not);
                    i += 1;
                }
            }
            '>' => {
                if peek(&chars, i + 1) == Some('=') {
                    tokens.push(Token::Op(Op::Ge));
                    i += 2;
                } else {
                    tokens.push(Token::Op(Op::Gt));
                    i += 1;
                }
            }
            '<' => {
                if peek(&chars, i + 1) == Some('=') {
                    tokens.push(Token::Op(Op::Le));
                    i += 2;
                } else {
                    tokens.push(Token::Op(Op::Lt));
                    i += 1;
                }
            }
            '&' if peek(&chars, i + 1) == Some('&') => {
                tokens.push(Token::And);
                i += 2;
            }
            '|' if peek(&chars, i + 1) == Some('|') => {
                tokens.push(Token::Or);
                i += 2;
            }
            _ => {
                // A bare word: up to whitespace, a paren, or an operator character.
                let start = i;
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_whitespace()
                        || matches!(c, '(' | ')' | ':' | '=' | '~' | '>' | '<')
                        || (c == '!' && matches!(peek(&chars, i + 1), Some('=') | Some('~')))
                    {
                        break;
                    }
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.to_ascii_uppercase().as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "NOT" => tokens.push(Token::Not),
                    _ => tokens.push(Token::Word(word)),
                }
            }
        }
    }
    Ok(tokens)
}

fn peek(chars: &[char], i: usize) -> Option<char> {
    chars.get(i).copied()
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// `or := and ( OR and )*`
    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.parse_and()?];
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            parts.push(self.parse_and()?);
        }
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expr::Any(parts)
        })
    }

    /// `and := unary ( AND? unary )*` — juxtaposition is an implicit AND.
    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.parse_unary()?];
        loop {
            match self.peek() {
                Some(Token::And) => {
                    self.advance();
                    parts.push(self.parse_unary()?);
                }
                // Implicit AND: another clause or `(` or `NOT` starts here.
                Some(Token::Word(_)) | Some(Token::LParen) | Some(Token::Not) => {
                    parts.push(self.parse_unary()?);
                }
                _ => break,
            }
        }
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expr::All(parts)
        })
    }

    /// `unary := NOT unary | ( or ) | clause`
    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::Not) => {
                self.advance();
                Ok(Expr::Not(Box::new(self.parse_unary()?)))
            }
            Some(Token::LParen) => {
                self.advance();
                let inner = self.parse_or()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(inner),
                    _ => Err(ParseError::new("missing a closing `)`")),
                }
            }
            _ => self.parse_clause(),
        }
    }

    /// `clause := WORD OP WORD`
    fn parse_clause(&mut self) -> Result<Expr, ParseError> {
        let field_tok = self
            .advance()
            .ok_or_else(|| ParseError::new("the query is empty"))?;
        let name = match field_tok {
            Token::Word(w) => w,
            other => {
                return Err(ParseError::new(format!(
                    "expected a field name, found `{}`",
                    other.text()
                )))
            }
        };
        let field = Field::parse(&name).ok_or_else(|| {
            ParseError::new(format!(
                "unknown field `{name}`. Known fields: method, host, path, url, scheme, port, \
                 ext, status, duration, identity, origin, secure, req.size, resp.size, \
                 req.header, resp.header, req.body, resp.body"
            ))
        })?;

        let op = match self.advance() {
            Some(Token::Op(op)) => op,
            other => {
                return Err(ParseError::new(format!(
                    "expected an operator after `{name}`, found `{}`",
                    other
                        .map(|t| t.text())
                        .unwrap_or_else(|| "end of query".into())
                )))
            }
        };

        let value = match self.advance() {
            Some(Token::Word(w)) => w,
            other => {
                return Err(ParseError::new(format!(
                    "expected a value after the operator on `{name}`, found `{}`",
                    other
                        .map(|t| t.text())
                        .unwrap_or_else(|| "end of query".into())
                )))
            }
        };

        // Guard mismatches early so the query fails when written, not silently at eval.
        if matches!(op, Op::Gt | Op::Lt | Op::Ge | Op::Le) && !field.is_numeric() {
            return Err(ParseError::new(format!(
                "`{name}` is not a numeric field, so `> < >= <=` do not apply to it"
            )));
        }

        let regex = if matches!(op, Op::Regex | Op::NotRegex) {
            Some(
                Regex::new(&value)
                    .map_err(|e| ParseError::new(format!("invalid regex in the query: {e}")))?,
            )
        } else {
            None
        };

        Ok(Expr::Clause(Clause {
            field,
            op,
            value,
            regex,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            method: "GET".into(),
            host: "api.target.com".into(),
            path: "/v1/users?page=2".into(),
            url: "https://api.target.com/v1/users?page=2".into(),
            scheme: "https".into(),
            port: 443,
            status: Some(200),
            duration_ms: Some(42),
            identity: Some("userA".into()),
            secure: true,
            response_size: 1500,
            origin: Some("proxy".into()),
            request_size: Some(0),
            request_headers: Some(vec![
                "Authorization: Bearer abc".into(),
                "Accept: application/json".into(),
            ]),
            response_headers: Some(vec![
                "Content-Type: application/json".into(),
                "Set-Cookie: s=1".into(),
            ]),
            request_body: Some(String::new()),
            response_body: Some(r#"{"users":[{"token":"xyz"}]}"#.into()),
        }
    }

    fn matches(q: &str) -> bool {
        Query::parse(q).unwrap().matches(&record())
    }

    #[test]
    fn a_contains_clause_is_case_insensitive() {
        assert!(matches("host:TARGET"));
        assert!(matches("method:get"));
        assert!(!matches("host:example"));
    }

    #[test]
    fn numeric_comparison_works_on_status() {
        assert!(matches("status=200"));
        assert!(matches("status>=200"));
        assert!(matches("status<300"));
        assert!(!matches("status>200"));
        assert!(matches("status!=404"));
    }

    #[test]
    fn implicit_and_requires_every_clause() {
        assert!(matches("status=200 host:target"));
        assert!(!matches("status=200 host:nope"));
    }

    #[test]
    fn explicit_or_needs_one() {
        assert!(matches("status=500 OR status=200"));
        assert!(!matches("status=500 OR status=404"));
    }

    #[test]
    fn not_negates() {
        assert!(matches("NOT status=500"));
        assert!(!matches("NOT status=200"));
    }

    #[test]
    fn parentheses_group() {
        assert!(matches("method=GET AND (status=500 OR status=200)"));
        assert!(!matches("method=POST AND (status=500 OR status=200)"));
    }

    #[test]
    fn header_fields_match_any_line() {
        assert!(matches("req.header:authorization"));
        assert!(matches("resp.header:set-cookie"));
        assert!(!matches("req.header:x-nope"));
    }

    #[test]
    fn body_and_regex() {
        assert!(matches(r#"resp.body:token"#));
        assert!(Query::parse(r"resp.body ~ tok.n")
            .unwrap()
            .matches(&record()));
        // `host` is api.target.com, which does not contain "example".
        assert!(Query::parse(r"host !~ example").unwrap().matches(&record()));
    }

    #[test]
    fn ext_is_the_path_extension() {
        let mut r = record();
        r.path = "/assets/app.min.js".into();
        assert!(Query::parse("ext=js").unwrap().matches(&r));
        assert!(!Query::parse("ext=png").unwrap().matches(&r));
    }

    #[test]
    fn quoted_values_keep_their_spaces() {
        let mut r = record();
        r.response_body = Some("a stack trace here".into());
        assert!(Query::parse(r#"resp.body:"stack trace""#)
            .unwrap()
            .matches(&r));
    }

    #[test]
    fn usage_flags_reflect_the_query() {
        let q = Query::parse("status=200").unwrap();
        assert!(!q.uses_response_body() && !q.uses_request_detail() && !q.uses_response_headers());

        let q = Query::parse("resp.body:token").unwrap();
        assert!(q.uses_response_body());
        assert!(!q.uses_request_detail());

        let q = Query::parse("req.header:authorization OR resp.header:set-cookie").unwrap();
        assert!(q.uses_request_detail());
        assert!(q.uses_response_headers());
        assert!(!q.uses_response_body());
    }

    #[test]
    fn unknown_field_is_rejected_with_a_helpful_message() {
        let err = Query::parse("bogus=1").unwrap_err();
        assert!(err.message.contains("unknown field"), "{}", err.message);
    }

    #[test]
    fn a_numeric_operator_on_text_is_rejected() {
        assert!(Query::parse("host>2").is_err());
    }

    #[test]
    fn an_invalid_regex_is_rejected_at_parse_time() {
        assert!(Query::parse("host ~ (unclosed").is_err());
    }

    #[test]
    fn an_unclosed_group_is_rejected() {
        assert!(Query::parse("(status=200").is_err());
        assert!(Query::parse("status=200)").is_err());
    }

    #[test]
    fn a_lazy_field_that_was_not_loaded_does_not_match() {
        let mut r = record();
        r.response_body = None;
        assert!(!Query::parse("resp.body:token").unwrap().matches(&r));
    }
}
