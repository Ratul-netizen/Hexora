//! # hexora-import
//!
//! Reads an API description and turns it into the requests it implies — Hexora's answer to
//! Burp's and Postman's "import an OpenAPI file", and the frontier a crawler cannot find because
//! an API has no HTML links to follow.
//!
//! Supports **OpenAPI 3.x** and **Swagger 2.0**, in JSON or YAML. The output is a list of
//! [`Operation`]s with their target already built: path parameters filled with a placeholder,
//! required query parameters appended. The caller decides whether to send them (through the
//! scope guard, like the crawler) or just list them.
//!
//! # It fills, it does not invent
//!
//! A path parameter with no example becomes `1` for an integer, `test` for a string — a value
//! that lets the request be *sent*, clearly a placeholder, never a guess at real data. Where the
//! spec gives an `example`, `default` or `enum`, that is used instead, because the spec's own
//! value is more likely to reach a real code path than a placeholder is.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

use serde_json::Value;

/// The HTTP methods an operation object may key, in a stable order.
const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];

/// One operation the spec describes, with its request target built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// The method, upper-cased (`GET`).
    pub method: String,
    /// The path template as written in the spec (`/users/{id}`).
    pub template: String,
    /// The request target: the template with path parameters filled and required query
    /// parameters appended (`/users/1?verbose=true`).
    pub target: String,
    /// The operation's summary or operationId, when the spec gives one.
    pub summary: Option<String>,
    /// Whether the method carries a body by convention (POST/PUT/PATCH).
    pub has_body: bool,
}

/// A parsed API description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSpec {
    /// The API title, when the spec gives one.
    pub title: Option<String>,
    /// The server base URLs the spec declares. May be empty (then the caller supplies a base).
    pub servers: Vec<String>,
    /// Every operation, in document order.
    pub operations: Vec<Operation>,
}

/// A spec that could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportError {
    /// Why the spec is invalid.
    pub message: String,
}

impl ImportError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ImportError {}

/// Parses an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML) into its operations.
pub fn parse(bytes: &[u8]) -> Result<ApiSpec, ImportError> {
    // JSON first (a subset of YAML, but a dedicated parser gives better errors), then YAML.
    let root: Value = match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => value,
        Err(_) => serde_yaml_ng::from_slice::<Value>(bytes)
            .map_err(|e| ImportError::new(format!("not valid JSON or YAML: {e}")))?,
    };
    from_value(root)
}

/// Turns a parsed document tree into an [`ApiSpec`].
fn from_value(root: Value) -> Result<ApiSpec, ImportError> {
    let obj = root
        .as_object()
        .ok_or_else(|| ImportError::new("the document is not an object"))?;

    let is_swagger2 = obj.get("swagger").and_then(Value::as_str).is_some();
    let title = obj
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let servers = if is_swagger2 {
        swagger2_servers(obj)
    } else {
        openapi3_servers(obj)
    };

    let paths = obj
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| ImportError::new("the spec has no `paths` object"))?;

    let mut operations = Vec::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        // Parameters declared once for the whole path apply to every method under it.
        let path_level = item.get("parameters").and_then(Value::as_array);

        for method in METHODS {
            let Some(op) = item.get(*method).and_then(Value::as_object) else {
                continue;
            };
            let mut params: Vec<&Value> = Vec::new();
            if let Some(shared) = path_level {
                params.extend(shared.iter());
            }
            if let Some(own) = op.get("parameters").and_then(Value::as_array) {
                params.extend(own.iter());
            }

            let target = build_target(path, &params);
            let summary = op
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| op.get("operationId").and_then(Value::as_str))
                .map(str::to_string);

            operations.push(Operation {
                method: method.to_uppercase(),
                template: path.clone(),
                target,
                summary,
                has_body: matches!(*method, "post" | "put" | "patch"),
            });
        }
    }

    if operations.is_empty() {
        return Err(ImportError::new(
            "the spec declared no operations under `paths`",
        ));
    }

    Ok(ApiSpec {
        title,
        servers,
        operations,
    })
}

/// OpenAPI 3 `servers[].url`.
fn openapi3_servers(obj: &serde_json::Map<String, Value>) -> Vec<String> {
    obj.get("servers")
        .and_then(Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|s| s.get("url").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Swagger 2 builds a base from `schemes`, `host` and `basePath`.
fn swagger2_servers(obj: &serde_json::Map<String, Value>) -> Vec<String> {
    let Some(host) = obj.get("host").and_then(Value::as_str) else {
        return Vec::new();
    };
    let base_path = obj.get("basePath").and_then(Value::as_str).unwrap_or("");
    let schemes: Vec<&str> = obj
        .get("schemes")
        .and_then(Value::as_array)
        .map(|s| s.iter().filter_map(Value::as_str).collect())
        .unwrap_or_else(|| vec!["https"]);
    schemes
        .iter()
        .map(|scheme| format!("{scheme}://{host}{base_path}"))
        .collect()
}

/// Builds a request target from a path template and its parameters: path parameters filled in,
/// required query parameters appended.
fn build_target(template: &str, params: &[&Value]) -> String {
    let mut path = template.to_string();
    let mut query: Vec<String> = Vec::new();

    for param in params {
        let Some(name) = param.get("name").and_then(Value::as_str) else {
            continue;
        };
        let location = param.get("in").and_then(Value::as_str).unwrap_or("");
        match location {
            "path" => {
                let value = placeholder(param);
                path = path.replace(&format!("{{{name}}}"), &percent_encode(&value));
            }
            "query" => {
                let required = param
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if required {
                    query.push(format!(
                        "{}={}",
                        percent_encode(name),
                        percent_encode(&placeholder(param))
                    ));
                }
            }
            _ => {}
        }
    }

    if query.is_empty() {
        path
    } else {
        format!("{path}?{}", query.join("&"))
    }
}

/// A value for a parameter: the spec's own example/default/enum if it has one, else a clearly
/// synthetic placeholder chosen by declared type.
fn placeholder(param: &Value) -> String {
    // OpenAPI 3 nests the type under `schema`; Swagger 2 puts `type`/`example` on the param.
    let schema = param.get("schema").unwrap_or(param);

    for source in [
        param.get("example"),
        schema.get("example"),
        schema.get("default"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(s) = scalar(source) {
            return s;
        }
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
    {
        if let Some(s) = scalar(first) {
            return s;
        }
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("integer") | Some("number") => "1".to_string(),
        Some("boolean") => "true".to_string(),
        _ => "test".to_string(),
    }
}

/// A scalar JSON value as a string, or `None` for arrays/objects/null.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Percent-encodes a value for a path segment or query string.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAPI3: &str = r#"{
        "openapi": "3.0.0",
        "info": {"title": "Demo API"},
        "servers": [{"url": "https://api.example.com/v1"}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "summary": "Get a user",
                    "parameters": [
                        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
                        {"name": "verbose", "in": "query", "required": true, "schema": {"type": "boolean"}},
                        {"name": "trace", "in": "query", "required": false, "schema": {"type": "boolean"}}
                    ]
                },
                "delete": {"operationId": "deleteUser"}
            },
            "/health": {"get": {}}
        }
    }"#;

    #[test]
    fn parses_openapi3_operations_and_server() {
        let spec = parse(OPENAPI3.as_bytes()).unwrap();
        assert_eq!(spec.title.as_deref(), Some("Demo API"));
        assert_eq!(spec.servers, vec!["https://api.example.com/v1"]);
        assert_eq!(
            spec.operations.len(),
            3,
            "GET+DELETE on users, GET on health"
        );
    }

    #[test]
    fn fills_path_params_and_required_query_only() {
        let spec = parse(OPENAPI3.as_bytes()).unwrap();
        let get_user = spec
            .operations
            .iter()
            .find(|o| o.method == "GET" && o.template == "/users/{id}")
            .unwrap();
        // Path param filled (integer -> 1), required query kept, optional query dropped.
        assert_eq!(get_user.target, "/users/1?verbose=true");
        assert_eq!(get_user.summary.as_deref(), Some("Get a user"));
        assert!(!get_user.has_body);
    }

    #[test]
    fn a_spec_example_beats_the_placeholder() {
        let spec = parse(
            br#"{"openapi":"3.0.0","paths":{"/u/{id}":{"get":{"parameters":[
                {"name":"id","in":"path","required":true,"schema":{"type":"string","example":"alice"}}]}}}}"#,
        )
        .unwrap();
        assert_eq!(spec.operations[0].target, "/u/alice");
    }

    #[test]
    fn post_is_marked_as_body_bearing() {
        let spec =
            parse(br#"{"openapi":"3.0.0","paths":{"/things":{"post":{"summary":"create"}}}}"#)
                .unwrap();
        assert!(spec.operations[0].has_body);
        assert_eq!(spec.operations[0].method, "POST");
    }

    #[test]
    fn swagger2_builds_a_base_from_host_and_basepath() {
        let spec = parse(
            br#"{"swagger":"2.0","host":"api.example.com","basePath":"/v2","schemes":["https"],
                "paths":{"/ping":{"get":{}}}}"#,
        )
        .unwrap();
        assert_eq!(spec.servers, vec!["https://api.example.com/v2"]);
        assert_eq!(spec.operations.len(), 1);
    }

    #[test]
    fn yaml_is_accepted_too() {
        let yaml = "openapi: 3.0.0\npaths:\n  /y:\n    get:\n      summary: yaml op\n";
        let spec = parse(yaml.as_bytes()).unwrap();
        assert_eq!(spec.operations.len(), 1);
        assert_eq!(spec.operations[0].summary.as_deref(), Some("yaml op"));
    }

    #[test]
    fn path_level_parameters_apply_to_each_method() {
        let spec = parse(
            br#"{"openapi":"3.0.0","paths":{"/x/{id}":{
                "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],
                "get":{},"delete":{}}}}"#,
        )
        .unwrap();
        assert!(spec.operations.iter().all(|o| o.target == "/x/1"));
    }

    #[test]
    fn a_spec_with_no_paths_is_an_error() {
        assert!(parse(br#"{"openapi":"3.0.0","info":{"title":"x"}}"#).is_err());
    }

    #[test]
    fn garbage_is_a_clean_error_not_a_panic() {
        assert!(parse(b"\x00\x01 not a spec").is_err());
        assert!(parse(b"[]").is_err());
    }
}
