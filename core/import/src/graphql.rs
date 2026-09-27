//! GraphQL import from an introspection result.
//!
//! A GraphQL API exposes one endpoint and a schema. The standard **introspection query** returns
//! that schema as JSON; this reads it and generates a sendable operation for each root field of
//! `Query` (and, when asked, `Mutation`) — required arguments filled with placeholders, a minimal
//! selection set (`{ __typename }`) where the field returns an object. The caller POSTs each one
//! to the endpoint, the same way the OpenAPI importer fetches REST operations.
//!
//! # It reaches each resolver once
//!
//! The generated queries are deliberately shallow: one level, `__typename` for objects, no
//! recursion into the type graph. That is enough to make the server run each resolver — which is
//! what feeds the scanner — without building queries so deep they never parse or never return.

use serde_json::Value;

use crate::ImportError;

/// One GraphQL operation the schema implies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlOp {
    /// `query` or `mutation`.
    pub kind: String,
    /// The root field this operation exercises.
    pub field: String,
    /// The GraphQL document to send (`query { field { __typename } }`).
    pub document: String,
    /// The JSON request body: `{"query": <document>}`.
    pub body: String,
}

impl GraphqlOp {
    /// Whether this operation changes data (a mutation).
    pub fn is_mutation(&self) -> bool {
        self.kind == "mutation"
    }
}

/// The operations parsed from an introspection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlApi {
    /// The `query` and `mutation` root-field operations, in schema order.
    pub operations: Vec<GraphqlOp>,
}

/// Parses a GraphQL introspection result (JSON) into its root-field operations.
pub fn parse_introspection(bytes: &[u8]) -> Result<GraphqlApi, ImportError> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| ImportError::new(format!("not valid JSON: {e}")))?;

    // Introspection results are usually wrapped in `data`; accept either.
    let schema = root
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| root.get("__schema"))
        .and_then(Value::as_object)
        .ok_or_else(|| ImportError::new("no __schema in the introspection result"))?;

    let types = schema
        .get("types")
        .and_then(Value::as_array)
        .ok_or_else(|| ImportError::new("the schema has no types"))?;

    // name -> the OBJECT type's field list, for the root types.
    let find_type = |name: &str| -> Option<&Value> {
        types
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(name))
    };

    let mut operations = Vec::new();
    for (root_key, kind) in [("queryType", "query"), ("mutationType", "mutation")] {
        let Some(type_name) = schema
            .get(root_key)
            .and_then(|t| t.get("name"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(fields) = find_type(type_name)
            .and_then(|t| t.get("fields"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for field in fields {
            if let Some(op) = operation_for(field, kind) {
                operations.push(op);
            }
        }
    }

    if operations.is_empty() {
        return Err(ImportError::new(
            "the schema declared no query or mutation root fields",
        ));
    }
    Ok(GraphqlApi { operations })
}

/// Builds an operation for one root field.
fn operation_for(field: &Value, kind: &str) -> Option<GraphqlOp> {
    let name = field.get("name").and_then(Value::as_str)?;

    // Required arguments, filled with placeholders.
    let mut args = Vec::new();
    if let Some(list) = field.get("args").and_then(Value::as_array) {
        for arg in list {
            let Some(arg_name) = arg.get("name").and_then(Value::as_str) else {
                continue;
            };
            let ty = arg.get("type");
            if is_required(ty) {
                args.push(format!("{arg_name}: {}", arg_placeholder(ty)));
            }
        }
    }
    let arg_str = if args.is_empty() {
        String::new()
    } else {
        format!("({})", args.join(", "))
    };

    // A selection set only where the return type is composite.
    let selection = if returns_composite(field.get("type")) {
        " { __typename }"
    } else {
        ""
    };

    let document = format!("{kind} {{ {name}{arg_str}{selection} }}");
    let body = serde_json::json!({ "query": document }).to_string();

    Some(GraphqlOp {
        kind: kind.to_string(),
        field: name.to_string(),
        document,
        body,
    })
}

/// Whether a type reference is `NON_NULL` at the top (a required argument).
fn is_required(ty: Option<&Value>) -> bool {
    ty.and_then(|t| t.get("kind"))
        .and_then(Value::as_str)
        .map(|k| k == "NON_NULL")
        .unwrap_or(false)
}

/// Unwraps NON_NULL/LIST wrappers to the base `(kind, name)`.
fn base_type(ty: Option<&Value>) -> (Option<String>, Option<String>) {
    let mut current = ty;
    // Bounded: a real type reference nests only a few wrappers deep.
    for _ in 0..8 {
        let Some(t) = current else { break };
        let kind = t.get("kind").and_then(Value::as_str);
        match kind {
            Some("NON_NULL") | Some("LIST") => {
                current = t.get("ofType");
            }
            _ => {
                return (
                    kind.map(str::to_string),
                    t.get("name").and_then(Value::as_str).map(str::to_string),
                );
            }
        }
    }
    (None, None)
}

/// Whether the field's return type is an object/interface/union (needs a selection set).
fn returns_composite(ty: Option<&Value>) -> bool {
    matches!(
        base_type(ty).0.as_deref(),
        Some("OBJECT") | Some("INTERFACE") | Some("UNION")
    )
}

/// A placeholder literal for a required argument, by its base scalar type.
fn arg_placeholder(ty: Option<&Value>) -> String {
    let (_, name) = base_type(ty);
    match name.as_deref() {
        Some("Int") => "1".to_string(),
        Some("Float") => "1.0".to_string(),
        Some("Boolean") => "true".to_string(),
        // ID and String (and unknown/custom scalars, enums, input objects) as a quoted string;
        // it is a placeholder, and a string is the least likely to be rejected outright.
        _ => "\"test\"".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTROSPECTION: &str = r#"{
      "data": { "__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
          {"kind": "OBJECT", "name": "Query", "fields": [
            {"name": "version", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
            {"name": "user", "args": [
              {"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}},
              {"name": "trace", "type": {"kind": "SCALAR", "name": "Boolean"}}
            ], "type": {"kind": "OBJECT", "name": "User"}}
          ]},
          {"kind": "OBJECT", "name": "Mutation", "fields": [
            {"name": "deleteUser", "args": [
              {"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "Int"}}}
            ], "type": {"kind": "SCALAR", "name": "Boolean"}}
          ]},
          {"kind": "OBJECT", "name": "User", "fields": []}
        ]
      }}
    }"#;

    #[test]
    fn scalar_field_needs_no_selection_set() {
        let api = parse_introspection(INTROSPECTION.as_bytes()).unwrap();
        let version = api
            .operations
            .iter()
            .find(|o| o.field == "version")
            .unwrap();
        assert_eq!(version.document, "query { version }");
        assert_eq!(version.kind, "query");
    }

    #[test]
    fn object_field_gets_a_typename_selection_and_required_args_only() {
        let api = parse_introspection(INTROSPECTION.as_bytes()).unwrap();
        let user = api.operations.iter().find(|o| o.field == "user").unwrap();
        // Required `id` filled (ID -> quoted), optional `trace` dropped, object -> __typename.
        assert_eq!(user.document, "query { user(id: \"test\") { __typename } }");
    }

    #[test]
    fn mutations_are_parsed_and_marked() {
        let api = parse_introspection(INTROSPECTION.as_bytes()).unwrap();
        let del = api
            .operations
            .iter()
            .find(|o| o.field == "deleteUser")
            .unwrap();
        assert!(del.is_mutation());
        // Int argument -> 1, scalar Boolean return -> no selection.
        assert_eq!(del.document, "mutation { deleteUser(id: 1) }");
    }

    #[test]
    fn the_body_is_a_graphql_post_payload() {
        let api = parse_introspection(INTROSPECTION.as_bytes()).unwrap();
        let version = api
            .operations
            .iter()
            .find(|o| o.field == "version")
            .unwrap();
        let body: Value = serde_json::from_str(&version.body).unwrap();
        assert_eq!(body["query"], "query { version }");
    }

    #[test]
    fn an_unwrapped_schema_without_data_is_accepted() {
        let raw = r#"{"__schema":{"queryType":{"name":"Q"},"types":[
            {"kind":"OBJECT","name":"Q","fields":[{"name":"ping","args":[],"type":{"kind":"SCALAR","name":"Boolean"}}]}]}}"#;
        let api = parse_introspection(raw.as_bytes()).unwrap();
        assert_eq!(api.operations.len(), 1);
        assert_eq!(api.operations[0].document, "query { ping }");
    }

    #[test]
    fn a_list_of_objects_still_gets_a_selection() {
        let raw = r#"{"__schema":{"queryType":{"name":"Q"},"types":[
            {"kind":"OBJECT","name":"Q","fields":[{"name":"users","args":[],"type":{
                "kind":"LIST","ofType":{"kind":"OBJECT","name":"User"}}}]},
            {"kind":"OBJECT","name":"User","fields":[]}]}}"#;
        let api = parse_introspection(raw.as_bytes()).unwrap();
        assert_eq!(api.operations[0].document, "query { users { __typename } }");
    }

    #[test]
    fn garbage_is_a_clean_error() {
        assert!(parse_introspection(b"not json").is_err());
        assert!(parse_introspection(br#"{"data":{}}"#).is_err());
    }
}
