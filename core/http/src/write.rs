//! Request serialization.
//!
//! The rule here is that Hexora sends what the user wrote. A normal client library
//! would add a `Host` header if missing, fix up `Content-Length`, reorder fields or
//! normalize casing — every one of which destroys a test case. Nothing is added,
//! removed or reordered at this layer; `HttpRequest` is already the wire form, and
//! this only lays it out.
//!
//! Consequently it is entirely possible to send a self-contradictory request. That is
//! deliberate: request smuggling research depends on it. Callers that must not do so
//! by accident (scanner, fuzzer) check [`HttpRequest::check_framing`] first.

use hexora_types::http::HttpRequest;

/// Serializes a request to its HTTP/1.x wire form.
pub fn serialize_request(request: &HttpRequest) -> Vec<u8> {
    let mut out = request.to_wire_head();
    out.extend_from_slice(&request.body);
    out
}

#[cfg(test)]
mod tests {
    use hexora_types::http::{Header, HttpService};

    use super::*;

    fn service() -> HttpService {
        HttpService::new("example.com", 80, false)
    }

    #[test]
    fn serializes_a_get_request() {
        let wire = serialize_request(&HttpRequest::get(service(), "/a?b=c"));
        let text = String::from_utf8(wire).unwrap();
        assert_eq!(text, "GET /a?b=c HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn appends_the_body_verbatim() {
        let mut request = HttpRequest::get(service(), "/submit");
        request.method = "POST".into();
        request.headers.set("Content-Length", "9");
        request.body = bytes::Bytes::from_static(b"key=value");

        let wire = serialize_request(&request);
        let text = String::from_utf8(wire).unwrap();
        assert!(text.ends_with("\r\n\r\nkey=value"), "{text:?}");
    }

    #[test]
    fn nothing_is_added_removed_or_reordered() {
        let mut request = HttpRequest::get(service(), "/");
        request.headers.remove("Host");
        request.headers.append(Header::new("B-Second", "2"));
        request.headers.append(Header::new("a-first", "1"));

        let text = String::from_utf8(serialize_request(&request)).unwrap();
        // No Host is invented, casing is preserved, order is preserved.
        assert!(!text.contains("Host:"), "{text:?}");
        assert!(
            text.find("B-Second").unwrap() < text.find("a-first").unwrap(),
            "{text:?}"
        );
    }

    #[test]
    fn a_deliberately_ambiguous_request_still_serializes() {
        // Smuggling test cases must be sendable.
        let mut request = HttpRequest::get(service(), "/");
        request.headers.append(Header::new("Content-Length", "6"));
        request
            .headers
            .append(Header::new("Transfer-Encoding", "chunked"));
        assert!(request.check_framing().is_err(), "the request is ambiguous");

        let text = String::from_utf8(serialize_request(&request)).unwrap();
        assert!(text.contains("Content-Length: 6"), "{text:?}");
        assert!(text.contains("Transfer-Encoding: chunked"), "{text:?}");
    }

    #[test]
    fn binary_bodies_are_not_mangled() {
        let mut request = HttpRequest::get(service(), "/");
        request.body = bytes::Bytes::from_static(&[0x00, 0xff, 0x0d, 0x0a]);
        let wire = serialize_request(&request);
        assert!(wire.ends_with(&[0x00, 0xff, 0x0d, 0x0a]));
    }
}
