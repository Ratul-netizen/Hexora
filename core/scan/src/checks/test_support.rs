//! Building an [`Exchange`](crate::Exchange) by hand, for the checks' own tests.
//!
//! Every check is a pure function from one exchange to some observations, which is
//! what makes them cheap to test exhaustively — including against the malformed input
//! a hostile application actually sends.

use hexora_types::http::{Header, Headers};
use hexora_types::ids::{RequestId, TargetId};
use hexora_types::tls::TlsInfo;

use crate::Exchange;

/// A builder for one exchange.
pub struct Build {
    exchange: Exchange,
}

/// An exchange over TLS to `api.example.com`.
pub fn https() -> Build {
    Build {
        exchange: Exchange {
            id: RequestId::new(),
            target: TargetId::new(),
            host: "api.example.com".into(),
            port: 443,
            secure: true,
            method: "GET".into(),
            url: "https://api.example.com/account".into(),
            path: "/account".into(),
            status: 200,
            request_headers: Headers::new(),
            response_headers: Headers::new(),
            response_bytes: 128,
            authenticated: false,
            tls: None,
            sent_at: "2026-01-01T00:00:00Z".into(),
        },
    }
}

/// An exchange over plaintext to `api.example.com`.
pub fn plaintext() -> Build {
    let mut build = https();
    build.exchange.secure = false;
    build.exchange.port = 80;
    build.exchange.url = "http://api.example.com/account".into();
    build
}

impl Build {
    /// Sets the response status and content headers.
    pub fn response(mut self, status: u16, headers: &[(&str, &str)]) -> Self {
        self.exchange.status = status;
        for (name, value) in headers {
            self.exchange
                .response_headers
                .append(Header::new((*name).to_string(), *value));
        }
        self
    }

    /// Appends a response header, keeping any of the same name.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.exchange
            .response_headers
            .append(Header::new(name.to_string(), value));
        self
    }

    /// Appends a request header.
    ///
    /// Credential-bearing names are the caller's business here: the scanner redacts
    /// on the way in, and a test that wants to check the redaction says so.
    pub fn request_header(mut self, name: &str, value: &str) -> Self {
        self.exchange
            .request_headers
            .append(Header::new(name.to_string(), value));
        self
    }

    /// Marks the request as having carried a credential.
    pub fn authenticated(mut self) -> Self {
        self.exchange.authenticated = true;
        self
    }

    /// Sets the response body size without a body, which is all the checks see.
    pub fn bytes(mut self, bytes: u64) -> Self {
        self.exchange.response_bytes = bytes;
        self
    }

    /// Attaches TLS details.
    pub fn tls(mut self, tls: TlsInfo) -> Self {
        self.exchange.tls = Some(tls);
        self
    }
}

/// Finishes a build.
pub fn exchange(build: Build) -> Exchange {
    build.exchange
}
