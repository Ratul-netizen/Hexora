//! The conforming HTTP/2 client path (M5.1a).
//!
//! This reaches an HTTP/2 origin and returns the same [`Exchange`] the HTTP/1.x transport
//! produces, so everything built on the transport boundary — the repeater, the
//! authorization matrix, the active scanner — can test an h2-only endpoint without
//! knowing the protocol changed underneath it.
//!
//! # Conforming, deliberately
//!
//! This wraps the `h2` crate, which will not emit a protocol violation. That is the wrong
//! tool for the *adversarial* half of HTTP/2 — HPACK bombs, CONTINUATION floods,
//! pseudo-header abuse — and the right tool for the common case of talking to a modern
//! server at all. The frame-level path that sends deliberately-malformed h2 is a separate,
//! later milestone (M5.1e); keeping them apart is what lets the useful half ship now.
//!
//! # What HTTP/2 costs the wire-preservation promise
//!
//! Hexora's identity is byte preservation, and h2 cannot honour all of it: header names
//! are lowercased by the protocol, there is no reason phrase, and the framing is the
//! `h2` crate's, not the tester's. Those are protocol facts, not choices this code makes —
//! and a server that treats header casing as significant is itself a finding, reachable
//! only *because* we sent lowercased names. The exchange records the negotiated protocol
//! (`tls.alpn`) so a reader can see which promise applied. Content coding is still
//! reversed exactly as it is for HTTP/1.x, and both forms are kept, so nothing downstream
//! has to special-case an h2 body.

use std::time::Instant;

use bytes::{Bytes, BytesMut};
use hexora_engine::transport::Exchange;
use hexora_types::error::{HexoraError, NetworkError, Result, TimeoutPhase};
use hexora_types::http::{Header, Headers, HttpRequest, HttpResponse, HttpVersion};
use hexora_types::limits::Limits;
use hexora_types::tls::TlsInfo;
use tokio::io::{AsyncRead, AsyncWrite};

/// Header fields that must not cross into an HTTP/2 request.
///
/// The connection-specific controls are forbidden by RFC 9113 §8.2.2 and the `h2` crate
/// rejects them; `host` and `content-length` are carried by h2's own machinery (the
/// `:authority` pseudo-header and DATA framing), so forwarding them invites a mismatch
/// for no gain.
fn is_dropped_request_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// Sends one request over a freshly negotiated HTTP/2 connection and returns the
/// buffered exchange.
///
/// `stream` is the already-established (and already h2-negotiated, per ALPN) transport;
/// `tls` is what that handshake produced, recorded on the exchange. `started` is passed
/// in rather than taken here so the duration covers the connect and handshake the caller
/// already paid for.
pub async fn send<S>(
    stream: S,
    tls: TlsInfo,
    request: HttpRequest,
    limits: &Limits,
    started: Instant,
) -> Result<Exchange>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::handshake(stream)
        .await
        .map_err(|e| conn_error(&request, e))?;

    // The connection future drives all I/O for the streams multiplexed over it. With one
    // request there is still exactly one, but it has to be polled for anything to move, so
    // it runs as its own task and ends when the request and its body are done with it.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!(error = %e, "http/2 connection ended with an error");
        }
    });

    let mut send_request = send_request
        .ready()
        .await
        .map_err(|e| conn_error(&request, e))?;

    let http_request = build_request(&request)?;

    let has_body = !request.body.is_empty();
    let (response_future, mut stream) = send_request
        .send_request(http_request, !has_body)
        .map_err(|e| conn_error(&request, e))?;

    if has_body {
        stream
            .send_data(request.body.clone(), true)
            .map_err(|e| conn_error(&request, e))?;
    }

    // The head is bounded by the same timeout the HTTP/1.x path uses, so a server that
    // accepts the stream and then goes quiet fails the same way whichever protocol it is.
    let response = tokio::time::timeout(limits.read_head_timeout, response_future)
        .await
        .map_err(|_| {
            HexoraError::Network(NetworkError::Timeout {
                phase: TimeoutPhase::ReadResponseHead,
                elapsed: limits.read_head_timeout,
            })
        })?
        .map_err(|e| conn_error(&request, e))?;

    let (parts, mut body) = response.into_parts();
    let status = parts.status.as_u16();

    let mut headers = Headers::new();
    let mut header_bytes = 0usize;
    for (name, value) in parts.headers.iter() {
        header_bytes += name.as_str().len() + value.len();
        // Constructed directly rather than via `Header::new`, whose value is UTF-8: an h2
        // header value is bytes, and a hostile server's value need not be valid text.
        headers.append(Header {
            name: name.as_str().to_string(),
            value: Bytes::copy_from_slice(value.as_bytes()),
        });
    }
    limits.check_header_size(header_bytes)?;

    // Body, bounded as it arrives. A response that runs past the cap is truncated and
    // flagged rather than refused outright, matching the HTTP/1.x streaming behaviour —
    // a tester still wants what did arrive.
    let mut buf = BytesMut::new();
    let mut truncated = false;
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| conn_error(&request, e))?;
        // Tell the peer we have consumed this window, or it stops sending.
        let _ = body.flow_control().release_capacity(chunk.len());

        let remaining = limits.max_body_bytes.saturating_sub(buf.len() as u64);
        if (chunk.len() as u64) > remaining {
            buf.extend_from_slice(&chunk[..remaining as usize]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }

    // Trailers join the header list, the same as chunked trailers do for HTTP/1.x, so
    // nothing downstream has to know whether a field arrived before or after the body.
    if !truncated {
        if let Some(trailers) = body.trailers().await.map_err(|e| conn_error(&request, e))? {
            for (name, value) in trailers.iter() {
                headers.append(Header {
                    name: name.as_str().to_string(),
                    value: Bytes::copy_from_slice(value.as_bytes()),
                });
            }
        }
    }

    // Content coding is reversed exactly as the HTTP/1.x path reverses it, and both forms
    // are kept. A truncated body is never decoded: a partial compressed stream does not
    // decode to a partial plaintext.
    let content_encoding = headers
        .get("Content-Encoding")
        .map(|h| h.value_lossy().into_owned())
        .unwrap_or_default();

    let mut body_bytes = buf.freeze();
    let mut encoded_body = None;
    let mut content_encoding_applied = None;
    if !truncated && !content_encoding.trim().is_empty() {
        let decoded = crate::decode::decode_body(&content_encoding, &body_bytes, limits)?;
        truncated |= decoded.truncated;
        encoded_body = Some(std::mem::replace(&mut body_bytes, decoded.body));
        content_encoding_applied = Some(content_encoding.trim().to_string());
    }

    Ok(Exchange {
        response: HttpResponse {
            status,
            // HTTP/2 has no reason phrase; there is nothing to record rather than a
            // reconstructed one that never crossed the wire.
            reason: None,
            version: HttpVersion::Http2,
            headers,
            body: body_bytes,
            truncated,
        },
        request,
        encoded_body,
        content_encoding: content_encoding_applied,
        // Raw sending over h2 is the frame-level path (M5.1e); a structured send has no
        // separate byte record, because serializing the model is not what went out here.
        raw_request: None,
        duration: started.elapsed(),
        tls: Some(tls),
    })
}

/// Builds the `http` crate request the `h2` API speaks from Hexora's message model.
fn build_request(request: &HttpRequest) -> Result<http::Request<()>> {
    let method = http::Method::from_bytes(request.method.as_bytes()).map_err(|e| {
        HexoraError::invalid_input("method", format!("{:?}: {e}", request.method))
    })?;

    let uri: http::Uri = request
        .url()
        .parse()
        .map_err(|e| HexoraError::invalid_input("url", format!("{}: {e}", request.url())))?;

    let mut http_request = http::Request::new(());
    *http_request.method_mut() = method;
    *http_request.uri_mut() = uri;
    *http_request.version_mut() = http::Version::HTTP_2;

    let map = http_request.headers_mut();
    for header in request.headers.iter() {
        let lower = header.name.to_ascii_lowercase();
        if is_dropped_request_header(&lower) {
            continue;
        }
        // A header the h2 model cannot represent (an invalid name, a value with control
        // bytes) is dropped with a note rather than failing the whole send: the request
        // is still worth making, and the omission is visible in the recorded request.
        match (
            http::header::HeaderName::from_bytes(lower.as_bytes()),
            http::header::HeaderValue::from_bytes(header.value.as_ref()),
        ) {
            (Ok(name), Ok(value)) => {
                map.append(name, value);
            }
            _ => {
                tracing::debug!(
                    name = %header.name,
                    "dropping a header HTTP/2 cannot carry"
                );
            }
        }
    }

    Ok(http_request)
}

/// Maps an `h2` error to a network error, naming the peer so the message is actionable.
fn conn_error(request: &HttpRequest, error: h2::Error) -> HexoraError {
    HexoraError::Network(NetworkError::Io(format!(
        "http/2 to {}: {error}",
        request.service.authority()
    )))
}
