//! Frame-level HTTP/2, for the requests the conforming client refuses to send (M5.1e).
//!
//! [`crate::h2`] wraps the `h2` crate to reach real servers, and the `h2` crate will not
//! emit a protocol violation — which is exactly wrong for a security tool. The whole point
//! of HTTP/2 testing is the request a conforming stack rejects: an uppercase header name, a
//! pseudo-header after a regular one, a duplicate `:path`, a header value carrying a CR/LF,
//! a `content-length` that disagrees with the DATA. Those are how h2→h1 desync, HPACK
//! surprises and pseudo-header confusion get found, and they cannot travel through a
//! validating library.
//!
//! So this is a small, deliberate HTTP/2 client that Hexora controls end to end. The tester
//! supplies an **ordered list of header fields, pseudo-headers and all, exactly as bytes**,
//! and this encodes them into a HEADERS frame with **no validation, no lowercasing, no
//! reordering** — the h2 analogue of raw mode. The encoding is HPACK *literal without
//! indexing, without Huffman*, which is the representation that lets any bytes through.
//!
//! The response is read at the frame level too. Its header block is HPACK-decoded far
//! enough to recover a static-table `:status` and any literal field, while a Huffman or
//! dynamic-table field is consumed exactly (so the decoder never loses sync) and marked
//! rather than guessed — the same honesty the rest of Hexora keeps about what it did and
//! did not decode. A stream the server refuses (`RST_STREAM`) or a connection it abandons
//! (`GOAWAY`) is reported as what it is, with the error code, because "the server rejected
//! this" is the result an adversarial request is looking for.

use std::time::Instant;

use bytes::{Bytes, BytesMut};
use hexora_engine::transport::Exchange;
use hexora_types::error::{HexoraError, NetworkError, ProtocolError, Result, TimeoutPhase};
use hexora_types::http::{Header, Headers, HttpRequest, HttpResponse, HttpVersion};
use hexora_types::limits::Limits;
use hexora_types::raw::RawH2Request;
use hexora_types::tls::TlsInfo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The HTTP/2 connection preface every client sends first (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types.
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

// Flags.
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// Sends a frame-level request over an already-negotiated h2 stream and reads the response.
///
/// `stream` must already be TLS with `h2` selected at ALPN; `tls` is recorded on the
/// exchange. This drives the connection by hand — preface, SETTINGS, one request on stream
/// 1 — because the point is to do exactly what the tester wrote, not what a library would
/// permit.
pub async fn send<S>(
    mut stream: S,
    tls: TlsInfo,
    request: &RawH2Request,
    limits: &Limits,
    started: Instant,
) -> Result<Exchange>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Preface, then our SETTINGS: no push, and a large receive window so a response of any
    // reasonable size arrives without us having to manage per-frame flow control.
    let mut out = Vec::new();
    out.extend_from_slice(PREFACE);
    write_settings(&mut out);
    // Open the connection-level flow-control window wide for the same reason.
    write_frame(&mut out, FRAME_WINDOW_UPDATE, 0, 0, &0x3fff_0000u32.to_be_bytes());

    // The request: one HEADERS frame carrying the tester's block verbatim, then DATA.
    let block = encode_header_block(&request.headers);
    let has_body = !request.body.is_empty();
    let mut headers_flags = FLAG_END_HEADERS;
    if !has_body {
        headers_flags |= FLAG_END_STREAM;
    }
    write_frame(&mut out, FRAME_HEADERS, headers_flags, 1, &block);
    if has_body {
        write_frame(&mut out, FRAME_DATA, FLAG_END_STREAM, 1, &request.body);
    }

    stream
        .write_all(&out)
        .await
        .map_err(|e| io_error("writing the request", e))?;
    stream
        .flush()
        .await
        .map_err(|e| io_error("flushing the request", e))?;

    read_response(&mut stream, tls, request, limits, started).await
}

/// Reads frames until the response stream ends, is reset, or the connection goes away.
async fn read_response<S>(
    stream: &mut S,
    tls: TlsInfo,
    request: &RawH2Request,
    limits: &Limits,
    started: Instant,
) -> Result<Exchange>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut header_block = BytesMut::new();
    let mut headers_done = false;
    let mut status: Option<u16> = None;
    let mut headers = Headers::new();
    let mut body = BytesMut::new();
    let mut truncated = false;

    loop {
        let (kind, flags, stream_id, payload) =
            read_frame(stream, limits, headers_done || status.is_some()).await?;

        match kind {
            FRAME_SETTINGS if flags & FLAG_ACK == 0 => {
                // Acknowledge the server's settings; ignore their contents — the window we
                // advertised is what matters for reading the response.
                let mut ack = Vec::new();
                write_frame(&mut ack, FRAME_SETTINGS, FLAG_ACK, 0, &[]);
                stream.write_all(&ack).await.map_err(|e| io_error("settings ack", e))?;
            }
            FRAME_SETTINGS => {} // an ACK of ours
            FRAME_WINDOW_UPDATE => {}
            FRAME_PING if flags & FLAG_ACK == 0 => {
                let mut ack = Vec::new();
                write_frame(&mut ack, FRAME_PING, FLAG_ACK, 0, &payload);
                stream.write_all(&ack).await.map_err(|e| io_error("ping ack", e))?;
            }
            FRAME_PING => {}
            FRAME_GOAWAY => {
                let code = payload.get(4..8).map(be_u32).unwrap_or(0);
                return Err(HexoraError::Protocol(ProtocolError::Malformed {
                    protocol: "HTTP/2",
                    reason: format!(
                        "the server sent GOAWAY (error {code}) — it rejected the connection \
                         rather than answering"
                    ),
                }));
            }
            FRAME_RST_STREAM if stream_id == 1 => {
                let code = payload.get(0..4).map(be_u32).unwrap_or(0);
                return Err(HexoraError::Protocol(ProtocolError::Malformed {
                    protocol: "HTTP/2",
                    reason: format!(
                        "the server reset the stream (error {code}) — it refused this request"
                    ),
                }));
            }
            FRAME_HEADERS | FRAME_CONTINUATION if stream_id == 1 => {
                // HEADERS may carry padding and priority; strip them so only the header
                // block fragment is decoded.
                let fragment = if kind == FRAME_HEADERS {
                    strip_headers_padding(&payload, flags)
                } else {
                    &payload[..]
                };
                header_block.extend_from_slice(fragment);
                if flags & FLAG_END_HEADERS != 0 {
                    let decoded = decode_header_block(&header_block);
                    status = decoded.status;
                    headers = decoded.headers;
                    headers_done = true;
                }
                if flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            FRAME_DATA if stream_id == 1 => {
                let data = strip_data_padding(&payload, flags);
                let remaining = limits.max_body_bytes.saturating_sub(body.len() as u64);
                if data.len() as u64 > remaining {
                    body.extend_from_slice(&data[..remaining as usize]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(data);
                if flags & FLAG_END_STREAM != 0 {
                    break;
                }
            }
            _ => {} // frames on other streams, or types we do not model, are ignored
        }
    }

    let status = status.ok_or_else(|| {
        HexoraError::Protocol(ProtocolError::Malformed {
            protocol: "HTTP/2",
            reason: "the stream ended without a response header block".to_string(),
        })
    })?;

    Ok(Exchange {
        response: HttpResponse {
            status,
            reason: None,
            version: HttpVersion::Http2,
            headers,
            body: body.freeze(),
            truncated,
        },
        request: view_of(request),
        encoded_body: None,
        content_encoding: None,
        // The faithful record is the header list the tester supplied, reconstructed above;
        // there is no single byte string for it the way h1 raw has, because the wire form is
        // HPACK and stream-scoped.
        raw_request: None,
        duration: started.elapsed(),
        tls: Some(tls),
    })
}

/// A best-effort [`HttpRequest`] view of a raw h2 request, for the history row and reports.
///
/// The pseudo-headers become the method, path and service; everything else becomes an
/// ordinary header. First value wins for a duplicated pseudo-header — a deliberate
/// duplicate is the point of the test, and the record notes the first rather than guessing
/// which the server honoured.
fn view_of(request: &RawH2Request) -> HttpRequest {
    let mut method = String::from("GET");
    let mut path = String::from("/");
    let mut headers = Headers::new();
    let mut seen_method = false;
    let mut seen_path = false;

    for (name, value) in &request.headers {
        let value_str = String::from_utf8_lossy(value).into_owned();
        match name.as_ref() {
            b":method" if !seen_method => {
                method = value_str;
                seen_method = true;
            }
            b":path" if !seen_path => {
                path = value_str;
                seen_path = true;
            }
            _ if name.starts_with(b":") => {} // other/duplicate pseudo-headers stay out of the view
            _ => headers.append(Header {
                name: String::from_utf8_lossy(name).into_owned(),
                value: value.clone(),
            }),
        }
    }

    // The connection target is the request's own service — where the socket went — not a
    // re-parse of a `:authority` the tester may have set to something else on purpose.
    HttpRequest {
        service: request.service.clone(),
        method,
        path,
        version: HttpVersion::Http2,
        headers,
        body: request.body.clone(),
    }
}

// ----------------------------------------------------------------- frame I/O

/// Writes a frame header and payload into `out`.
fn write_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Our SETTINGS: disable push, advertise a large receive window.
fn write_settings(out: &mut Vec<u8>) {
    let mut payload = Vec::new();
    // SETTINGS_ENABLE_PUSH = 0
    payload.extend_from_slice(&2u16.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    // SETTINGS_INITIAL_WINDOW_SIZE = max
    payload.extend_from_slice(&4u16.to_be_bytes());
    payload.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
    write_frame(out, FRAME_SETTINGS, 0, 0, &payload);
}

/// Reads one frame: its type, flags, stream id and payload.
///
/// `expect_more` selects which timeout applies: reading the first response frame is bounded
/// like a response head, later frames like a response body.
async fn read_frame<S>(
    stream: &mut S,
    limits: &Limits,
    expect_more: bool,
) -> Result<(u8, u8, u32, Bytes)>
where
    S: AsyncRead + Unpin,
{
    let timeout = if expect_more {
        limits.total_timeout
    } else {
        limits.read_head_timeout
    };
    let phase = if expect_more {
        TimeoutPhase::ReadResponseBody
    } else {
        TimeoutPhase::ReadResponseHead
    };

    let mut header = [0u8; 9];
    read_exact(stream, &mut header, timeout, phase).await?;

    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let kind = header[3];
    let flags = header[4];
    let stream_id = be_u32(&header[5..9]) & 0x7fff_ffff;

    // A frame the size of a large body is refused before it is read, the same bound the
    // HTTP/1.x reader keeps.
    limits.check_body_size(len as u64)?;

    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact(stream, &mut payload, timeout, phase).await?;
    }
    Ok((kind, flags, stream_id, Bytes::from(payload)))
}

async fn read_exact<S>(
    stream: &mut S,
    buf: &mut [u8],
    timeout: std::time::Duration,
    phase: TimeoutPhase,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    tokio::time::timeout(timeout, stream.read_exact(buf))
        .await
        .map_err(|_| {
            HexoraError::Network(NetworkError::Timeout {
                phase,
                elapsed: timeout,
            })
        })?
        .map_err(|e| io_error("reading a frame", e))?;
    Ok(())
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn io_error(context: &str, e: std::io::Error) -> HexoraError {
    HexoraError::Network(NetworkError::Io(format!("http/2 raw: {context}: {e}")))
}

/// Drops the optional pad-length byte, padding and priority bytes from a HEADERS payload,
/// returning the header block fragment.
fn strip_headers_padding(payload: &[u8], flags: u8) -> &[u8] {
    const PADDED: u8 = 0x8;
    const PRIORITY: u8 = 0x20;
    let mut start = 0;
    let mut pad = 0usize;
    if flags & PADDED != 0 && !payload.is_empty() {
        pad = payload[0] as usize;
        start = 1;
    }
    if flags & PRIORITY != 0 && payload.len() >= start + 5 {
        start += 5;
    }
    let end = payload.len().saturating_sub(pad);
    payload.get(start..end).unwrap_or(&[])
}

/// Drops the optional pad-length byte and padding from a DATA payload.
fn strip_data_padding(payload: &[u8], flags: u8) -> &[u8] {
    const PADDED: u8 = 0x8;
    if flags & PADDED != 0 && !payload.is_empty() {
        let pad = payload[0] as usize;
        let end = payload.len().saturating_sub(pad);
        payload.get(1..end).unwrap_or(&[])
    } else {
        payload
    }
}

// ----------------------------------------------------------------- HPACK

/// Encodes a header list as HPACK *literal without indexing, without Huffman*.
///
/// This is the representation that carries arbitrary bytes: every field is a fresh name and
/// value with an explicit length, so an uppercase name, a `:path` that appears twice or a
/// value with an embedded CR/LF all survive exactly as written. Nothing is indexed, so the
/// dynamic table never changes and encoding is stateless.
fn encode_header_block(headers: &[(Bytes, Bytes)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        // 0x00 = literal header field without indexing, new name.
        out.push(0x00);
        encode_string(&mut out, name);
        encode_string(&mut out, value);
    }
    out
}

/// Encodes an HPACK string literal without Huffman: length as an integer, then the bytes.
fn encode_string(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_integer(out, bytes.len(), 7, 0x00);
    out.extend_from_slice(bytes);
}

/// Encodes an HPACK integer with an `prefix_bits`-bit prefix, OR-ing `flags` into the first
/// byte's high bits.
fn encode_integer(out: &mut Vec<u8>, value: usize, prefix_bits: u8, flags: u8) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if value < max_prefix {
        out.push(flags | value as u8);
    } else {
        out.push(flags | max_prefix as u8);
        let mut remainder = value - max_prefix;
        while remainder >= 128 {
            out.push((remainder % 128 + 128) as u8);
            remainder /= 128;
        }
        out.push(remainder as u8);
    }
}

/// What a decoded response header block yielded.
struct DecodedHeaders {
    status: Option<u16>,
    headers: Headers,
}

/// Decodes a response header block far enough to be useful, and never loses sync.
///
/// A field whose name or value is Huffman-coded, or references the dynamic table, is
/// consumed by its exact length and recorded as opaque rather than guessed — so `:status`,
/// which servers send as a static-table index, is recovered reliably while the rest is
/// reported honestly. Maintaining a dynamic table is deliberately skipped: it is not needed
/// to stay in sync, and this decoder reads responses, it does not need to reproduce them.
fn decode_header_block(block: &[u8]) -> DecodedHeaders {
    let mut headers = Headers::new();
    let mut status = None;
    let mut pos = 0;

    while pos < block.len() {
        let first = block[pos];
        if first & 0x80 != 0 {
            // Indexed header field.
            let (index, next) = decode_integer(block, pos, 7);
            pos = next;
            if let Some((name, value)) = static_entry(index) {
                record(&mut headers, &mut status, name, value);
            } else {
                record(&mut headers, &mut status, "<indexed>", &format!("#{index}"));
            }
        } else if first & 0x40 != 0 {
            // Literal with incremental indexing (6-bit name index prefix).
            pos = decode_literal(block, pos, 6, &mut headers, &mut status);
        } else if first & 0x20 != 0 {
            // Dynamic table size update — no header emitted.
            let (_size, next) = decode_integer(block, pos, 5);
            pos = next;
        } else {
            // Literal without indexing / never indexed (4-bit name index prefix).
            pos = decode_literal(block, pos, 4, &mut headers, &mut status);
        }
    }

    DecodedHeaders { status, headers }
}

/// Decodes one literal header field beginning at `pos`, returning the next position.
fn decode_literal(
    block: &[u8],
    pos: usize,
    name_prefix: u8,
    headers: &mut Headers,
    status: &mut Option<u16>,
) -> usize {
    // `decode_integer` consumes the representation byte and any continuation, so `pos`
    // already points at the name string (index 0) or the value string (indexed name).
    let (name_index, mut pos) = decode_integer(block, pos, name_prefix);
    let name = if name_index == 0 {
        let (bytes, next) = decode_string(block, pos);
        pos = next;
        bytes
    } else {
        static_entry(name_index)
            .map(|(n, _)| n.as_bytes().to_vec())
            .unwrap_or_else(|| b"<indexed-name>".to_vec())
    };
    let (value, next) = decode_string(block, pos);
    pos = next;

    record(
        headers,
        status,
        &String::from_utf8_lossy(&name),
        &String::from_utf8_lossy(&value),
    );
    pos
}

/// Records a decoded field, capturing `:status` as the response status when it parses.
fn record(headers: &mut Headers, status: &mut Option<u16>, name: &str, value: &str) {
    if name == ":status" {
        if let Ok(code) = value.trim().parse::<u16>() {
            *status = Some(code);
        }
        return;
    }
    if name.starts_with(':') {
        return; // other response pseudo-headers are not kept as ordinary headers
    }
    headers.append(Header {
        name: name.to_string(),
        value: Bytes::from(value.as_bytes().to_vec()),
    });
}

/// Decodes an HPACK integer with the given prefix, returning it and the next position.
fn decode_integer(block: &[u8], pos: usize, prefix_bits: u8) -> (usize, usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    let mut value = (block[pos] as usize) & max_prefix;
    let mut pos = pos + 1;
    if value == max_prefix {
        let mut shift = 0;
        while pos < block.len() {
            let byte = block[pos];
            pos += 1;
            value += ((byte & 0x7f) as usize) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    (value, pos)
}

/// Decodes an HPACK string literal, returning its bytes and the next position.
///
/// A Huffman-coded string is consumed by its exact length and returned as a marker: this
/// decoder does not Huffman-decode, but it stays perfectly in sync, which is what lets the
/// static-table `:status` beside it be trusted.
fn decode_string(block: &[u8], pos: usize) -> (Vec<u8>, usize) {
    if pos >= block.len() {
        return (Vec::new(), pos);
    }
    let huffman = block[pos] & 0x80 != 0;
    let (len, start) = decode_integer(block, pos, 7);
    let end = (start + len).min(block.len());
    if huffman {
        (b"<huffman>".to_vec(), end)
    } else {
        (block[start..end].to_vec(), end)
    }
}

/// The HPACK static table (RFC 7541 Appendix A), indices 1..=61.
fn static_entry(index: usize) -> Option<(&'static str, &'static str)> {
    const TABLE: &[(&str, &str)] = &[
        (":authority", ""),
        (":method", "GET"),
        (":method", "POST"),
        (":path", "/"),
        (":path", "/index.html"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "200"),
        (":status", "204"),
        (":status", "206"),
        (":status", "304"),
        (":status", "400"),
        (":status", "404"),
        (":status", "500"),
        ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"),
        ("accept-language", ""),
        ("accept-ranges", ""),
        ("accept", ""),
        ("access-control-allow-origin", ""),
        ("age", ""),
        ("allow", ""),
        ("authorization", ""),
        ("cache-control", ""),
        ("content-disposition", ""),
        ("content-encoding", ""),
        ("content-language", ""),
        ("content-length", ""),
        ("content-location", ""),
        ("content-range", ""),
        ("content-type", ""),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("expect", ""),
        ("expires", ""),
        ("from", ""),
        ("host", ""),
        ("if-match", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("if-range", ""),
        ("if-unmodified-since", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("max-forwards", ""),
        ("proxy-authenticate", ""),
        ("proxy-authorization", ""),
        ("range", ""),
        ("referer", ""),
        ("refresh", ""),
        ("retry-after", ""),
        ("server", ""),
        ("set-cookie", ""),
        ("strict-transport-security", ""),
        ("transfer-encoding", ""),
        ("user-agent", ""),
        ("vary", ""),
        ("via", ""),
        ("www-authenticate", ""),
    ];
    index
        .checked_sub(1)
        .and_then(|i| TABLE.get(i))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_across_the_prefix_boundary() {
        for value in [0usize, 1, 30, 126, 127, 128, 255, 300, 16_384, 1_000_000] {
            let mut out = Vec::new();
            encode_integer(&mut out, value, 7, 0x00);
            let (decoded, pos) = decode_integer(&out, 0, 7);
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(pos, out.len(), "the whole integer is consumed for {value}");
        }
    }

    #[test]
    fn a_literal_block_round_trips_and_yields_the_status() {
        // What we encode (literal without indexing) is exactly what the decoder handles,
        // so a block we build reads back field for field — including a `:status`.
        let headers = vec![
            (Bytes::from_static(b":status"), Bytes::from_static(b"418")),
            (Bytes::from_static(b"content-type"), Bytes::from_static(b"text/plain")),
            (Bytes::from_static(b"x-odd"), Bytes::from_static(b"a b c")),
        ];
        let block = encode_header_block(&headers);
        let decoded = decode_header_block(&block);

        assert_eq!(decoded.status, Some(418));
        assert_eq!(
            decoded.headers.get("content-type").map(|h| h.value_lossy().into_owned()),
            Some("text/plain".to_string())
        );
        assert_eq!(
            decoded.headers.get("x-odd").map(|h| h.value_lossy().into_owned()),
            Some("a b c".to_string())
        );
    }

    #[test]
    fn a_static_table_status_index_is_decoded() {
        // Servers send `:status: 200` as the single indexed byte 0x88 (static index 8).
        let decoded = decode_header_block(&[0x88]);
        assert_eq!(decoded.status, Some(200));
    }

    #[test]
    fn a_huffman_value_is_consumed_exactly_and_marked_not_guessed() {
        // A literal field whose value has the Huffman bit set: the decoder must skip the
        // stated length precisely so the field after it still parses, and must not pretend
        // to know the value.
        let mut block = Vec::new();
        block.push(0x00); // literal without indexing, new name
        encode_string(&mut block, b"x-h"); // name, not huffman
        // value: Huffman flag + length 3 + three arbitrary bytes
        block.push(0x83);
        block.extend_from_slice(&[0xff, 0xff, 0xff]);
        // a following, ordinary field must still decode
        block.push(0x00);
        encode_string(&mut block, b"after");
        encode_string(&mut block, b"here");

        let decoded = decode_header_block(&block);
        assert_eq!(
            decoded.headers.get("x-h").map(|h| h.value_lossy().into_owned()),
            Some("<huffman>".to_string()),
            "an undecoded value is marked, never guessed"
        );
        assert_eq!(
            decoded.headers.get("after").map(|h| h.value_lossy().into_owned()),
            Some("here".to_string()),
            "the decoder stayed in sync past the Huffman field"
        );
    }

    #[test]
    fn a_raw_request_view_reads_its_pseudo_headers() {
        let service = hexora_types::http::HttpService::new("example.com", 443, true);
        let mut request = RawH2Request::get(service, "/accounts/7");
        request
            .headers
            .push((Bytes::from_static(b"x-test"), Bytes::from_static(b"1")));

        let view = view_of(&request);
        assert_eq!(view.method, "GET");
        assert_eq!(view.path, "/accounts/7");
        assert_eq!(view.service.host, "example.com");
        assert_eq!(
            view.headers.get("x-test").map(|h| h.value_lossy().into_owned()),
            Some("1".to_string())
        );
    }
}
