//! Streaming response bodies.
//!
//! # Why streaming is not an optimisation here
//!
//! Buffering a whole response before returning it is fine for `hexora send`, and wrong
//! for everything the proxy has to do. A proxy that waits for the last byte before
//! forwarding the first turns every download into a stall, breaks server-sent events
//! and long-poll endpoints outright, and needs enough memory to hold whatever the
//! target decides to send.
//!
//! Worse for a security tool: buffering means a hostile server can hold the connection
//! open indefinitely and Hexora would have nothing to show for it. Streaming means the
//! limit fires against bytes already counted, and whatever arrived before the cut is
//! still evidence.
//!
//! # What this yields
//!
//! [`BodyStream`] yields **transfer-decoded** bytes: chunked framing is removed, but
//! `Content-Encoding` is left alone. That split is deliberate. A proxy forwards
//! compressed bytes untouched — decompressing only to recompress would be wasteful and
//! would change what the client receives — while a caller that wants to read the body
//! asks for [`BodyStream::collect`], which reverses content coding at the end.

use bytes::{Bytes, BytesMut};
use hexora_types::error::{HexoraError, NetworkError, ProtocolError, Result, TimeoutPhase};
use hexora_types::http::Headers;
use hexora_types::limits::Limits;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::chunked;
use crate::parse::{BodyFraming, Quirk};

/// Bytes requested from the socket per read.
const READ_CHUNK: usize = 16 * 1024;

/// A response body being read from the connection.
///
/// Owns the connection for the lifetime of the body, because the bytes cannot be
/// framed without it. Dropping the stream drops the connection, which is the correct
/// way to abandon a response that is taking too long.
pub struct BodyStream<'a> {
    stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
    buf: BytesMut,
    framing: BodyFraming,
    limits: Limits,
    chunked: Option<chunked::Decoder>,
    /// Bytes still expected, for `Content-Length` framing.
    remaining: u64,
    produced: u64,
    finished: bool,
    truncated: bool,
    quirks: Vec<Quirk>,
    trailers: Headers,
    deadline: tokio::time::Instant,
}

impl std::fmt::Debug for BodyStream<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyStream")
            .field("framing", &self.framing)
            .field("produced", &self.produced)
            .field("finished", &self.finished)
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

/// A body that has been read to completion.
#[derive(Debug, Clone)]
pub struct CollectedBody {
    /// The body, with transfer *and* content coding reversed.
    pub bytes: Bytes,
    /// Trailer fields, for a chunked body that carried them.
    pub trailers: Headers,
    /// Deviations observed while framing the body.
    pub quirks: Vec<Quirk>,
    /// Whether a limit stopped the read early.
    pub truncated: bool,
}

impl<'a> BodyStream<'a> {
    /// Builds a stream over `connection`, starting with `prefix` — the bytes that
    /// arrived alongside the response head and belong to the body.
    ///
    /// The connection may be borrowed rather than owned. The proxy needs that: it
    /// reads a request body from a client socket it must keep afterwards to write the
    /// response back, and requiring ownership here would have meant a second copy of
    /// the chunked decoder living in the proxy.
    pub fn new(
        connection: Box<dyn AsyncRead + Send + Unpin + 'a>,
        prefix: BytesMut,
        framing: BodyFraming,
        limits: Limits,
    ) -> Self {
        let deadline = tokio::time::Instant::now() + limits.total_timeout;
        Self {
            stream: connection,
            buf: prefix,
            chunked: matches!(framing, BodyFraming::Chunked).then(chunked::Decoder::new),
            remaining: match framing {
                BodyFraming::ContentLength(n) => n,
                _ => 0,
            },
            framing,
            limits,
            produced: 0,
            finished: matches!(framing, BodyFraming::None),
            truncated: false,
            quirks: Vec::new(),
            trailers: Headers::new(),
            deadline,
        }
    }

    /// Yields the next piece of the body, or `None` once it is complete.
    ///
    /// Chunks are whatever the network happened to deliver; callers must not assume
    /// any particular size or alignment.
    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        loop {
            if self.finished {
                return Ok(None);
            }

            if let Some(ready) = self.take_ready()? {
                if !ready.is_empty() {
                    return Ok(Some(ready));
                }
                // Nothing decodable yet; fall through and read more.
            }
            if self.finished {
                return Ok(None);
            }

            let read = self.fill().await?;
            if read == 0 {
                return self.handle_eof();
            }
        }
    }

    /// Decodes whatever is already buffered, without touching the socket.
    fn take_ready(&mut self) -> Result<Option<Bytes>> {
        match self.framing {
            BodyFraming::None => {
                self.finished = true;
                Ok(None)
            }

            BodyFraming::ContentLength(_) => {
                if self.remaining == 0 {
                    self.finished = true;
                    return Ok(None);
                }
                if self.buf.is_empty() {
                    return Ok(Some(Bytes::new()));
                }
                let take = (self.remaining as usize).min(self.buf.len());
                let take = self.clamp_to_limit(take);
                let out = self.buf.split_to(take).freeze();
                self.remaining -= out.len() as u64;
                self.produced += out.len() as u64;
                if self.remaining == 0 {
                    self.finished = true;
                }
                Ok(Some(out))
            }

            BodyFraming::UntilClose => {
                if self.buf.is_empty() {
                    return Ok(Some(Bytes::new()));
                }
                let take = self.clamp_to_limit(self.buf.len());
                let out = self.buf.split_to(take).freeze();
                self.produced += out.len() as u64;
                Ok(Some(out))
            }

            BodyFraming::Chunked => {
                let decoder = self
                    .chunked
                    .as_mut()
                    .expect("chunked framing always has a decoder");
                let out = decoder.push(&mut self.buf, &self.limits)?;
                self.produced += out.len() as u64;

                if decoder.is_done() || decoder.truncated() {
                    self.truncated |= decoder.truncated();
                    self.trailers = decoder.trailers().clone();
                    for quirk in decoder.quirks() {
                        if !self.quirks.contains(quirk) {
                            self.quirks.push(*quirk);
                        }
                    }
                    self.finished = true;
                }
                Ok(Some(out))
            }
        }
    }

    /// Caps a read against the body limit, marking truncation when it bites.
    fn clamp_to_limit(&mut self, wanted: usize) -> usize {
        let room = self.limits.max_body_bytes.saturating_sub(self.produced);
        if (wanted as u64) <= room {
            return wanted;
        }
        // Truncation is recorded, never silent: evidence built on a partial body has
        // to be able to disclose that it is partial.
        self.truncated = true;
        self.finished = true;
        room as usize
    }

    /// Reads more bytes from the connection, honouring the total deadline.
    async fn fill(&mut self) -> Result<usize> {
        let before = self.buf.len();
        self.buf.resize(before + READ_CHUNK, 0);

        let result =
            tokio::time::timeout_at(self.deadline, self.stream.read(&mut self.buf[before..])).await;

        match result {
            Err(_) => {
                self.buf.truncate(before);
                Err(HexoraError::Network(NetworkError::Timeout {
                    phase: TimeoutPhase::ReadResponseBody,
                    elapsed: self.limits.total_timeout,
                }))
            }
            Ok(Err(e)) => {
                self.buf.truncate(before);
                Err(HexoraError::Network(NetworkError::Io(e.to_string())))
            }
            Ok(Ok(read)) => {
                self.buf.truncate(before + read);
                Ok(read)
            }
        }
    }

    /// Decides what an unexpected end of connection means for this framing.
    fn handle_eof(&mut self) -> Result<Option<Bytes>> {
        self.finished = true;
        match self.framing {
            // Closing *is* the terminator here.
            BodyFraming::UntilClose | BodyFraming::None => Ok(None),

            BodyFraming::ContentLength(declared) => {
                Err(HexoraError::Protocol(ProtocolError::Malformed {
                    protocol: "HTTP/1.1",
                    reason: format!(
                        "connection closed after {} of {declared} declared body bytes",
                        self.produced
                    ),
                }))
            }

            BodyFraming::Chunked => Err(HexoraError::Protocol(
                ProtocolError::InvalidChunkedEncoding(
                    "connection closed before the terminating chunk".to_string(),
                ),
            )),
        }
    }

    /// Reads the body to completion and reverses any `Content-Encoding`.
    ///
    /// `content_encoding` is the raw header value; pass an empty string when absent.
    pub async fn collect(mut self, content_encoding: &str) -> Result<CollectedBody> {
        let mut bytes = BytesMut::new();
        while let Some(chunk) = self.next_chunk().await? {
            bytes.extend_from_slice(&chunk);
        }

        let mut truncated = self.truncated;
        let mut body = bytes.freeze();

        // Content coding is reversed only once the whole body is present: a partial
        // compressed stream does not decode to a partial plaintext, it decodes to an
        // error or to garbage.
        if !truncated && !content_encoding.trim().is_empty() {
            let decoded = crate::decode::decode_body(content_encoding, &body, &self.limits)?;
            truncated |= decoded.truncated;
            body = decoded.body;
        }

        Ok(CollectedBody {
            bytes: body,
            trailers: self.trailers.clone(),
            quirks: self.quirks.clone(),
            truncated,
        })
    }

    /// Whether a limit stopped the read early.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Deviations observed while framing the body.
    pub fn quirks(&self) -> &[Quirk] {
        &self.quirks
    }

    /// Trailer fields, populated once a chunked body completes.
    pub fn trailers(&self) -> &Headers {
        &self.trailers
    }

    /// Bytes yielded so far.
    pub fn produced(&self) -> u64 {
        self.produced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection that hands over `pieces` one read at a time, so tests can control
    /// exactly how the body is split across reads.
    struct Pieces(Vec<Vec<u8>>);

    impl AsyncRead for Pieces {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.0.is_empty() {
                return std::task::Poll::Ready(Ok(()));
            }
            let piece = self.0.remove(0);
            let take = piece.len().min(buf.remaining());
            buf.put_slice(&piece[..take]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn stream(pieces: Vec<&[u8]>, framing: BodyFraming, limits: Limits) -> BodyStream<'static> {
        let owned: Vec<Vec<u8>> = pieces.into_iter().map(<[u8]>::to_vec).collect();
        BodyStream::new(Box::new(Pieces(owned)), BytesMut::new(), framing, limits)
    }

    async fn drain(mut body: BodyStream<'_>) -> Result<Vec<Bytes>> {
        let mut chunks = Vec::new();
        while let Some(chunk) = body.next_chunk().await? {
            if !chunk.is_empty() {
                chunks.push(chunk);
            }
        }
        Ok(chunks)
    }

    #[tokio::test]
    async fn a_content_length_body_streams_in_pieces() {
        let body = stream(
            vec![b"hello ", b"world"],
            BodyFraming::ContentLength(11),
            Limits::default(),
        );
        let chunks = drain(body).await.unwrap();
        assert!(
            chunks.len() > 1,
            "streaming should yield more than one piece"
        );
        let joined: Vec<u8> = chunks.concat();
        assert_eq!(joined, b"hello world");
    }

    #[tokio::test]
    async fn a_chunked_body_yields_data_before_the_terminator_arrives() {
        // The whole reason this milestone exists.
        let mut body = stream(
            vec![b"5\r\nhello\r\n", b"6\r\n world\r\n", b"0\r\n\r\n"],
            BodyFraming::Chunked,
            Limits::default(),
        );
        let first = body.next_chunk().await.unwrap().unwrap();
        assert_eq!(first.as_ref(), b"hello");
        assert!(!body.truncated());
    }

    #[tokio::test]
    async fn a_chunked_body_reassembles_correctly() {
        let body = stream(
            vec![b"3\r\nabc\r\n", b"3\r\ndef\r\n0\r\nX-T: 1\r\n\r\n"],
            BodyFraming::Chunked,
            Limits::default(),
        );
        let collected = body.collect("").await.unwrap();
        assert_eq!(collected.bytes.as_ref(), b"abcdef");
        assert_eq!(collected.trailers.get("X-T").unwrap().value_lossy(), "1");
    }

    #[tokio::test]
    async fn a_body_split_awkwardly_across_reads_still_decodes() {
        // Chunk headers straddling a read boundary is the case that breaks naive
        // implementations.
        let body = stream(
            vec![b"3\r\nab", b"c\r\n3", b"\r\ndef\r", b"\n0\r\n\r\n"],
            BodyFraming::Chunked,
            Limits::default(),
        );
        let collected = body.collect("").await.unwrap();
        assert_eq!(collected.bytes.as_ref(), b"abcdef");
    }

    #[tokio::test]
    async fn an_until_close_body_ends_at_eof() {
        let body = stream(
            vec![b"streamed ", b"to the end"],
            BodyFraming::UntilClose,
            Limits::default(),
        );
        let collected = body.collect("").await.unwrap();
        assert_eq!(collected.bytes.as_ref(), b"streamed to the end");
        assert!(!collected.truncated);
    }

    #[tokio::test]
    async fn a_bodiless_response_yields_nothing() {
        let body = stream(vec![b"ignored"], BodyFraming::None, Limits::default());
        assert!(body.collect("").await.unwrap().bytes.is_empty());
    }

    #[tokio::test]
    async fn the_limit_bites_mid_stream_rather_than_after() {
        let limits = Limits {
            max_body_bytes: 8,
            ..Default::default()
        };
        let body = stream(
            vec![b"AAAAAAAAAA", b"BBBBBBBBBB", b"CCCCCCCCCC"],
            BodyFraming::UntilClose,
            limits,
        );
        let collected = body.collect("").await.unwrap();
        assert_eq!(collected.bytes.len(), 8);
        assert!(
            collected.truncated,
            "a body cut short must say so, or evidence built on it lies"
        );
    }

    #[tokio::test]
    async fn a_short_content_length_body_is_an_error_not_a_short_read() {
        let body = stream(
            vec![b"short"],
            BodyFraming::ContentLength(100),
            Limits::default(),
        );
        let err = body.collect("").await.unwrap_err();
        assert_eq!(err.code(), "protocol");
        assert!(err.to_string().contains("declared body bytes"), "{err}");
    }

    #[tokio::test]
    async fn a_chunked_body_that_never_terminates_is_an_error() {
        let body = stream(
            vec![b"5\r\nhello\r\n"],
            BodyFraming::Chunked,
            Limits::default(),
        );
        let err = body.collect("").await.unwrap_err();
        assert_eq!(err.code(), "protocol");
        assert!(err.to_string().contains("terminating chunk"), "{err}");
    }

    #[tokio::test]
    async fn collecting_reverses_content_encoding() {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"compressed payload").unwrap();
        let compressed = encoder.finish().unwrap();

        let body = BodyStream::new(
            Box::new(Pieces(vec![compressed.clone()])),
            BytesMut::new(),
            BodyFraming::ContentLength(compressed.len() as u64),
            Limits::default(),
        );
        let collected = body.collect("gzip").await.unwrap();
        assert_eq!(collected.bytes.as_ref(), b"compressed payload");
    }

    #[tokio::test]
    async fn bytes_arriving_with_the_head_are_not_lost() {
        let body = BodyStream::new(
            Box::new(Pieces(vec![b" world".to_vec()])),
            BytesMut::from(&b"hello"[..]),
            BodyFraming::ContentLength(11),
            Limits::default(),
        );
        assert_eq!(
            body.collect("").await.unwrap().bytes.as_ref(),
            b"hello world"
        );
    }

    #[tokio::test]
    async fn chunked_quirks_survive_to_the_collected_body() {
        let body = stream(
            vec![b"5;ext=1\r\nhello\r\n0\r\n\r\n"],
            BodyFraming::Chunked,
            Limits::default(),
        );
        let collected = body.collect("").await.unwrap();
        assert!(collected.quirks.contains(&Quirk::ChunkExtension));
    }
}
