-- Hexora project schema, revision 2: preserve the body as it arrived.
--
-- Revision 1 stored one body per message. The engine hands back a *decoded* body —
-- chunked framing removed, Content-Encoding reversed — because that is what a tester
-- searches and matches on. Storing only that quietly contradicts the principle the
-- whole message model is built on: preserve the wire.
--
-- It matters beyond principle. A finding about compression side channels, a
-- decompression bomb, or a parser differential in gzip handling is a finding about the
-- *encoded* bytes. Having thrown them away, the evidence cannot be re-examined and the
-- exchange cannot be replayed byte-for-byte.
--
-- So both forms are kept. They are content-addressed, so an uncompressed response
-- costs nothing extra: the two hashes are simply equal and the blob is stored once.
--
-- This is a separate migration rather than an edit to revision 1 because a released
-- migration is never edited — see docs/storage.md. Projects created before this
-- revision keep working; their encoded columns are simply NULL, meaning "the body as
-- stored is the body as it arrived".

-- The body exactly as it came off the wire, before Content-Encoding was reversed.
-- NULL means no content coding was applied, so `body_hash` already is the wire form.
ALTER TABLE responses ADD COLUMN encoded_body_hash TEXT;
ALTER TABLE responses ADD COLUMN encoded_body_size INTEGER NOT NULL DEFAULT 0;

-- The Content-Encoding that was reversed, so the decoded form can be reproduced and
-- an analyst can see what the server claimed without re-parsing the header block.
ALTER TABLE responses ADD COLUMN content_encoding TEXT;

CREATE INDEX idx_responses_encoded_body_hash ON responses(encoded_body_hash);

-- Framing anomalies observed while parsing this exchange, as a JSON array of quirk
-- names. These are smuggling signals: recorded per exchange so a tester can find every
-- response that showed one, rather than having to notice a log line as it went past.
ALTER TABLE requests ADD COLUMN quirks TEXT NOT NULL DEFAULT '[]';
ALTER TABLE responses ADD COLUMN quirks TEXT NOT NULL DEFAULT '[]';

-- What the TLS handshake produced, serialized as `hexora_types::tls::TlsInfo`.
-- NULL for plaintext exchanges. Kept on the request because that is what carries the
-- connection, and because a finding derived from an unverified connection has to be
-- able to disclose that.
ALTER TABLE requests ADD COLUMN tls_json TEXT;
