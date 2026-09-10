-- M12.6: how a request reached the socket, and the bytes it was made of.
--
-- A structured request is serialized from the message model, so `method`, `path` and
-- `headers_raw` describe it completely and re-serializing them reproduces what went
-- out. A raw request is bytes the tester wrote, and re-serializing anything would
-- produce a *different* request — CRLF where they wrote LF, a Content-Length they
-- deliberately left wrong, headers in an order that was the point. So the bytes
-- themselves are kept, in the blob store, exactly as sent.
--
-- Existing rows are structured by definition: raw mode did not exist when they were
-- written. The default says so rather than leaving a NULL for every reader to
-- interpret.

ALTER TABLE requests ADD COLUMN request_mode TEXT NOT NULL DEFAULT 'structured'
    CHECK (request_mode IN ('structured', 'raw'));

-- The complete request bytes — head and body together — for a raw request. NULL for
-- a structured one, whose bytes are reproducible from the columns beside it.
--
-- Content-addressed like every other body, so re-sending the same raw request a
-- hundred times while fuzzing a header costs one copy.
ALTER TABLE requests ADD COLUMN raw_hash TEXT;
ALTER TABLE requests ADD COLUMN raw_size INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_requests_mode ON requests(request_mode);
