-- The captured request that establishes this identity's session — its recorded login.
-- Replaying it (`identity renew`) mints a fresh session without a second hand-login, and
-- lets a long scan re-authenticate when the session expires mid-run.
--
-- Stored as the request's id: the request itself already lives in the traffic table, so
-- this is a reference, not a second copy of any credential it carries.
ALTER TABLE identities ADD COLUMN login_request TEXT;
