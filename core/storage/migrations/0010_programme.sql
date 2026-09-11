-- M14.3: the terms an engagement is conducted under.
--
-- Scope says which systems may be touched. This says which kinds of finding the
-- programme running the engagement will accept — a different question, and one a bug
-- bounty programme answers for you. Wolt's, for instance, puts missing security
-- headers, missing cookie flags, CORS without proven impact, banner grabbing, username
-- enumeration and absent rate limits out of scope as *classes*, which is most of what a
-- passive scanner produces.
--
-- Stored beside the scope and the attached headers, in the single project row, for the
-- same reason as both: a project file should be a complete record of an engagement,
-- including the terms it was conducted under. A reader six months later needs to know
-- not only what was found but what this programme would never have accepted, or the
-- coverage claim is unreadable.
ALTER TABLE project ADD COLUMN programme_json TEXT NOT NULL DEFAULT '{}';

-- And on the run record: which detectors were reporting-suppressed, and why.
--
-- Without this a report cannot tell "nobody looked" from "it was looked at and this
-- programme does not accept them", and a reader who cannot tell those apart is being
-- misled about coverage. Invariant 15 by another road.
ALTER TABLE scan_run_detectors ADD COLUMN excluded_reason TEXT;
