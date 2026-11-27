-- The verifier's lookup count (typedstandards#143; IMPL TS-143): one row per UTC
-- day and host, with the number of link lookups of a record on that host. Nothing
-- else is kept: no network address, no cookie, no identifier, no path, never the
-- record. src/lib/lookup-count.ts is the one writer (INCREMENT_SQL) and the one
-- reader (TOTALS_SQL, totals across all hosts only).
--
-- Run once, in the Neon project's SQL Editor, before LOOKUP_COUNT_DATABASE_URL is
-- set on the deployment.
CREATE TABLE IF NOT EXISTS lookup_counts (
  day date NOT NULL,
  host text NOT NULL,
  lookups integer NOT NULL CHECK (lookups > 0),
  PRIMARY KEY (day, host)
);

-- The reversal, after LOOKUP_COUNT_DATABASE_URL is removed:
--   DROP TABLE IF EXISTS lookup_counts;
