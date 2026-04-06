-- ============================================================
--  Auth0 Checkmate — Database Schema
--  Stores security scan reports downloaded from GitHub
-- ============================================================

-- Enable pgcrypto for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─────────────────────────────────────────────
--  scans
--  One row per downloaded report file.
--  file_name is an idempotency key so re-importing
--  the same report does not create duplicate rows.
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name    TEXT        NOT NULL UNIQUE,
    scanned_at   TIMESTAMPTZ NOT NULL,           -- parsed from filename or file mtime
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- denormalised severity counts for fast dashboard queries
    cnt_high     INT         NOT NULL DEFAULT 0,
    cnt_moderate INT         NOT NULL DEFAULT 0,
    cnt_low      INT         NOT NULL DEFAULT 0,
    cnt_info     INT         NOT NULL DEFAULT 0,
    cnt_genai    INT         NOT NULL DEFAULT 0,
    cnt_total    INT         NOT NULL DEFAULT 0
);

-- ─────────────────────────────────────────────
--  findings
--  One row per check in a scan (e.g. checkCustomDomain).
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id          UUID        NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    name             TEXT        NOT NULL,   -- e.g. "checkCustomDomain"
    title            TEXT        NOT NULL,   -- e.g. "Custom Domains"
    description      TEXT,
    status           TEXT        NOT NULL,   -- "red" | "yellow" | "green"
    severity         TEXT        NOT NULL,   -- "High" | "Moderate" | "Low" | "Info" | "GenAI"
    severity_message TEXT,
    disclaimer       TEXT,

    -- structured JSON blobs kept as-is for full-fidelity rendering
    advisory         JSONB,
    pre_requisites   JSONB,
    docs_path        TEXT[]      NOT NULL DEFAULT '{}',

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);

-- ─────────────────────────────────────────────
--  finding_details
--  One row per entry inside a finding's "details" array.
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS finding_details (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID        NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    field       TEXT,
    item_name   TEXT,        -- "name" field (some details have a resource name)
    status      TEXT,        -- "red" | "yellow" | "green"
    value       TEXT,        -- optional scalar value (stringified)
    message     TEXT,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_details_finding_id ON finding_details(finding_id);

-- ─────────────────────────────────────────────
--  Convenience view: scan summary
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW scan_summary AS
SELECT
    s.id,
    s.file_name,
    s.scanned_at,
    s.imported_at,
    s.cnt_high,
    s.cnt_moderate,
    s.cnt_low,
    s.cnt_info,
    s.cnt_genai,
    s.cnt_total,
    COUNT(f.id)::INT AS findings_count
FROM scans s
LEFT JOIN findings f ON f.scan_id = s.id
GROUP BY s.id
ORDER BY s.scanned_at DESC;
