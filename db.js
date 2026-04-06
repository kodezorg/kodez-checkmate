/**
 * db.js — PostgreSQL connection pool
 *
 * Reads DATABASE_URL from environment (set by docker-compose or .env).
 * Falls back to individual PG* vars for local development convenience.
 */
const { Pool } = require("pg");

const databaseUrl = process.env.DATABASE_URL || "";

function summarizeDatabaseUrl(connectionString) {
  if (!connectionString) {
    return {
      source: "PG env vars",
      target: "(from PG* variables)",
      sslmode: "",
      parseError: "",
      hasHashChar: false,
    };
  }

  try {
    const parsed = new URL(connectionString);
    return {
      source: "DATABASE_URL",
      target: `${parsed.hostname || "unknown"}:${parsed.port || "5432"}/${(parsed.pathname || "").replace(/^\//, "")}`,
      sslmode: String(parsed.searchParams.get("sslmode") || "").trim(),
      parseError: "",
      hasHashChar: connectionString.includes("#"),
    };
  } catch (err) {
    return {
      source: "DATABASE_URL",
      target: "(unparseable)",
      sslmode: "",
      parseError: err.message,
      hasHashChar: connectionString.includes("#"),
    };
  }
}

function resolveSslConfig(connectionString) {
  const explicit = String(process.env.DATABASE_SSL || "").trim().toLowerCase();
  if (["true", "1", "require"].includes(explicit)) {
    return { rejectUnauthorized: false };
  }
  if (["false", "0", "disable"].includes(explicit)) {
    return false;
  }

  try {
    if (!connectionString) return false;
    const parsed = new URL(connectionString);
    const sslmode = String(parsed.searchParams.get("sslmode") || "").trim().toLowerCase();

    if (["require", "prefer", "verify-ca", "verify-full"].includes(sslmode)) {
      return { rejectUnauthorized: false };
    }

    if (parsed.hostname.endsWith(".postgres.database.azure.com")) {
      return { rejectUnauthorized: false };
    }
  } catch {
    // Fall through to plain TCP when URL parsing fails.
  }

  return false;
}

const sslConfig = resolveSslConfig(databaseUrl);
const dbSummary = summarizeDatabaseUrl(databaseUrl);

console.log(
  `[DB] Init source=${dbSummary.source} target=${dbSummary.target} ssl=${sslConfig ? "enabled" : "disabled"}` +
  `${dbSummary.sslmode ? ` sslmode=${dbSummary.sslmode}` : ""}`
);
if (dbSummary.parseError) {
  console.warn(`[DB] DATABASE_URL parse failed: ${dbSummary.parseError}`);
}
if (dbSummary.hasHashChar) {
  console.warn("[DB] DATABASE_URL contains '#'. If this is in the password, encode it as %23 to avoid URL parsing issues.");
}

const pool = new Pool({
  connectionString: databaseUrl || undefined,
  // Reasonable defaults — adjust via DATABASE_URL or PG* env vars
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  ssl: sslConfig,
});

pool.on("error", (err) => {
  console.error("[DB] Unexpected pool error:", err.message);
});

/**
 * Parse the scanned_at timestamp from the report filename.
 * Supported patterns:
 *  - *_YYYY-MM-DD_HH_MM_SS_report.json
 *  - *YYYY-MM-DDTHH-MM-SS*.json
 * Falls back to now() when parsing fails.
 */
function parseScanDate(fileName) {
  // e.g. iamhackathon..._2026-04-01_04_55_27_report.json
  const reportPattern = fileName.match(/_(\d{4}-\d{2}-\d{2})_(\d{2})_(\d{2})_(\d{2})(?:_|\.)/);
  if (reportPattern) {
    const [, datePart, hh, mm, ss] = reportPattern;
    const d = new Date(`${datePart}T${hh}:${mm}:${ss}Z`);
    if (!isNaN(d)) return d;
  }

  // Backward compatibility with names like findings_2024-03-15T10-30-00.json
  const legacyPattern = fileName.match(/(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})/);
  if (legacyPattern) {
    const [, datePart, hh, mm, ss] = legacyPattern;
    const d = new Date(`${datePart}T${hh}:${mm}:${ss}Z`);
    if (!isNaN(d)) return d;
  }

  return new Date();
}

/**
 * Upsert a scan report into the database.
 *
 * @param {string}   fileName   - original filename (used as idempotency key)
 * @param {object[]} findings   - parsed array from the JSON report
 * @returns {Promise<{scanId: string, inserted: boolean}>}
 */
async function upsertScan(fileName, findings) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Count severities
    const counts = { High: 0, Moderate: 0, Low: 0, Info: 0, GenAI: 0 };
    for (const f of findings) {
      const sev = f.severity || "Info";
      if (sev in counts) counts[sev]++;
      else counts.Info++;
    }
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const scannedAt = parseScanDate(fileName);

    // Upsert scan row (skip re-import of same file)
    const scanRes = await client.query(
      `INSERT INTO scans
         (file_name, scanned_at, cnt_high, cnt_moderate, cnt_low, cnt_info, cnt_genai, cnt_total)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (file_name) DO UPDATE
         SET scanned_at    = EXCLUDED.scanned_at,
             cnt_high     = EXCLUDED.cnt_high,
             cnt_moderate = EXCLUDED.cnt_moderate,
             cnt_low      = EXCLUDED.cnt_low,
             cnt_info     = EXCLUDED.cnt_info,
             cnt_genai    = EXCLUDED.cnt_genai,
             cnt_total    = EXCLUDED.cnt_total,
             imported_at  = now()
       RETURNING id, (xmax = 0) AS inserted`,
      [fileName, scannedAt, counts.High, counts.Moderate, counts.Low, counts.Info, counts.GenAI, total]
    );

    const { id: scanId, inserted } = scanRes.rows[0];

    if (inserted) {
      // Fresh insert — persist all findings
      for (const f of findings) {
        const findingRes = await client.query(
          `INSERT INTO findings
             (scan_id, name, title, description, status, severity, severity_message,
              disclaimer, advisory, pre_requisites, docs_path)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
           RETURNING id`,
          [
            scanId,
            f.name || "",
            f.title || "",
            f.description || null,
            f.status || "red",
            f.severity || "Info",
            f.severity_message || null,
            f.disclaimer || null,
            f.advisory ? JSON.stringify(f.advisory) : null,
            f.pre_requisites ? JSON.stringify(f.pre_requisites) : null,
            f.docsPath || [],
          ]
        );

        const findingId = findingRes.rows[0].id;

        for (const d of f.details || []) {
          await client.query(
            `INSERT INTO finding_details (finding_id, field, item_name, status, value, message)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [
              findingId,
              d.field || null,
              d.name || null,
              d.status || null,
              d.value != null ? String(d.value) : null,
              d.message || null,
            ]
          );
        }
      }
    }

    await client.query("COMMIT");
    return { scanId, inserted };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Return all scans ordered by scanned_at DESC.
 */
async function listScans() {
  const res = await pool.query(
    `SELECT id, file_name, scanned_at, imported_at,
            cnt_high, cnt_moderate, cnt_low, cnt_info, cnt_genai, cnt_total
     FROM scans
     ORDER BY scanned_at DESC`
  );
  return res.rows;
}

/**
 * Return one scan with all its findings + details.
 */
async function getScanWithFindings(scanId) {
  const scanRes = await pool.query(
    `SELECT id, file_name, scanned_at, imported_at,
            cnt_high, cnt_moderate, cnt_low, cnt_info, cnt_genai, cnt_total
     FROM scans WHERE id = $1`,
    [scanId]
  );
  if (!scanRes.rows.length) return null;

  const findingsRes = await pool.query(
    `SELECT id, name, title, description, status, severity, severity_message,
            disclaimer, advisory, pre_requisites, docs_path
     FROM findings WHERE scan_id = $1 ORDER BY
       CASE severity
         WHEN 'High'     THEN 1
         WHEN 'Moderate' THEN 2
         WHEN 'Low'      THEN 3
         WHEN 'GenAI'    THEN 4
         ELSE 5
       END, title`,
    [scanId]
  );

  const detailsRes = await pool.query(
    `SELECT fd.id, fd.finding_id, fd.field, fd.item_name, fd.status, fd.value, fd.message
     FROM finding_details fd
     JOIN findings f ON f.id = fd.finding_id
     WHERE f.scan_id = $1`,
    [scanId]
  );

  // Group details by finding_id
  const detailsMap = {};
  for (const d of detailsRes.rows) {
    (detailsMap[d.finding_id] ||= []).push(d);
  }

  return {
    ...scanRes.rows[0],
    findings: findingsRes.rows.map((f) => ({
      ...f,
      advisory: f.advisory,
      pre_requisites: f.pre_requisites,
      details: detailsMap[f.id] || [],
    })),
  };
}

module.exports = { pool, upsertScan, listScans, getScanWithFindings };
