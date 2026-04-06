/**
 * Auth0 Checkmate Runner — Token Vault v6 (patched)
 *
 * Fix (post v6): GitHub 404 on /api/workflows, /api/trigger and /api/runs
 *
 * Root cause (GitHub App tokens — ghu_*):
 *   GitHub App user access tokens do NOT use OAuth scopes.  Their access is
 *   governed entirely by the permissions configured in the GitHub App settings:
 *     GitHub → Settings → Developer Settings → GitHub Apps → [App]
 *     → Permissions & events → Repository permissions
 *   If "Actions" is set to "No access", every call to the Actions REST API
 *   (list workflows, trigger dispatch, list runs) returns 404 — regardless of
 *   what scopes were requested during the OAuth/connect flow.
 *
 *   Fix: in the GitHub App settings set
 *     Actions     → Read and write  (required for list + dispatch + list runs)
 *     Contents    → Read            (needed to resolve workflow file references)
 *     Metadata    → Read            (required by GitHub for all Apps)
 *   Then re-install or re-authorize the App (users must re-approve the new
 *   permissions) so their ghu_* token picks up the updated permissions.
 *   No code change is required — the API calls are correct for GitHub Apps.
 *
 * Fix from v5: "Invalid redirect_uri" (400) on POST /me/v1/connected-accounts/connect
 *
 * Root cause:
 *   Auth0's My Account API validates the redirect_uri in the initiate request
 *   against the application's Allowed Callback URLs, exactly like /authorize does.
 *   The URL  {AUTH0_BASE_URL}/connect/github/complete  must be explicitly added
 *   to the Auth0 Dashboard → App → Settings → Allowed Callback URLs.
 *
 * Additional fix: use connect_uri from the API response directly
 *   The response from POST /me/v1/connected-accounts/connect returns both
 *   connect_uri AND connect_params.ticket.  The correct redirect is:
 *     {connect_uri}?ticket={ticket}
 *   v5 re-constructed the URL from a hardcoded domain pattern which could
 *   differ from the actual connect_uri (e.g. regional subdomains).
 *
 * Connected Accounts flow per Auth0 docs:
 *  - Initiate:  POST /me/v1/connected-accounts/connect
 *  - Redirect:  {connect_uri}?ticket={ticket}   (connect_uri from response)
 *  - Complete:  POST /me/v1/connected-accounts/complete  + redirect_uri
 *  - Query:     GET  /me/v1/connected-accounts/accounts
 *  - Token exchange uses MRRT (refresh token → My Account API access token)
 *
 * Auth0 Dashboard prerequisites:
 *  1. Token Vault Early Access enabled on tenant (contact Auth0 Support)
 *  2. Regular Web App → Grant Types → Token Vault ✅, Refresh Token ✅, Auth Code ✅
 *  3. Regular Web App → Advanced → OAuth → Refresh Token Rotation → OFF ✅
 *  4. Regular Web App → Multi-Resource Refresh Token → My Account API → ON ✅
 *  5. Custom API → Allow Offline Access ✅
 *  6. My Account API → activated ✅ → App Access → your app → Authorized → All connected_accounts scopes ✅
 *  7. My Account API → Settings → Allow Skipping User Consent ✅
 *  8. GitHub connection → Purpose → Connected Accounts for Token Vault ✅ + Offline Access ✅
 *  9. GitHub connection → Applications → your app → enabled ✅
 */

require("dotenv").config();

const express = require("express");
const { auth, requiresAuth } = require("express-openid-connect");
const fetch = require("node-fetch");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const fsPromises = require("fs").promises;
const { upsertScan, listScans, getScanWithFindings } = require("./db");

// ── Validate env ──────────────────────────────────────────────────────────
const REQUIRED = [
  "AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET",
  "AUTH0_BASE_URL", "AUTH0_AUDIENCE", "AUTH0_MY_ACCOUNT_AUDIENCE",
  "AUTH0_GITHUB_CONNECTION", "GITHUB_REPO_OWNER", "GITHUB_REPO_NAME",
  "GITHUB_WORKFLOW_ID", "SESSION_SECRET",
];
for (const k of REQUIRED) {
  if (!process.env[k]) {
    console.error(`[ERROR] Missing env var: ${k}`);
    process.exit(1);
  }
}

const {
  AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET,
  AUTH0_BASE_URL, AUTH0_AUDIENCE, AUTH0_MY_ACCOUNT_AUDIENCE,
  AUTH0_GITHUB_CONNECTION, GITHUB_REPO_OWNER, GITHUB_REPO_NAME,
  GITHUB_WORKFLOW_ID, SESSION_SECRET,
} = process.env;

const FOUNDRY_TARGET_URI = process.env.FOUNDRY_TARGET_URI || "";
const FOUNDRY_API_KEY = process.env.FOUNDRY_API_KEY || "";
const FOUNDRY_DEPLOYMENT = process.env.FOUNDRY_DEPLOYMENT || "gpt-5.4";
const FOUNDRY_API_VERSION = process.env.FOUNDRY_API_VERSION || "2024-05-01-preview";
const AUTH0_JIRA_CONNECTION =
  process.env.AUTH0_JIRA_CONNECTION ||
  process.env.AUTH0_ATLASSIAN_CONNECTION ||
  "atlassian";
const JIRA_CONNECT_REDIRECT_URI =
  process.env.JIRA_CONNECT_REDIRECT_URI ||
  process.env.ATLASSIAN_REDIRECT_URI ||
  `${AUTH0_BASE_URL}/connect/jira/complete`;
const JIRA_CONNECT_SCOPES =
  process.env.AUTH0_JIRA_SCOPES ||
  process.env.ATLASSIAN_SCOPES ||
  "read:jira-work write:jira-work read:me offline_access";
const JIRA_SITE_URL = process.env.JIRA_SITE_URL || "https://kodez.atlassian.net";
const JIRA_PROJECT_KEY = process.env.JIRA_PROJECT_KEY || "CMA";
const JIRA_ISSUE_TYPE = process.env.JIRA_ISSUE_TYPE || "Task";
const AUTH0_CONFLUENCE_CONNECTION = process.env.AUTH0_CONFLUENCE_CONNECTION || AUTH0_JIRA_CONNECTION;
const CONFLUENCE_CONNECT_REDIRECT_URI =
  process.env.CONFLUENCE_CONNECT_REDIRECT_URI ||
  `${AUTH0_BASE_URL}/connect/integrations/confluence/complete`;
const CONFLUENCE_CONNECT_SCOPES =
  process.env.AUTH0_CONFLUENCE_SCOPES ||
  "read:space:confluence read:page:confluence write:page:confluence read:me offline_access";
const CONFLUENCE_SITE_URL = process.env.CONFLUENCE_SITE_URL || JIRA_SITE_URL;
const CONFLUENCE_SPACE_ID = process.env.CONFLUENCE_SPACE_ID || "";
const AUTH0_TEAMS_CONNECTION =
  process.env.AUTH0_TEAMS_CONNECTION ||
  process.env.AUTH0_MICROSOFT_CONNECTION ||
  "microsoft";
const TEAMS_CONNECT_REDIRECT_URI =
  process.env.TEAMS_CONNECT_REDIRECT_URI ||
  `${AUTH0_BASE_URL}/connect/integrations/teams/complete`;
const TEAMS_CONNECT_SCOPES =
  process.env.AUTH0_TEAMS_SCOPES ||
  "User.Read Team.ReadBasic.All Channel.ReadBasic.All ChannelMessage.Send offline_access";
const TEAMS_DEFAULT_TEAM_ID = process.env.TEAMS_DEFAULT_TEAM_ID || "";
const TEAMS_DEFAULT_CHANNEL_ID = process.env.TEAMS_DEFAULT_CHANNEL_ID || "";
const CONNECTED_ACCOUNTS_CACHE_TTL_MS = Number(process.env.CONNECTED_ACCOUNTS_CACHE_TTL_MS || 20_000);
const ACTIVITY_LOG_LIMIT = Number(process.env.ACTIVITY_LOG_LIMIT || 250);
// ── Webhook config ───────────────────────────────────────────────────────
// GITHUB_WEBHOOK_SECRET — secret set in repo → Settings → Webhooks.
//   Used for HMAC-SHA256 signature verification of incoming payloads.
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || "";
const GITHUB_WEBHOOK_TOKEN =
  process.env.GITHUB_WEBHOOK_TOKEN ||
  process.env.GITHUB_TOKEN ||
  "";

const PORT = process.env.PORT || 3000;

// ── Local reports directory ────────────────────────────────────────────────
const REPORTS_DIR = path.join(__dirname, "reports");
fs.mkdirSync(REPORTS_DIR, { recursive: true });

// ── Express setup ──────────────────────────────────────────────────────────
const app = express();
// The verify callback captures the raw body Buffer so the GitHub webhook
// signature (X-Hub-Signature-256) can be verified before JSON.parse runs.
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; },
}));
app.use(express.static(path.join(__dirname, "public")));
app.use("/branding", express.static(path.join(__dirname, "branding")));

// ── Auth0 OIDC middleware ──────────────────────────────────────────────────
// The user logs in to Auth0 Universal Login (username/password, or any
// other configured IdP *except* GitHub, since GitHub is only the Connected
// Account — not the login IdP here).
//
// scope includes offline_access → Auth0 issues a refresh token.
// MRRT is configured so the same refresh token can be exchanged for
// access tokens to both AUTH0_AUDIENCE and AUTH0_MY_ACCOUNT_AUDIENCE.
// ──────────────────────────────────────────────────────────────────────────
app.use(
  auth({
    issuerBaseURL: `https://${AUTH0_DOMAIN}`,
    baseURL: AUTH0_BASE_URL,
    clientID: AUTH0_CLIENT_ID,
    clientSecret: AUTH0_CLIENT_SECRET,
    secret: SESSION_SECRET,
    authRequired: false,
    auth0Logout: true,
    authorizationParams: {
      response_type: "code",
      audience: AUTH0_AUDIENCE,
      scope: "openid profile email offline_access",
    },
  })
);

// ── In-memory pending state store (replace with Redis in production) ───────
// Maps state → { auth_session, redirectUri, userSub, connection, ... }
const pendingStates = new Map();
const approvalsById = new Map();
const aiChatApprovals = new Map();
const activityLog = [];
const connectedAccountsCache = new Map();
const sseClients = new Set(); // Server-Sent Events — browser dashboard connections

// ── Dashboard page (requires login) ───────────────────────────────────────
app.get("/dashboard", requiresAuth(), (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ── Server-Sent Events — real-time push to the dashboard ──────────────────
// The dashboard opens one persistent GET /api/events connection. The webhook
// handler calls broadcastSSE() to push events to every connected browser tab.
app.get("/api/events", requiresAuth(), (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no", // prevent nginx from buffering the stream
  });
  res.flushHeaders();

  // Heartbeat every 25 s keeps the connection alive through proxies / LBs
  const heartbeat = setInterval(() => res.write(": heartbeat\n\n"), 25_000);
  sseClients.add(res);

  req.on("close", () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

function broadcastSSE(eventName, data) {
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.write(payload); } catch { sseClients.delete(client); }
  }
}

// ── Helper: get My Account API access token via MRRT ──────────────────────
// Exchange the Auth0 refresh token (issued for AUTH0_AUDIENCE) for an
// access token scoped to the My Account API audience.
// This requires MRRT to be enabled on the app in the Auth0 Dashboard.
async function getMyAccountToken(refreshToken) {
  const res = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "refresh_token",
      client_id: AUTH0_CLIENT_ID,
      client_secret: AUTH0_CLIENT_SECRET,
      refresh_token: refreshToken,
      audience: AUTH0_MY_ACCOUNT_AUDIENCE,
      scope: [
        "openid", "profile", "offline_access",
        "create:me:connected_accounts",
        "read:me:connected_accounts",
        "delete:me:connected_accounts",
      ].join(" "),
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) {
    throw new Error(
      `My Account token exchange failed: ${data.error_description || data.error || JSON.stringify(data)}`
    );
  }
  return data.access_token;
}

// ── Helper: Token Vault Refresh Token Exchange → GitHub access token ───────
async function getConnectionTokenFromVault(refreshToken, connection) {
  const res = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: AUTH0_CLIENT_ID,
      client_secret: AUTH0_CLIENT_SECRET,
      grant_type: "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
      subject_token: refreshToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:refresh_token",
      requested_token_type: "http://auth0.com/oauth/token-type/federated-connection-access-token",
      connection,
    }),
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) {
    const err = new Error(data.error_description || data.error || JSON.stringify(data));
    err.auth0Code = data.error;
    throw err;
  }
  return data.access_token;
}

async function getGitHubTokenFromVault(refreshToken) {
  return getConnectionTokenFromVault(refreshToken, AUTH0_GITHUB_CONNECTION);
}

// ── Routes ─────────────────────────────────────────────────────────────────

app.get("/api/me", (req, res) => {
  if (!req.oidc.isAuthenticated()) return res.json({ authenticated: false });
  const u = req.oidc.user;
  res.json({
    authenticated: true,
    user: { name: u.name || u.nickname, email: u.email, picture: u.picture, sub: u.sub },
    hasRefreshToken: !!req.oidc.refreshToken,
  });
});

app.get("/api/config", (req, res) => {
  if (!req.oidc.isAuthenticated()) return res.json({ authenticated: false });
  res.json({
    repo: `${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}`,
    workflow: GITHUB_WORKFLOW_ID,
    connection: AUTH0_GITHUB_CONNECTION,
    jiraConnection: AUTH0_JIRA_CONNECTION,
    jiraSite: JIRA_SITE_URL,
    jiraProject: JIRA_PROJECT_KEY,
    confluenceSite: CONFLUENCE_SITE_URL,
    confluenceSpaceId: CONFLUENCE_SPACE_ID,
    confluenceCreatePagePath: "/api/confluence/page",
    teamsDefaultTeamId: TEAMS_DEFAULT_TEAM_ID,
    teamsDefaultChannelId: TEAMS_DEFAULT_CHANNEL_ID,
    integrations: listIntegrationDefs().map((integration) => ({
      key: integration.key,
      label: integration.label,
      connection: integration.connection,
      connectPath: integration.connectPath,
      description: integration.description,
      category: integration.category,
    })),
  });
});

function jiraConfigError() {
  if (!AUTH0_JIRA_CONNECTION) {
    return "Set AUTH0_JIRA_CONNECTION to the Auth0 connection name for Atlassian/JIRA.";
  }
  return null;
}

function integrationConfigError(key) {
  const integration = getIntegrationDef(key);
  if (!integration) return `Unknown integration: ${key}`;
  if (!integration.connection) {
    return `Set the Auth0 connection name for ${integration.label}.`;
  }
  return null;
}

function getUserSub(req) {
  return req.oidc?.user?.sub || null;
}

function parseScopeList(scopes) {
  return String(scopes || "")
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

const INTEGRATION_DEFS = {
  github: {
    key: "github",
    label: "GitHub",
    category: "engineering",
    connection: AUTH0_GITHUB_CONNECTION,
    redirectUri: `${AUTH0_BASE_URL}/connect/github/complete`,
    scopes: ["actions", "contents"],
    connectPath: "/connect/github/start",
    description: "Run Checkmate workflows and pull scan reports from GitHub.",
  },
  jira: {
    key: "jira",
    label: "JIRA",
    category: "delivery",
    connection: AUTH0_JIRA_CONNECTION,
    redirectUri: JIRA_CONNECT_REDIRECT_URI,
    scopes: parseScopeList(JIRA_CONNECT_SCOPES),
    connectPath: "/connect/jira/start",
    description: "Create remediation tickets and boards in the configured Atlassian project.",
  },
  confluence: {
    key: "confluence",
    label: "Confluence",
    category: "knowledge",
    connection: AUTH0_CONFLUENCE_CONNECTION,
    redirectUri: CONFLUENCE_CONNECT_REDIRECT_URI,
    scopes: parseScopeList(CONFLUENCE_CONNECT_SCOPES),
    connectPath: "/connect/integrations/confluence/start",
    description: "Publish executive-friendly scan reports into Confluence pages.",
  },
  teams: {
    key: "teams",
    label: "Microsoft Teams",
    category: "comms",
    connection: AUTH0_TEAMS_CONNECTION,
    redirectUri: TEAMS_CONNECT_REDIRECT_URI,
    scopes: parseScopeList(TEAMS_CONNECT_SCOPES),
    connectPath: "/connect/integrations/teams/start",
    description: "Post security updates into Microsoft Teams channels.",
  },
};

function getIntegrationDef(key) {
  return INTEGRATION_DEFS[String(key || "").toLowerCase()] || null;
}

function listIntegrationDefs() {
  return Object.values(INTEGRATION_DEFS);
}

function isRateLimitError(err) {
  const message = String(err?.message || "");
  return (
    err?.auth0Code === "too_many_requests" ||
    /\b429\b/.test(message) ||
    /too many requests/i.test(message) ||
    /rate limit/i.test(message)
  );
}

// ── GitHub webhook signature verification (HMAC-SHA256) ───────────────────
function verifyGitHubWebhookSignature(rawBody, signatureHeader, secret) {
  if (!secret || !signatureHeader) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expected));
  } catch {
    return false;
  }
}

function buildJiraStatusPayload(extra = {}) {
  return {
    connected: false,
    mode: "token-vault",
    project: JIRA_PROJECT_KEY,
    site: JIRA_SITE_URL,
    connection: AUTH0_JIRA_CONNECTION,
    ...extra,
  };
}

function clearConnectedAccountsCache(userSub) {
  if (userSub) connectedAccountsCache.delete(userSub);
}

function logActivity({ userSub, type, integration = "", status = "info", message = "", detail = "", metadata = null }) {
  const entry = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    userSub: userSub || "",
    type,
    integration,
    status,
    message,
    detail,
    metadata,
  };
  activityLog.unshift(entry);
  if (activityLog.length > ACTIVITY_LOG_LIMIT) activityLog.length = ACTIVITY_LOG_LIMIT;
  return entry;
}

function getActivityForUser(userSub, limit = 80) {
  return activityLog
    .filter((entry) => !userSub || entry.userSub === userSub)
    .slice(0, limit);
}

async function listConnectedAccounts(refreshToken, userSub, { force = false } = {}) {
  const cacheKey = userSub || `rt:${String(refreshToken || "").slice(-12)}`;
  const cached = connectedAccountsCache.get(cacheKey);
  if (!force && cached && Date.now() < cached.expiresAt) {
    return cached.accounts;
  }

  try {
    const myAccountToken = await getMyAccountToken(refreshToken);
    const res = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/accounts`, {
      headers: { Authorization: `Bearer ${myAccountToken}` },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(`My Account API ${res.status}: ${body}`);
    }

    const data = await res.json();
    const accounts = Array.isArray(data?.accounts) ? data.accounts : [];
    connectedAccountsCache.set(cacheKey, {
      accounts,
      expiresAt: Date.now() + CONNECTED_ACCOUNTS_CACHE_TTL_MS,
    });
    return accounts;
  } catch (err) {
    if (cached && isRateLimitError(err)) {
      return cached.accounts;
    }
    throw err;
  }
}

async function getConnectedAccount(refreshToken, connection, userSub, options = {}) {
  const accounts = await listConnectedAccounts(refreshToken, userSub, options);
  return accounts.find((account) => account.connection === connection) || null;
}

async function getIntegrationConnectedAccount(refreshToken, key, userSub, options = {}) {
  const integration = getIntegrationDef(key);
  if (!integration?.connection) return null;
  return getConnectedAccount(refreshToken, integration.connection, userSub, options);
}

async function getIntegrationTokenFromVault(refreshToken, key) {
  const integration = getIntegrationDef(key);
  if (!integration?.connection) {
    throw new Error(`Unknown or unconfigured integration: ${key}`);
  }
  return getConnectionTokenFromVault(refreshToken, integration.connection);
}

async function getJiraTokenFromVault(refreshToken) {
  return getConnectionTokenFromVault(refreshToken, AUTH0_JIRA_CONNECTION);
}

async function getJiraConnectedAccount(refreshToken, userSub, options = {}) {
  return getConnectedAccount(refreshToken, AUTH0_JIRA_CONNECTION, userSub, options);
}

async function resolveJiraCloudByToken(accessToken) {
  const res = await fetch("https://api.atlassian.com/oauth/token/accessible-resources", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  const resources = await res.json();
  if (!res.ok || !Array.isArray(resources)) {
    throw new Error(`Failed to resolve Atlassian cloud: ${JSON.stringify(resources)}`);
  }

  const targetHost = new URL(JIRA_SITE_URL).host;
  const match = resources.find((r) => {
    try {
      return new URL(r.url).host === targetHost;
    } catch {
      return false;
    }
  }) || resources[0];

  if (!match?.id) throw new Error("No accessible Atlassian cloud found for this token.");
  return { cloudId: match.id, siteUrl: match.url || JIRA_SITE_URL };
}

async function resolveConfluenceCloudByToken(accessToken) {
  const res = await fetch("https://api.atlassian.com/oauth/token/accessible-resources", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  const resources = await res.json();
  if (!res.ok || !Array.isArray(resources)) {
    throw new Error(`Failed to resolve Atlassian cloud: ${JSON.stringify(resources)}`);
  }

  const targetHost = new URL(CONFLUENCE_SITE_URL).host;
  const match = resources.find((r) => {
    try {
      return new URL(r.url).host === targetHost;
    } catch {
      return false;
    }
  }) || resources[0];

  if (!match?.id) throw new Error("No accessible Atlassian cloud found for this Confluence token.");
  return { cloudId: match.id, siteUrl: match.url || CONFLUENCE_SITE_URL };
}

function escapeHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SEVERITY_ORDER = { High: 0, Moderate: 1, Low: 2, Info: 3, GenAI: 4 };

function getSortedFindings(findings = []) {
  return [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
}

function getScanDateLabel(scan) {
  try {
    return new Date(scan.scanned_at).toISOString().slice(0, 10);
  } catch {
    return new Date().toISOString().slice(0, 10);
  }
}

function buildSeveritySummary(scan) {
  return [
    `High ${Number(scan.cnt_high || 0)}`,
    `Moderate ${Number(scan.cnt_moderate || 0)}`,
    `Low ${Number(scan.cnt_low || 0)}`,
    `Info ${Number(scan.cnt_info || 0)}`,
    `GenAI ${Number(scan.cnt_genai || 0)}`,
  ].join(" · ");
}

function buildScanHeadline(scan) {
  const date = getScanDateLabel(scan);
  return `${scan.file_name} (${date})`;
}

function buildTopFindings(scan, limit = 5) {
  return getSortedFindings(scan.findings || []).slice(0, limit).map((finding) => {
    const details = Array.isArray(finding.details) ? finding.details : [];
    const firstDetail = details.find((d) => d.message)?.message || "";
    return {
      severity: finding.severity || "Info",
      title: finding.title || finding.name || "Security finding",
      message: firstDetail,
    };
  });
}

function buildScanSummaryText(scan, note = "") {
  const lines = [];
  lines.push(`Checkmate scan summary: ${buildScanHeadline(scan)}`);
  lines.push(`Findings: ${Number(scan.cnt_total || 0)} total`);
  lines.push(`Severity mix: ${buildSeveritySummary(scan)}`);
  if (note) lines.push(`Operator note: ${note}`);
  const topFindings = buildTopFindings(scan, 5);
  if (topFindings.length) {
    lines.push("Top findings:");
    for (const finding of topFindings) {
      lines.push(`- [${finding.severity}] ${finding.title}${finding.message ? ` — ${finding.message}` : ""}`);
    }
  }
  return lines.join("\n");
}

function buildScanMarkdownReport(scan, note = "") {
  const lines = [];
  lines.push(`# Checkmate Security Report`);
  lines.push("");
  lines.push(`- Scan: ${buildScanHeadline(scan)}`);
  lines.push(`- Total findings: ${Number(scan.cnt_total || 0)}`);
  lines.push(`- Severity mix: ${buildSeveritySummary(scan)}`);
  if (note) {
    lines.push(`- Operator note: ${note}`);
  }
  lines.push("");
  lines.push(`## Priority Findings`);
  const findings = buildTopFindings(scan, 12);
  if (!findings.length) {
    lines.push("No findings were present in the selected scan.");
  } else {
    for (const finding of findings) {
      lines.push(`### [${finding.severity}] ${finding.title}`);
      if (finding.message) lines.push(finding.message);
      lines.push("");
    }
  }
  return lines.join("\n");
}

function buildScanConfluenceStorage(scan, note = "") {
  const findings = buildTopFindings(scan, 12);
  const items = findings.length
    ? findings.map((finding) => `<li><strong>[${escapeHtml(finding.severity)}]</strong> ${escapeHtml(finding.title)}${finding.message ? ` - ${escapeHtml(finding.message)}` : ""}</li>`).join("")
    : "<li>No findings were present in the selected scan.</li>";

  return [
    `<h1>Checkmate Security Report</h1>`,
    `<p><strong>Scan:</strong> ${escapeHtml(buildScanHeadline(scan))}</p>`,
    `<p><strong>Total findings:</strong> ${escapeHtml(String(Number(scan.cnt_total || 0)))}</p>`,
    `<p><strong>Severity mix:</strong> ${escapeHtml(buildSeveritySummary(scan))}</p>`,
    note ? `<p><strong>Operator note:</strong> ${escapeHtml(note)}</p>` : "",
    `<h2>Priority Findings</h2>`,
    `<ul>${items}</ul>`,
  ].filter(Boolean).join("");
}

function buildConfluencePageStorageFromText(content = "") {
  const trimmed = String(content || "").trim();
  const source = trimmed || "Created via Auth0 Token Vault.";
  const blocks = source
    .split(/\n{2,}/)
    .map((block) => block.trim())
    .filter(Boolean);

  return blocks.map((block) => {
    const lines = block.split(/\n/).map((line) => line.trim()).filter(Boolean);
    if (lines.length && lines.every((line) => /^[-*]\s+/.test(line))) {
      return `<ul>${lines.map((line) => `<li>${escapeHtml(line.replace(/^[-*]\s+/, ""))}</li>`).join("")}</ul>`;
    }
    return `<p>${escapeHtml(block).replace(/\n/g, "<br/>")}</p>`;
  }).join("");
}

async function loadScanOrThrow(scanId) {
  if (!scanId || !/^[0-9a-f-]{36}$/.test(scanId)) {
    throw new Error("A valid scan must be selected.");
  }
  const scan = await getScanWithFindings(scanId);
  if (!scan) throw new Error("Selected scan not found.");
  return scan;
}

async function graphApi(accessToken, pathName, { method = "GET", body } = {}) {
  const res = await fetch(`https://graph.microsoft.com/v1.0${pathName}`, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { message: text }; }
  if (!res.ok) {
    const err = new Error(data?.error?.message || data?.message || `Microsoft Graph ${res.status}`);
    err.status = res.status;
    err.graphCode = data?.error?.code || "";
    err.graphRequestId =
      data?.error?.innerError?.["request-id"] ||
      data?.error?.innerError?.requestId ||
      res.headers.get("request-id") ||
      "";
    err.graphBody = data;
    throw err;
  }
  return data;
}

function buildTeamsSendErrorResponse(err, actionLabel) {
  const detail = String(err?.message || "Microsoft Teams action failed.");
  const graphCode = String(err?.graphCode || "");
  const requestId = String(err?.graphRequestId || "");

  if (graphCode === "InsufficientPrivileges" || /InsufficientPrivileges/i.test(detail)) {
    return {
      status: 403,
      body: {
        error:
          `Microsoft Graph denied permission to ${actionLabel}. ` +
          `Reconnect Microsoft Teams after adding ChannelMessage.Send, ` +
          `make sure the Microsoft enterprise app has consent for that Graph permission, ` +
          `and confirm the signed-in user can post to the selected channel.`,
        code: graphCode || "InsufficientPrivileges",
        detail,
        ...(requestId ? { requestId } : {}),
      },
    };
  }

  return {
    status: Number(err?.status) || 500,
    body: {
      error: detail,
      ...(graphCode ? { code: graphCode } : {}),
      ...(requestId ? { requestId } : {}),
    },
  };
}

async function listTeams(refreshToken) {
  const token = await getIntegrationTokenFromVault(refreshToken, "teams");
  const data = await graphApi(token, "/me/joinedTeams");
  return (data.value || []).map((team) => ({
    id: team.id,
    displayName: team.displayName,
    description: team.description || "",
  }));
}

async function listTeamChannels(refreshToken, teamId) {
  if (!teamId) throw new Error("A Teams team must be selected.");
  const token = await getIntegrationTokenFromVault(refreshToken, "teams");
  const data = await graphApi(token, `/teams/${encodeURIComponent(teamId)}/channels`);
  return (data.value || []).map((channel) => ({
    id: channel.id,
    displayName: channel.displayName,
    membershipType: channel.membershipType || "standard",
  }));
}

async function broadcastScanToTeams(refreshToken, scan, { teamId, channelId, note = "" } = {}) {
  const targetTeamId = teamId || TEAMS_DEFAULT_TEAM_ID;
  const targetChannelId = channelId || TEAMS_DEFAULT_CHANNEL_ID;
  if (!targetTeamId || !targetChannelId) {
    throw new Error("Provide Teams team and channel IDs or set TEAMS_DEFAULT_TEAM_ID / TEAMS_DEFAULT_CHANNEL_ID.");
  }

  const token = await getIntegrationTokenFromVault(refreshToken, "teams");
  const content = escapeHtml(buildScanSummaryText(scan, note)).replace(/\n/g, "<br/>");
  const data = await graphApi(token, `/teams/${encodeURIComponent(targetTeamId)}/channels/${encodeURIComponent(targetChannelId)}/messages`, {
    method: "POST",
    body: {
      body: {
        contentType: "html",
        content,
      },
    },
  });

  return {
    teamId: targetTeamId,
    channelId: targetChannelId,
    messageId: data.id,
  };
}

async function sendCustomTeamsMessage(refreshToken, { teamId, channelId, message } = {}) {
  const targetTeamId = String(teamId || TEAMS_DEFAULT_TEAM_ID || "").trim();
  const targetChannelId = String(channelId || TEAMS_DEFAULT_CHANNEL_ID || "").trim();
  const contentText = String(message || "").trim();

  if (!targetTeamId || !targetChannelId) {
    throw new Error("Provide Teams team and channel IDs or set TEAMS_DEFAULT_TEAM_ID / TEAMS_DEFAULT_CHANNEL_ID.");
  }
  if (!contentText) {
    throw new Error("A custom Teams message is required.");
  }

  const token = await getIntegrationTokenFromVault(refreshToken, "teams");
  const content = escapeHtml(contentText).replace(/\n/g, "<br/>");
  const data = await graphApi(
    token,
    `/teams/${encodeURIComponent(targetTeamId)}/channels/${encodeURIComponent(targetChannelId)}/messages`,
    {
      method: "POST",
      body: {
        body: {
          contentType: "html",
          content,
        },
      },
    }
  );

  return {
    teamId: targetTeamId,
    channelId: targetChannelId,
    messageId: data.id,
    message: contentText,
  };
}

async function listConfluenceSpaces(refreshToken) {
  const token = await getIntegrationTokenFromVault(refreshToken, "confluence");
  const cloud = await resolveConfluenceCloudByToken(token);
  const res = await fetch(`https://api.atlassian.com/ex/confluence/${cloud.cloudId}/wiki/api/v2/spaces?limit=100`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data?.message || `Confluence API ${res.status}`);
  }
  return (data.results || []).map((space) => ({
    id: space.id,
    key: space.key,
    name: space.name,
  }));
}

async function findConfluenceSpaceByKey(refreshToken, spaceKey) {
  const desiredKey = String(spaceKey || "").trim();
  if (!desiredKey) throw new Error("A Confluence space key is required.");

  const token = await getIntegrationTokenFromVault(refreshToken, "confluence");
  const cloud = await resolveConfluenceCloudByToken(token);
  const url = new URL(`https://api.atlassian.com/ex/confluence/${cloud.cloudId}/wiki/api/v2/spaces`);
  url.searchParams.set("keys", desiredKey);
  url.searchParams.set("limit", "25");

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { message: text }; }
  if (!res.ok) {
    const detail =
      data?.message ||
      data?.detail ||
      (text && text !== "[object Object]" ? text : "") ||
      `Confluence API ${res.status}`;
    throw new Error(detail);
  }

  const match = (data.results || []).find((space) =>
    String(space?.key || "").toLowerCase() === desiredKey.toLowerCase()
  );
  if (!match) return null;

  return {
    id: match.id,
    key: match.key,
    name: match.name,
  };
}

function getConfluenceErrorDetail(data, rawText, status) {
  const parts = [];

  const add = (value) => {
    const text = String(value || "").trim();
    if (!text || text === "[object Object]" || parts.includes(text)) return;
    parts.push(text);
  };

  add(data?.message);
  add(data?.detail);
  add(data?.error);

  if (Array.isArray(data?.errors)) {
    for (const item of data.errors) {
      if (typeof item === "string") add(item);
      else {
        add(item?.message);
        add(item?.title);
      }
    }
  } else if (data?.errors && typeof data.errors === "object") {
    for (const [key, value] of Object.entries(data.errors)) {
      add(`${key}: ${value}`);
    }
  }

  add(rawText);
  return parts.join("; ") || `Confluence API ${status}`;
}

async function resolveConfluenceSpace(refreshToken, requestedSpace) {
  const desired = String(requestedSpace || "").trim();
  if (!desired) throw new Error("Provide a Confluence space ID or set CONFLUENCE_SPACE_ID.");

  if (/^\d+$/.test(desired)) {
    return {
      id: desired,
      key: "",
      name: "",
    };
  }

  const spaces = await listConfluenceSpaces(refreshToken);
  const normalized = desired.toLowerCase();
  const match = spaces.find((space) =>
    String(space.id || "").trim() === desired ||
    String(space.key || "").trim().toLowerCase() === normalized
  );

  if (!match) {
    throw new Error(`Confluence space "${desired}" was not found. Provide a valid space ID or space key.`);
  }

  return match;
}

async function createConfluencePageFromStorage(
  refreshToken,
  { spaceId, title, storageValue, parentId = "" } = {}
) {
  const token = await getIntegrationTokenFromVault(refreshToken, "confluence");
  const cloud = await resolveConfluenceCloudByToken(token);
  const requestedSpace = String(spaceId || CONFLUENCE_SPACE_ID || "").trim();
  const resolvedSpace = await resolveConfluenceSpace(refreshToken, requestedSpace);
  const targetSpaceId = String(resolvedSpace.id || "").trim();
  const pageTitle = String(title || "").trim();
  if (!pageTitle) throw new Error("A Confluence page title is required.");
  const bodyValue = String(storageValue || "").trim();
  if (!bodyValue) throw new Error("Confluence page content cannot be empty.");
  const normalizedParentId = String(parentId || "").trim();

  const payload = {
    spaceId: /^\d+$/.test(targetSpaceId) ? Number(targetSpaceId) : targetSpaceId,
    status: "current",
    title: pageTitle.slice(0, 240),
    body: {
      representation: "storage",
      value: bodyValue,
    },
  };
  if (normalizedParentId) {
    payload.parentId = /^\d+$/.test(normalizedParentId) ? Number(normalizedParentId) : normalizedParentId;
  }

  const createPageV2 = async () => fetch(`https://api.atlassian.com/ex/confluence/${cloud.cloudId}/wiki/api/v2/pages`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const buildPageResult = (data, fallbackTitle) => {
    const relative = data?._links?.webui || data?._links?.tinyui || "";
    const base = data?._links?.base || cloud.siteUrl.replace(/\/+$/, "");
    return {
      pageId: data.id,
      title: data.title || fallbackTitle,
      url: relative ? `${base}${relative}` : base,
    };
  };

  const v2Res = await createPageV2();
  const v2Text = await v2Res.text();
  let v2Data;
  try { v2Data = JSON.parse(v2Text); } catch { v2Data = { message: v2Text }; }
  if (v2Res.ok) {
    return buildPageResult(v2Data, payload.title);
  }

  if (v2Res.status !== 400 || !resolvedSpace.key) {
    throw new Error(getConfluenceErrorDetail(v2Data, v2Text, v2Res.status));
  }

  const legacyPayload = {
    type: "page",
    title: pageTitle.slice(0, 240),
    space: { key: resolvedSpace.key },
    body: {
      storage: {
        value: bodyValue,
        representation: "storage",
      },
    },
  };
  if (normalizedParentId) {
    legacyPayload.ancestors = [{ id: normalizedParentId }];
  }

  const legacyRes = await fetch(`https://api.atlassian.com/ex/confluence/${cloud.cloudId}/wiki/rest/api/content`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(legacyPayload),
  });

  const legacyText = await legacyRes.text();
  let legacyData;
  try { legacyData = JSON.parse(legacyText); } catch { legacyData = { message: legacyText }; }
  if (!legacyRes.ok) {
    throw new Error(getConfluenceErrorDetail(legacyData, legacyText, legacyRes.status));
  }

  return buildPageResult(legacyData, legacyPayload.title);
}

async function createConfluencePage(refreshToken, { spaceId, title, content = "", parentId = "" } = {}) {
  return createConfluencePageFromStorage(refreshToken, {
    spaceId,
    title,
    parentId,
    storageValue: buildConfluencePageStorageFromText(content),
  });
}

async function publishScanToConfluence(refreshToken, scan, { spaceId, note = "", title, parentId = "" } = {}) {
  return createConfluencePageFromStorage(refreshToken, {
    spaceId,
    title: String(title || `Checkmate Report — ${buildScanHeadline(scan)}`),
    parentId,
    storageValue: buildScanConfluenceStorage(scan, note),
  });
}

async function createJiraSummaryTicketForScan(refreshToken, scan, note = "") {
  const token = await getJiraTokenFromVault(refreshToken);
  const cloud = await resolveJiraCloudByToken(token);
  const url = `https://api.atlassian.com/ex/jira/${cloud.cloudId}/rest/api/3/issue`;
  const summary = `[Checkmate] ${scan.file_name} summary`;
  const description = buildScanSummaryText(scan, note);
  const payload = {
    fields: {
      project: { key: JIRA_PROJECT_KEY },
      summary: summary.slice(0, 255),
      issuetype: { name: JIRA_ISSUE_TYPE },
      description: {
        type: "doc",
        version: 1,
        content: [{ type: "paragraph", content: [{ type: "text", text: description }] }],
      },
    },
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { message: text }; }
  if (!res.ok) {
    throw new Error(data?.errorMessages?.join("; ") || data?.message || `JIRA API ${res.status}`);
  }

  return {
    issueKey: data.key,
    url: data.key ? `${cloud.siteUrl.replace(/\/+$/, "")}/browse/${data.key}` : null,
  };
}

function buildAutomationActions(prompt, destinations = {}) {
  const text = String(prompt || "").toLowerCase();
  const actions = [];
  if (/\bjira\b/.test(text)) actions.push({ type: "jira_ticket", label: "Create JIRA summary ticket" });
  if (/\bteams\b|microsoft teams/.test(text)) actions.push({ type: "teams_broadcast", label: "Broadcast to Teams" });
  if (/\bconfluence\b/.test(text)) actions.push({ type: "confluence_publish", label: "Publish to Confluence" });

  if (!actions.length) {
    if (destinations.teamsTeamId || destinations.teamsChannelId) actions.push({ type: "teams_broadcast", label: "Broadcast to Teams" });
    if (destinations.confluenceSpaceId) actions.push({ type: "confluence_publish", label: "Publish to Confluence" });
  }

  return actions;
}

async function inferAutomationActions(prompt, destinations = {}) {
  const heuristic = buildAutomationActions(prompt, destinations);
  if (!FOUNDRY_TARGET_URI || !FOUNDRY_API_KEY || !String(prompt || "").trim()) {
    return heuristic;
  }

  const endpoint = buildFoundryEndpoint();
  if (!endpoint) return heuristic;

  const systemPrompt = [
    "You are an action-planning assistant for a security operations dashboard.",
    "Pick from these action types only: jira_ticket, teams_broadcast, confluence_publish.",
    "Return ONLY valid JSON shaped like {\"actions\":[{\"type\":\"jira_ticket\",\"label\":\"Create JIRA summary ticket\"}]}",
    "Do not invent destinations. Infer only action types from the instruction.",
  ].join("\n");

  let payload;
  if (endpoint.mode === "responses") {
    payload = {
      model: FOUNDRY_DEPLOYMENT,
      input: String(prompt),
      instructions: systemPrompt,
      max_output_tokens: 400,
      temperature: 0,
    };
  } else {
    payload = {
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: String(prompt) },
      ],
      temperature: 0,
      max_tokens: 400,
    };
    if (!/\/openai\/deployments\//i.test(endpoint.url) && FOUNDRY_DEPLOYMENT) {
      payload.model = FOUNDRY_DEPLOYMENT;
    }
  }

  try {
    const res = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": FOUNDRY_API_KEY,
        Authorization: `Bearer ${FOUNDRY_API_KEY}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) return heuristic;
    const data = await res.json();
    const raw = extractAssistantMessage(data);
    const cleaned = raw.replace(/^```(?:json)?\n?|```$/gm, "").trim();
    const parsed = JSON.parse(cleaned);
    if (!Array.isArray(parsed?.actions)) return heuristic;
    const valid = parsed.actions
      .map((action) => ({
        type: action?.type,
        label: action?.label || action?.type,
      }))
      .filter((action) => ["jira_ticket", "teams_broadcast", "confluence_publish"].includes(action.type));
    return valid.length ? valid : heuristic;
  } catch {
    return heuristic;
  }
}

async function executeApprovedAction(refreshToken, scan, action) {
  switch (action.type) {
    case "jira_ticket":
      return createJiraSummaryTicketForScan(refreshToken, scan, action.note || "");
    case "teams_broadcast":
      return broadcastScanToTeams(refreshToken, scan, {
        teamId: action.teamId,
        channelId: action.channelId,
        note: action.note || "",
      });
    case "confluence_publish":
      return publishScanToConfluence(refreshToken, scan, {
        spaceId: action.spaceId,
        parentId: action.parentId || "",
        title: action.title,
        note: action.note || "",
      });
    default:
      throw new Error(`Unknown action type: ${action.type}`);
  }
}

// ── AI Agent (Microsoft Foundry) ─────────────────────────────────────────
function buildFoundryEndpoint() {
  if (!FOUNDRY_TARGET_URI) return null;

  const raw = FOUNDRY_TARGET_URI.trim().replace(/\/+$/, "");
  const lowerRaw = raw.toLowerCase();

  // Foundry/OpenAI v1-style endpoints should be used as-is (no api-version).
  if (lowerRaw.includes("/openai/v1/")) {
    return {
      url: raw,
      mode: lowerRaw.endsWith("/responses") ? "responses" : "chat-completions",
      isV1: true,
    };
  }

  let base = raw;
  let mode = "chat-completions";

  if (/\/responses$/i.test(base)) {
    mode = "responses";
  }

  if (!/\/chat\/completions$/i.test(base) && mode !== "responses") {
    if (/\/openai\/deployments\//i.test(base)) {
      base = `${base}/chat/completions`;
    } else {
      const deployment = encodeURIComponent(FOUNDRY_DEPLOYMENT);
      base = `${base}/openai/deployments/${deployment}/chat/completions`;
    }
  }

  if (!/[?&]api-version=/i.test(base)) {
    base += `${base.includes("?") ? "&" : "?"}api-version=${encodeURIComponent(FOUNDRY_API_VERSION)}`;
  }

  return { url: base, mode, isV1: false };
}

function extractAssistantMessage(data) {
  if (typeof data?.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }

  if (Array.isArray(data?.output)) {
    const out = data.output
      .flatMap((item) => item?.content || [])
      .map((c) => (typeof c?.text === "string" ? c.text : ""))
      .join("\n")
      .trim();
    if (out) return out;
  }

  const content = data?.choices?.[0]?.message?.content;
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content.map((p) => (typeof p?.text === "string" ? p.text : "")).join("\n").trim();
  }
  return "";
}

function parseWorkflowRefFromMessage(message) {
  const m = message.match(/(?:branch|ref)\s+([A-Za-z0-9._\/-]+)/i);
  return m?.[1] || "main";
}

function isWorkflowTriggerIntent(message) {
  const text = String(message || "").toLowerCase();
  return (
    /\b(run|trigger|start|launch|execute)\b/.test(text) &&
    /\b(workflow|scan|checkmate)\b/.test(text)
  ) || /\brun\s+the\s+checkmate\s+scan\b/.test(text);
}

function isJiraTicketIntent(message) {
  const text = String(message || "").toLowerCase();
  return (
    /\b(create|open|file|raise|log|make|submit|add)\b/.test(text) &&
    /\b(jira|ticket|issue|task|bug|story)\b/.test(text)
  );
}

function parseJiraSeverityFilters(message) {
  const text = String(message || "").toLowerCase();
  const severities = [];
  if (/\bhigh\b/.test(text)) severities.push("High");
  if (/\bmoderate\b/.test(text)) severities.push("Moderate");
  if (/\blow\b/.test(text)) severities.push("Low");
  if (/\binfo\b/.test(text)) severities.push("Info");
  if (/\bgen\s*ai\b|\bgenai\b/.test(text)) severities.push("GenAI");
  return severities;
}

function isSeverityFilteredFindingTicketIntent(message) {
  const text = String(message || "").toLowerCase();
  return (
    parseJiraSeverityFilters(text).length > 0 &&
    /\b(finding|findings|issue|issues)\b/.test(text) &&
    /\b(create|open|file|raise|log|make|submit|add)\b/.test(text) &&
    /\b(ticket|tickets|issue|issues|task|tasks|bug|bugs|story|stories)\b/.test(text)
  );
}

function isJiraBoardIntent(message) {
  const text = String(message || "").toLowerCase();
  if (!/\bboard\b/.test(text) && isSeverityFilteredFindingTicketIntent(text)) return false;
  // Explicit board/sprint mention
  if (/\b(create|set\s*up|make|build|generate)\b/.test(text) && /\bboard\b/.test(text)) return true;
  // "create all/every/each/bulk tickets for scan"
  if (
    /\b(create|file|open|raise|log|make)\b/.test(text) &&
    /\b(all|every|each|bulk)\b/.test(text) &&
    /\b(ticket|issue|task)s?\b/.test(text)
  ) return true;
  // "create tickets for this scan / all findings"
  if (
    /\b(create|file|open|raise)\b/.test(text) &&
    /\b(ticket|issue|task)s?\b/.test(text) &&
    /\b(this\s+scan|current\s+scan|all\s+finding|each\s+finding|every\s+finding|the\s+scan)\b/.test(text)
  ) return true;
  return false;
}

function isConfluencePublishIntent(message) {
  const text = String(message || "").toLowerCase();
  const asksToCreate = /\b(create|publish|write|make|generate|post|save|add|share)\b/.test(text);
  const mentionsConfluence = /\bconfluence\b|\bwiki\b/.test(text);
  const mentionsArtifact = /\b(page|report|analysis|summary|document|doc)\b/.test(text);
  const mentionsSecurityContent = /\bsecurity\b|\banalysis\b|\bscan\b|\breport\b|\bfinding\b/.test(text);
  return (
    asksToCreate &&
    mentionsConfluence &&
    (mentionsArtifact || mentionsSecurityContent)
  );
}

function isConfluencePageIntent(message) {
  const text = String(message || "").toLowerCase();
  return (
    /\b(create|publish|write|make|post|add|save|draft)\b/.test(text) &&
    /\bconfluence\b|\bwiki\b/.test(text) &&
    /\bpage|document|doc|note|notes\b/.test(text)
  );
}

function isTeamsMessageIntent(message) {
  const text = String(message || "").toLowerCase();
  return (
    /\b(send|post|publish|publishing|share|notify|alert|broadcast|message|announce|write)\b/.test(text) &&
    /\bteams\b|\bmicrosoft teams\b|\bchannel\b/.test(text)
  );
}

function isTeamsScanBroadcastIntent(message) {
  const text = String(message || "").toLowerCase();
  if (!isTeamsMessageIntent(text)) return false;
  const mentionsScanData = /\b(scan|checkmate|finding|findings|result|results|vulnerabilit(?:y|ies)|security\s+scan)\b/.test(text);
  const wantsLatestOrSummary = /\b(latest|current|this|summary|report|analysis|publish)\b/.test(text);
  return mentionsScanData && wantsLatestOrSummary;
}

function parseConfluenceTitleFromMessage(message) {
  const match = String(message || "").match(/\b(?:titled|called|named)\s+["']?([^"'`\n]+)["']?/i);
  return match?.[1]?.trim().slice(0, 240) || "";
}

function parseTeamsMessageBody(message) {
  const text = String(message || "").trim();
  const quoted = text.match(/["“]([^"”]+)["”]/);
  if (quoted?.[1]) return quoted[1].trim();

  const stripped = text
    .replace(/\b(send|post|share|notify|message|announce|write)\b/i, "")
    .replace(/\b(to|in|on)\b\s+(my\s+)?(microsoft\s+teams|teams|channel)\b/i, "")
    .replace(/\bchannel\b/i, "")
    .trim();
  return stripped || text;
}

function buildConfluencePageBodyFromMessage(message) {
  const text = String(message || "").trim();
  const contentMatch = text.match(/\b(?:with content|saying|that says|body)\b[:\s]+([\s\S]+)/i);
  if (contentMatch?.[1]?.trim()) return contentMatch[1].trim();
  return `Requested via AI chat:\n\n${text}`;
}

async function loadRequestedOrLatestScan(scanId) {
  const requestedId = String(scanId || "").trim();
  if (requestedId) {
    if (!/^[0-9a-f-]{36}$/.test(requestedId)) {
      throw new Error("Selected scan id is invalid.");
    }
    const scan = await getScanWithFindings(requestedId);
    if (!scan) throw new Error("Selected scan not found.");
    return { scan, usedLatest: false };
  }

  const scans = await listScans();
  if (!Array.isArray(scans) || !scans.length) {
    throw new Error("No Checkmate scans are available yet. Run a scan first.");
  }

  const latestId = scans[0]?.id;
  if (!latestId) throw new Error("Latest scan could not be resolved.");

  const latestScan = await getScanWithFindings(latestId);
  if (!latestScan) throw new Error("Latest scan details could not be loaded.");
  return { scan: latestScan, usedLatest: true };
}

function messageRequestsLatestScan(message) {
  const text = String(message || "").toLowerCase();
  return /\blatest\b/.test(text) && /\b(scan|finding|findings|summary|report|analysis|result|results)\b/.test(text);
}

// ── Shared: download + import report files from GitHub ────────────────────
// Used by both GET /api/reports (user-initiated) and POST /webhooks/github
// (automated). Accepts an already-resolved githubToken so callers can get
// the token via Token Vault however is appropriate for their context.
async function downloadAndImportReports(githubToken, {
  repoOwner = GITHUB_REPO_OWNER,
  repoName = GITHUB_REPO_NAME,
  branch = "main",
} = {}) {
  const contentsUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/contents/reports?ref=${branch}`;
  const ghRes = await fetch(contentsUrl, {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!ghRes.ok) {
    const body = await ghRes.text();
    throw new Error(`GitHub ${ghRes.status} fetching reports folder: ${body}`);
  }

  const items = await ghRes.json();
  if (!Array.isArray(items)) throw new Error("Unexpected response from GitHub Contents API.");

  const fileItems = items.filter((i) => i.type === "file");
  const downloaded = [];
  const downloadedAt = new Date().toISOString();

  for (const file of fileItems) {
    // Sanitise filename to prevent path traversal
    const safeName = path.basename(file.name);
    const dest = path.join(REPORTS_DIR, safeName);

    const dlRes = await fetch(file.download_url, {
      headers: { Authorization: `Bearer ${githubToken}` },
    });

    if (!dlRes.ok) {
      console.warn(`[Reports] Failed to download ${safeName}: HTTP ${dlRes.status}`);
      continue;
    }

    const buffer = await dlRes.buffer();
    await fsPromises.writeFile(dest, buffer);
    console.log(`[Reports] Downloaded: ${safeName} (${file.size} bytes)`);

    let scanId = null;
    let dbInserted = false;
    if (safeName.endsWith(".json")) {
      try {
        const findings = JSON.parse(buffer.toString("utf8"));
        if (Array.isArray(findings)) {
          const result = await upsertScan(safeName, findings);
          scanId = result.scanId;
          dbInserted = result.inserted;
          console.log(`[Reports] DB upsert ${safeName}: scanId=${scanId} inserted=${dbInserted}`);
        }
      } catch (dbErr) {
        console.error(`[Reports] DB upsert failed for ${safeName}:`, dbErr.message);
        console.error(
          `[Reports] DB upsert diagnostics file=${safeName} ` +
          `name=${dbErr.name || "n/a"} code=${dbErr.code || "n/a"}`
        );
        if (dbErr.stack) {
          const stackTop = dbErr.stack.split("\n").slice(0, 4).join(" | ");
          console.error(`[Reports] DB upsert stack ${safeName}: ${stackTop}`);
        }
      }
    }

    downloaded.push({
      name: safeName,
      size: file.size,
      sha: file.sha,
      githubUrl: file.html_url,
      localUrl: `/reports/${encodeURIComponent(safeName)}`,
      scanId,
      downloadedAt,
    });
  }

  return { files: downloaded, repo: `${repoOwner}/${repoName}`, branch };
}

function buildJiraTicketDraftsFromFindings(scan, findings) {
  const scanDate = getScanDateLabel(scan);
  return (findings || []).map((finding) => {
    const summary = `[${finding.severity || "Info"}] ${finding.title || "Security Finding"}`.slice(0, 200);
    let descText = "";
    if (finding.description) descText += `${finding.description}\n\n`;
    if (finding.advisory?.issue) descText += `Advisory: ${finding.advisory.issue}\n`;
    const fixSteps = finding.advisory?.how_to_fix;
    if (Array.isArray(fixSteps) && fixSteps.length) {
      descText += `How to fix:\n${fixSteps.map((item) => `• ${item}`).join("\n")}\n`;
    }
    const details = Array.isArray(finding.details) ? finding.details : [];
    if (details.length) {
      descText += `\nIssues (${details.length}):\n`;
      descText += details
        .slice(0, 20)
        .map((detail) => `• ${detail.item_name || detail.name || ""}: ${detail.message || ""}`.trim())
        .join("\n");
    }
    descText += `\n\nScan: ${scan.file_name} | Scanned: ${scanDate} | Severity: ${finding.severity || "Info"}`;
    return {
      summary,
      description: descText.slice(0, 32000),
      severity: finding.severity || "Info",
      findingTitle: finding.title || "Security Finding",
    };
  });
}

async function dispatchCheckmateWorkflow(refreshToken, ref = "main") {
  let githubToken;
  try {
    githubToken = await getGitHubTokenFromVault(refreshToken);
  } catch (err) {
    return { success: false, status: 502, error: err.message };
  }

  const url = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/actions/workflows/${GITHUB_WORKFLOW_ID}/dispatches`;
  try {
    const ghRes = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${githubToken}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({ ref }),
    });

    if (ghRes.status === 204) {
      return { success: true, status: 200 };
    }

    const errText = await ghRes.text();
    let errBody;
    try { errBody = JSON.parse(errText); } catch { errBody = { message: errText }; }
    return {
      success: false,
      status: ghRes.status,
      error: errBody?.message || `GitHub dispatch failed with ${ghRes.status}`,
      githubError: errBody,
      url,
    };
  } catch (err) {
    return { success: false, status: 500, error: "Internal server error." };
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForWorkflowCompletion(refreshToken, {
  ref = "main",
  startedAtMs = Date.now(),
  timeoutMs = 8 * 60 * 1000,
  pollMs = 10 * 1000,
} = {}) {
  let githubToken;
  try {
    githubToken = await getGitHubTokenFromVault(refreshToken);
  } catch (err) {
    return { completed: false, reason: `token_error:${err.message}` };
  }

  const startedCutoff = startedAtMs - 2 * 60 * 1000;
  const deadline = Date.now() + timeoutMs;
  const url = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/actions/workflows/${GITHUB_WORKFLOW_ID}/runs?per_page=15`;

  while (Date.now() < deadline) {
    try {
      const ghRes = await fetch(url, {
        headers: {
          Authorization: `Bearer ${githubToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });

      if (ghRes.ok) {
        const data = await ghRes.json();
        const runs = Array.isArray(data.workflow_runs) ? data.workflow_runs : [];

        const candidate = runs.find((run) => {
          const createdAt = new Date(run.created_at || 0).getTime();
          const branchMatch = !ref || String(run.head_branch || "") === String(ref);
          return branchMatch && createdAt >= startedCutoff;
        }) || null;

        if (candidate && candidate.status === "completed") {
          return {
            completed: true,
            run: candidate,
          };
        }
      } else {
        const body = await ghRes.text();
        console.warn(`[AI Orchestrator] Workflow polling failed HTTP ${ghRes.status}: ${body}`);
      }
    } catch (err) {
      console.warn(`[AI Orchestrator] Workflow polling error: ${err.message}`);
    }

    await sleep(pollMs);
  }

  return { completed: false, reason: "timeout" };
}

async function createJiraBoardAndTicketsForScan(refreshToken, scan) {
  const jiraToken = await getJiraTokenFromVault(refreshToken);
  const cloud = await resolveJiraCloudByToken(jiraToken);

  const scanDate = getScanDateLabel(scan);
  const boardName = `Checkmate: ${scan.file_name.replace(/\.json$/i, "")} (${scanDate})`.slice(0, 100);
  const scanLabel = `checkmate-${scanDate}`.replace(/[^a-zA-Z0-9_-]/g, "-");

  let boardId = null;
  let boardUrl = null;
  let boardError = null;

  try {
    const boardRes = await fetch(
      `https://api.atlassian.com/ex/jira/${cloud.cloudId}/rest/agile/1.0/board`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jiraToken}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: boardName,
          type: "kanban",
          location: { type: "project", projectKeyOrId: JIRA_PROJECT_KEY },
        }),
      }
    );
    const boardBody = await boardRes.json();
    if (boardRes.ok && boardBody?.id) {
      boardId = boardBody.id;
      boardUrl = `${cloud.siteUrl.replace(/\/+$/, "")}/jira/software/projects/${JIRA_PROJECT_KEY}/boards/${boardId}`;
    } else {
      boardError = boardBody?.errorMessages?.join("; ") || boardBody?.message || `HTTP ${boardRes.status}`;
      console.warn("[JiraBoard] Board creation failed:", boardError);
    }
  } catch (err) {
    boardError = err.message;
    console.warn("[JiraBoard] Board creation error:", err.message);
  }

  const sortedFindings = getSortedFindings(scan.findings || []).slice(0, 50);
  const createdTickets = [];
  const ticketErrors = [];

  for (const finding of sortedFindings) {
    const summary = `[${finding.severity || "Info"}] ${finding.title || "Security Finding"}`.slice(0, 200);

    let descText = "";
    if (finding.description) descText += `${finding.description}\n\n`;
    if (finding.advisory?.issue) descText += `Advisory: ${finding.advisory.issue}\n`;
    const fixSteps = finding.advisory?.how_to_fix;
    if (Array.isArray(fixSteps) && fixSteps.length) {
      descText += `How to fix:\n${fixSteps.map((h) => `• ${h}`).join("\n")}\n`;
    }
    const details = Array.isArray(finding.details) ? finding.details : [];
    if (details.length) {
      descText += `\nIssues (${details.length}):\n`;
      descText += details
        .slice(0, 20)
        .map((d) => `• ${d.item_name || d.name || ""}: ${d.message || ""}`.trim())
        .join("\n");
    }
    descText += `\n\nScan: ${scan.file_name} | Scanned: ${scanDate} | Severity: ${finding.severity || "Info"}`;

    const payload = {
      fields: {
        project: { key: JIRA_PROJECT_KEY },
        summary,
        issuetype: { name: JIRA_ISSUE_TYPE },
        labels: [scanLabel],
        description: {
          type: "doc",
          version: 1,
          content: [{
            type: "paragraph",
            content: [{ type: "text", text: descText.slice(0, 32000) }],
          }],
        },
      },
    };

    try {
      const issueRes = await fetch(
        `https://api.atlassian.com/ex/jira/${cloud.cloudId}/rest/api/3/issue`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${jiraToken}`,
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );
      const issueBody = await issueRes.json();
      if (issueRes.ok && issueBody?.key) {
        createdTickets.push({
          key: issueBody.key,
          severity: finding.severity || "Info",
          summary: finding.title || "Security Finding",
          url: `${cloud.siteUrl.replace(/\/+$/, "")}/browse/${issueBody.key}`,
        });
      } else {
        const errMsg = issueBody?.errorMessages?.join("; ") || issueBody?.message || `HTTP ${issueRes.status}`;
        ticketErrors.push(`${finding.title || "Finding"}: ${errMsg}`);
      }
    } catch (err) {
      ticketErrors.push(`${finding.title || "Finding"}: ${err.message}`);
    }
  }

  if (!createdTickets.length) {
    throw new Error(`Failed to create any JIRA tickets: ${ticketErrors.join("; ")}`);
  }

  return {
    board: boardUrl ? { id: boardId, url: boardUrl, name: boardName } : null,
    boardError,
    tickets: createdTickets,
    ticketErrors,
    scanLabel,
  };
}

function buildAIApprovalPlan(message, flags) {
  const steps = [];
  if (flags.wantsWorkflow) steps.push("Run Auth0 CheckMate security scan workflow");
  if (flags.wantsConfluence || flags.wantsConfluencePage) steps.push("Create/publish a Confluence page with scan summary");
  if (flags.wantsJiraBoard) steps.push("Create a JIRA board and tickets for scan findings");
  if (flags.wantsJiraTicket && !flags.wantsJiraBoard) steps.push("Create JIRA ticket(s)");
  if (flags.wantsTeams) steps.push("Broadcast summary to Microsoft Teams");

  return {
    summary: `Execute ${steps.length || 1} task(s) requested by AI instruction`,
    steps,
    prompt: String(message || ""),
  };
}

function createAIChatApproval(userSub, plan, message) {
  const id = crypto.randomUUID();
  const now = Date.now();
  const approval = {
    id,
    userSub,
    plan,
    message: String(message || ""),
    status: "pending",
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 10 * 60 * 1000).toISOString(),
  };
  aiChatApprovals.set(id, approval);
  return approval;
}

function validateAndConsumeAIChatApproval({ approvalId, userSub, message }) {
  const approval = aiChatApprovals.get(String(approvalId || ""));
  if (!approval) return { ok: false, error: "Approval not found. Please request approval again." };
  if (approval.userSub !== userSub) return { ok: false, error: "Approval does not belong to this user." };
  if (approval.status !== "pending") return { ok: false, error: "Approval is no longer pending." };
  if (new Date(approval.expiresAt).getTime() < Date.now()) {
    aiChatApprovals.delete(approval.id);
    return { ok: false, error: "Approval expired. Please request approval again." };
  }
  if (String(approval.message || "") !== String(message || "")) {
    return { ok: false, error: "Prompt changed after approval request. Please request approval again." };
  }

  approval.status = "approved";
  aiChatApprovals.delete(approval.id);
  return { ok: true, approval };
}

app.post("/api/ai/chat", requiresAuth(), async (req, res) => {
  const userMessage = String(req.body?.message || "").trim();
  const scanContext = String(req.body?.context || "").trim();
  const scanId = String(req.body?.scanId || "").trim();
  const teamsTeamId = String(req.body?.teamsTeamId || "").trim();
  const teamsChannelId = String(req.body?.teamsChannelId || "").trim();
  const confluenceSpaceId = String(req.body?.confluenceSpaceId || "").trim();
  const confluenceParentId = String(req.body?.confluenceParentId || "").trim();
  const approvalId = String(req.body?.approvalId || "").trim();
  const approve = req.body?.approve === true;
  if (!userMessage) return res.status(400).json({ error: "Message is required." });

  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.status(400).json({ error: "No refresh token. Log out and log in again." });
  }

  const wantsWorkflow = isWorkflowTriggerIntent(userMessage);
  const wantsConfluence = isConfluencePublishIntent(userMessage);
  const wantsConfluencePage = isConfluencePageIntent(userMessage);
  const wantsJiraBoard = isJiraBoardIntent(userMessage);
  const wantsJiraTicket = isJiraTicketIntent(userMessage);
  const wantsTeams = isTeamsMessageIntent(userMessage);
  const hasActionableIntent = wantsWorkflow || wantsConfluence || wantsConfluencePage || wantsJiraBoard || wantsJiraTicket || wantsTeams;

  if (hasActionableIntent && !approve) {
    const plan = buildAIApprovalPlan(userMessage, {
      wantsWorkflow,
      wantsConfluence,
      wantsConfluencePage,
      wantsJiraBoard,
      wantsJiraTicket,
      wantsTeams,
    });
    const approval = createAIChatApproval(getUserSub(req), plan, userMessage);
    return res.json({
      reply: "Approval required before executing this instruction.",
      approvalRequired: true,
      approval,
    });
  }

  if (hasActionableIntent && approve) {
    const validation = validateAndConsumeAIChatApproval({
      approvalId,
      userSub: getUserSub(req),
      message: userMessage,
    });
    if (!validation.ok) {
      return res.status(400).json({ error: validation.error });
    }
  }

  // Multi-step orchestration for compound prompts (trigger scan, then post actions).
  if (wantsWorkflow && (wantsConfluence || wantsJiraBoard || wantsTeams)) {
    const ref = parseWorkflowRefFromMessage(userMessage);
    const runRequestedAt = Date.now();
    const dispatch = await dispatchCheckmateWorkflow(refreshToken, ref);

    if (!dispatch.success) {
      const errText = String(dispatch.error || "").toLowerCase();
      if (
        errText.includes("federated connection refresh token not found") ||
        errText.includes("connected account") ||
        errText.includes("token vault")
      ) {
        return res.json({
          reply: "GitHub integration is not connected. Please enable GitHub integration first to run an Auth0 CheckMate security scan.",
        });
      }
      return res.status(dispatch.status || 500).json({
        error: dispatch.error || "Failed to trigger Checkmate workflow.",
      });
    }

    const lines = [`Started Checkmate workflow on ref "${ref}".`];
    const waitResult = await waitForWorkflowCompletion(refreshToken, {
      ref,
      startedAtMs: runRequestedAt,
    });

    if (!waitResult.completed) {
      lines.push(
        "The workflow has not completed yet, so follow-up Confluence/JIRA/Teams actions were not executed in this run. " +
        "Please try again after the run completes."
      );
      return res.json({ reply: lines.join("\n\n") });
    }

    const run = waitResult.run || {};
    if (run.conclusion !== "success") {
      lines.push(`Workflow completed with conclusion "${run.conclusion || "unknown"}". Follow-up actions were skipped.`);
      if (run.html_url) lines.push(`Run URL: ${run.html_url}`);
      return res.json({ reply: lines.join("\n\n") });
    }

    if (run.html_url) lines.push(`Workflow completed successfully.\n${run.html_url}`);
    else lines.push("Workflow completed successfully.");

    try {
      const githubToken = await getGitHubTokenFromVault(refreshToken);
      await downloadAndImportReports(githubToken, { branch: run.head_branch || ref });
      lines.push("Latest scan reports were synced from GitHub into the database.");
    } catch (err) {
      lines.push(`Report sync after completion failed: ${err.message}`);
    }

    let scanInfo;
    try {
      scanInfo = await loadRequestedOrLatestScan("");
      lines.push(`Using scan: ${buildScanHeadline(scanInfo.scan)}`);
    } catch (err) {
      lines.push(`Could not load latest scan for follow-up actions: ${err.message}`);
      return res.json({ reply: lines.join("\n\n") });
    }

    if (wantsConfluence) {
      try {
        const result = await publishScanToConfluence(refreshToken, scanInfo.scan, {
          spaceId: confluenceSpaceId || CONFLUENCE_SPACE_ID,
          title: `Checkmate Security Analysis — ${buildScanHeadline(scanInfo.scan)}`.slice(0, 240),
          note: "Created automatically after workflow completion from AI multi-step request.",
        });
        lines.push(`Confluence page created:\n${result.title}\n${result.url}`);
      } catch (err) {
        lines.push(`Confluence step failed: ${err.message}`);
      }
    }

    if (wantsJiraBoard) {
      try {
        const jiraResult = await createJiraBoardAndTicketsForScan(refreshToken, scanInfo.scan);
        if (jiraResult.board?.url) {
          lines.push(`JIRA board created:\n${jiraResult.board.url}`);
        } else if (jiraResult.boardError) {
          lines.push(`JIRA board creation failed: ${jiraResult.boardError}`);
        }
        lines.push(`Created ${jiraResult.tickets.length} JIRA ticket(s) for scan findings.`);
        if (jiraResult.ticketErrors.length) {
          lines.push(`${jiraResult.ticketErrors.length} ticket(s) failed: ${jiraResult.ticketErrors.join("; ")}`);
        }
      } catch (err) {
        lines.push(`JIRA board/ticket step failed: ${err.message}`);
      }
    }

    if (wantsTeams) {
      try {
        const result = await broadcastScanToTeams(refreshToken, scanInfo.scan, {
          teamId: teamsTeamId || TEAMS_DEFAULT_TEAM_ID,
          channelId: teamsChannelId || TEAMS_DEFAULT_CHANNEL_ID,
          note: "Automated broadcast after workflow completion from AI multi-step request.",
        });
        lines.push(`Teams broadcast posted to team ${result.teamId}, channel ${result.channelId}.`);
      } catch (err) {
        lines.push(`Teams broadcast step failed: ${err.message}`);
      }
    }

    return res.json({
      reply: lines.join("\n\n"),
    });
  }

  // Intent-based command routing: trigger workflow directly from chat.
  if (wantsWorkflow) {
    const ref = parseWorkflowRefFromMessage(userMessage);
    const dispatch = await dispatchCheckmateWorkflow(refreshToken, ref);
    if (dispatch.success) {
      return res.json({
        reply: `Checkmate workflow triggered successfully on ref \"${ref}\".`,
      });
    }

    const errText = String(dispatch.error || "").toLowerCase();
    if (
      errText.includes("federated connection refresh token not found") ||
      errText.includes("connected account") ||
      errText.includes("token vault")
    ) {
      return res.json({
        reply: "GitHub integration is not connected. Please enable GitHub integration first to run an Auth0 CheckMate security scan.",
      });
    }

    return res.status(dispatch.status || 500).json({
      error: dispatch.error || "Failed to trigger Checkmate workflow.",
    });
  }

  if (isConfluencePublishIntent(userMessage)) {
    const cfgErr = integrationConfigError("confluence");
    if (cfgErr) {
      return res.json({
        reply: `Confluence is not configured on the server: ${cfgErr}`,
      });
    }

    let scanInfo;
    try {
      scanInfo = await loadRequestedOrLatestScan(messageRequestsLatestScan(userMessage) ? "" : scanId);
    } catch (err) {
      return res.json({ reply: err.message });
    }

    const userSub = getUserSub(req);
    const pageTitle =
      parseConfluenceTitleFromMessage(userMessage) ||
      `Checkmate Security Analysis — ${buildScanHeadline(scanInfo.scan)}`.slice(0, 240);
    const note = `Requested via AI chat: ${userMessage}`;

    try {
      const result = await publishScanToConfluence(refreshToken, scanInfo.scan, {
        title: pageTitle,
        note,
      });

      logActivity({
        userSub,
        type: "action",
        integration: "confluence",
        status: "success",
        message: `Published Confluence page "${result.title}" from AI chat.`,
        detail: result.url,
      });

      const scopeNote = scanInfo.usedLatest
        ? `using the latest available scan, ${buildScanHeadline(scanInfo.scan)}`
        : `for ${buildScanHeadline(scanInfo.scan)}`;

      return res.json({
        reply:
          `Created a Confluence security analysis page ${scopeNote}.\n\n` +
          `${result.title}\n${result.url}`,
        confluencePage: result,
      });
    } catch (err) {
      let account = null;
      try {
        account = await getIntegrationConnectedAccount(refreshToken, "confluence", userSub);
      } catch (accountErr) {
        const detail = isRateLimitError(accountErr)
          ? "Auth0 rate limit reached while checking your Confluence connection. Please wait a few seconds and try again."
          : `Unable to check your Confluence Token Vault connection: ${accountErr.message}`;
        return res.json({ reply: detail });
      }

      if (!account) {
        return res.json({
          reply: "Confluence is not connected. Please connect your Confluence account from the Integrations section first, then try again.",
        });
      }

      logActivity({
        userSub,
        type: "action",
        integration: "confluence",
        status: "error",
        message: "AI chat Confluence publish failed.",
        detail: err.message,
      });

      return res.json({
        reply: `Confluence is connected, but the page could not be created: ${err.message}`,
      });
    }
  }

  if (isConfluencePageIntent(userMessage)) {
    const cfgErr = integrationConfigError("confluence");
    if (cfgErr) return res.json({ reply: `Confluence is not configured on the server: ${cfgErr}` });

    const pageTitle =
      parseConfluenceTitleFromMessage(userMessage) ||
      "Confluence Page from Checkmate AI";
    const pageContent = buildConfluencePageBodyFromMessage(userMessage);

    try {
      const result = await createConfluencePage(refreshToken, {
        spaceId: confluenceSpaceId || CONFLUENCE_SPACE_ID,
        parentId: confluenceParentId,
        title: pageTitle,
        content: pageContent,
      });
      logActivity({
        userSub: getUserSub(req),
        type: "action",
        integration: "confluence",
        status: "success",
        message: `Created Confluence page "${result.title}" from AI chat.`,
        detail: result.url,
      });
      return res.json({
        reply: `Created a Confluence page.\n\n${result.title}\n${result.url}`,
        confluencePage: result,
      });
    } catch (err) {
      return res.json({
        reply: `I couldn't create the Confluence page: ${err.message}`,
      });
    }
  }

  if (isTeamsMessageIntent(userMessage)) {
    const cfgErr = integrationConfigError("teams");
    if (cfgErr) return res.json({ reply: `Microsoft Teams is not configured on the server: ${cfgErr}` });

    if (isTeamsScanBroadcastIntent(userMessage)) {
      let scanInfo;
      try {
        scanInfo = await loadRequestedOrLatestScan(messageRequestsLatestScan(userMessage) ? "" : scanId);
      } catch (err) {
        return res.json({ reply: err.message });
      }

      try {
        const result = await broadcastScanToTeams(refreshToken, scanInfo.scan, {
          teamId: teamsTeamId || TEAMS_DEFAULT_TEAM_ID,
          channelId: teamsChannelId || TEAMS_DEFAULT_CHANNEL_ID,
          note: "Published from Dashboard AI Agent request.",
        });

        logActivity({
          userSub: getUserSub(req),
          type: "action",
          integration: "teams",
          status: "success",
          message: `Posted scan summary to Teams channel ${result.channelId} from AI chat.`,
          detail: buildScanHeadline(scanInfo.scan),
        });

        return res.json({
          reply:
            `Published the ${scanInfo.usedLatest ? "latest" : "selected"} scan summary to Microsoft Teams.\n\n` +
            `${buildScanHeadline(scanInfo.scan)}\n` +
            `Team: ${result.teamId}\nChannel: ${result.channelId}`,
          teamsMessage: result,
        });
      } catch (err) {
        return res.json({
          reply: `I couldn't publish scan results to Microsoft Teams: ${err.message}`,
        });
      }
    }

    const content = parseTeamsMessageBody(userMessage);
    try {
      const result = await sendCustomTeamsMessage(refreshToken, {
        teamId: teamsTeamId || TEAMS_DEFAULT_TEAM_ID,
        channelId: teamsChannelId || TEAMS_DEFAULT_CHANNEL_ID,
        message: content,
      });
      logActivity({
        userSub: getUserSub(req),
        type: "action",
        integration: "teams",
        status: "success",
        message: `Posted Teams message from AI chat to channel ${result.channelId}.`,
        detail: result.message,
      });
      return res.json({
        reply: `Posted your message to Microsoft Teams.\n\n${result.message}`,
        teamsMessage: result,
      });
    } catch (err) {
      return res.json({
        reply: `I couldn't post to Microsoft Teams: ${err.message}`,
      });
    }
  }

  // ── Intent: create JIRA board + one ticket per finding for the selected scan ──
  if (isJiraBoardIntent(userMessage)) {
    const cfgErr = jiraConfigError();
    if (cfgErr) return res.json({ reply: `JIRA is not configured on the server: ${cfgErr}` });

    let jiraToken;
    try {
      jiraToken = await getJiraTokenFromVault(refreshToken);
    } catch (err) {
      let jiraAccount = null;
      try {
        jiraAccount = await getJiraConnectedAccount(refreshToken);
      } catch (accountErr) {
        const detail = isRateLimitError(accountErr)
          ? "Auth0 rate limit reached while checking your JIRA connection. Please wait a few seconds and try again."
          : `Unable to check your JIRA Token Vault connection: ${accountErr.message}`;
        return res.json({ reply: detail });
      }

      if (!jiraAccount) {
        return res.json({
          reply: "JIRA is not connected. Connect your JIRA account from the home page first, then try again.",
        });
      }

      return res.json({
        reply: `JIRA is connected, but Token Vault could not mint an Atlassian access token: ${err.message}`,
      });
    }

    if (!scanId || !/^[0-9a-f-]{36}$/.test(scanId)) {
      return res.json({
        reply: "No scan is currently selected. Please click a scan in the sidebar to select it, then ask again.",
      });
    }

    let scan;
    try {
      scan = await getScanWithFindings(scanId);
    } catch (err) {
      return res.status(500).json({ error: `Failed to load scan: ${err.message}` });
    }
    if (!scan) return res.json({ reply: "Selected scan not found. Try selecting a different scan." });

    const findings = scan.findings || [];
    if (!findings.length) {
      return res.json({ reply: "The selected scan has no findings to create tickets for." });
    }

    let cloud;
    try {
      cloud = await resolveJiraCloudByToken(jiraToken);
    } catch (err) {
      return res.status(502).json({ error: `Failed to resolve JIRA cloud: ${err.message}` });
    }

    const scanDate = new Date(scan.scanned_at).toISOString().slice(0, 10);
    const boardName = `Checkmate: ${scan.file_name.replace(/\.json$/i, "")} (${scanDate})`.slice(0, 100);
    const scanLabel = `checkmate-${scanDate}`.replace(/[^a-zA-Z0-9_-]/g, "-");

    // ── Step 1: Create a JIRA Kanban board ─────────────────────────────
    let boardId = null;
    let boardUrl = null;
    let boardError = null;

    try {
      const boardRes = await fetch(
        `https://api.atlassian.com/ex/jira/${cloud.cloudId}/rest/agile/1.0/board`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${jiraToken}`,
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: boardName,
            type: "kanban",
            location: { type: "project", projectKeyOrId: JIRA_PROJECT_KEY },
          }),
        }
      );
      const boardBody = await boardRes.json();
      if (boardRes.ok && boardBody?.id) {
        boardId = boardBody.id;
        boardUrl = `${cloud.siteUrl.replace(/\/+$/, "")}/jira/software/projects/${JIRA_PROJECT_KEY}/boards/${boardId}`;
      } else {
        boardError = boardBody?.errorMessages?.join("; ") || boardBody?.message || `HTTP ${boardRes.status}`;
        console.warn("[JiraBoard] Board creation failed:", boardError);
      }
    } catch (err) {
      boardError = err.message;
      console.warn("[JiraBoard] Board creation error:", err.message);
    }

    // ── Step 2: Create one ticket per finding ──────────────────────────
    const SEV_ORDER_LOCAL = { High: 0, Moderate: 1, Low: 2, Info: 3, GenAI: 4 };
    const sortedFindings = [...findings]
      .sort((a, b) => (SEV_ORDER_LOCAL[a.severity] ?? 9) - (SEV_ORDER_LOCAL[b.severity] ?? 9))
      .slice(0, 50);

    const createdTickets = [];
    const ticketErrors = [];

    for (const finding of sortedFindings) {
      const summary = `[${finding.severity || "Info"}] ${finding.title || "Security Finding"}`.slice(0, 200);

      let descText = "";
      if (finding.description) descText += `${finding.description}\n\n`;
      if (finding.advisory?.issue) descText += `Advisory: ${finding.advisory.issue}\n`;
      const fixSteps = finding.advisory?.how_to_fix;
      if (Array.isArray(fixSteps) && fixSteps.length) {
        descText += `How to fix:\n${fixSteps.map((h) => `• ${h}`).join("\n")}\n`;
      }
      const details = Array.isArray(finding.details) ? finding.details : [];
      if (details.length) {
        descText += `\nIssues (${details.length}):\n`;
        descText += details
          .slice(0, 20)
          .map((d) => `• ${d.item_name || d.name || ""}: ${d.message || ""}`.trim())
          .join("\n");
      }
      descText += `\n\nScan: ${scan.file_name} | Scanned: ${scanDate} | Severity: ${finding.severity || "Info"}`;

      const payload = {
        fields: {
          project: { key: JIRA_PROJECT_KEY },
          summary,
          issuetype: { name: JIRA_ISSUE_TYPE },
          labels: [scanLabel],
          description: {
            type: "doc",
            version: 1,
            content: [{
              type: "paragraph",
              content: [{ type: "text", text: descText.slice(0, 32000) }],
            }],
          },
        },
      };

      try {
        const issueRes = await fetch(
          `https://api.atlassian.com/ex/jira/${cloud.cloudId}/rest/api/3/issue`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${jiraToken}`,
              Accept: "application/json",
              "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
          }
        );
        const issueBody = await issueRes.json();
        if (issueRes.ok && issueBody?.key) {
          createdTickets.push({
            key: issueBody.key,
            severity: finding.severity || "Info",
            summary: finding.title || "Security Finding",
            url: `${cloud.siteUrl.replace(/\/+$/, "")}/browse/${issueBody.key}`,
          });
        } else {
          const errMsg = issueBody?.errorMessages?.join("; ") || issueBody?.message || `HTTP ${issueRes.status}`;
          ticketErrors.push(`${finding.title || "Finding"}: ${errMsg}`);
          console.warn("[JiraBoard] Ticket creation failed:", errMsg);
        }
      } catch (err) {
        ticketErrors.push(`${finding.title || "Finding"}: ${err.message}`);
      }
    }

    if (!createdTickets.length) {
      return res.status(502).json({
        error: `Failed to create any JIRA tickets: ${ticketErrors.join("; ")}`,
      });
    }

    const lines = [];
    if (boardUrl) {
      lines.push(`JIRA board created: "${boardName}"\n${boardUrl}`);
    } else {
      lines.push(
        `Note: Board creation failed (${boardError}). ` +
        `You may need to re-connect JIRA after enabling the "manage:jira-project" scope on the home page. ` +
        `Tickets were still created in project ${JIRA_PROJECT_KEY}.`
      );
    }
    lines.push(`\nCreated ${createdTickets.length} ticket(s) labelled "${scanLabel}":`);
    for (const t of createdTickets) {
      lines.push(`• [${t.severity}] ${t.key}: ${t.summary}\n  ${t.url}`);
    }
    if (ticketErrors.length) {
      lines.push(`\n${ticketErrors.length} ticket(s) failed: ${ticketErrors.join("; ")}`);
    }

    return res.json({
      reply: lines.join("\n"),
      board: boardUrl ? { id: boardId, url: boardUrl, name: boardName } : null,
      tickets: createdTickets,
    });
  }

  // ── Intent-based JIRA ticket creation ─────────────────────────────────
  if (isJiraTicketIntent(userMessage)) {
    const cfgErr = jiraConfigError();
    if (cfgErr) {
      return res.json({
        reply: `JIRA is not configured on the server: ${cfgErr}`,
      });
    }

    let jiraToken;
    try {
      jiraToken = await getJiraTokenFromVault(refreshToken);
    } catch (err) {
      let jiraAccount = null;
      try {
        jiraAccount = await getJiraConnectedAccount(refreshToken);
      } catch (accountErr) {
        const detail = isRateLimitError(accountErr)
          ? "Auth0 rate limit reached while checking your JIRA connection. Please wait a few seconds and try again."
          : `Unable to check your JIRA Token Vault connection: ${accountErr.message}`;
        return res.json({ reply: detail });
      }

      if (!jiraAccount) {
        return res.json({
          reply: "JIRA is not connected. Please connect your JIRA account from the home page first, then try again.",
        });
      }

      return res.json({
        reply: `JIRA is connected, but Token Vault could not mint an Atlassian access token: ${err.message}`,
      });
    }

    let ticketsToCreate = [];
    const requestedSeverities = parseJiraSeverityFilters(userMessage);
    if (isSeverityFilteredFindingTicketIntent(userMessage)) {
      let scanInfo;
      try {
        scanInfo = await loadRequestedOrLatestScan(messageRequestsLatestScan(userMessage) ? "" : scanId);
      } catch (err) {
        return res.json({ reply: err.message });
      }

      const matchingFindings = getSortedFindings(scanInfo.scan.findings || [])
        .filter((finding) => requestedSeverities.includes(String(finding.severity || "Info")))
        .slice(0, 10);

      if (!matchingFindings.length) {
        return res.json({
          reply: `No ${requestedSeverities.join("/")} severity findings were found in the ${scanInfo.usedLatest ? "latest" : "selected"} scan.`,
        });
      }

      ticketsToCreate = buildJiraTicketDraftsFromFindings(scanInfo.scan, matchingFindings);
    }

    // ── Use AI (Foundry) to extract structured ticket data ──────────────
    if (FOUNDRY_TARGET_URI && FOUNDRY_API_KEY) {
      const endpoint = buildFoundryEndpoint();
      if (endpoint && !ticketsToCreate.length) {
        const extractSystemPrompt = [
          "You are a JIRA ticket extraction assistant for a security platform.",
          "Based on the user instruction and scan context, extract JIRA ticket details.",
          "Respond with ONLY valid JSON (no markdown fences, no extra text) in this exact format:",
          `{"tickets":[{"summary":"ticket title (max 100 chars)","description":"detailed description with context and remediation guidance"}]}`,
          "Create one ticket per distinct security finding mentioned.",
          "When the user asks for all High/Moderate/Low findings, create one ticket per finding in that severity.",
          "If the request is too vague, create a single well-described ticket based on available context.",
        ].join("\n");

        const userContent = scanContext
          ? `Scan context:\n${scanContext}\n\nUser instruction: ${userMessage}`
          : `User instruction: ${userMessage}`;

        let extractPayload;
        if (endpoint.mode === "responses") {
          extractPayload = {
            model: FOUNDRY_DEPLOYMENT,
            input: userContent,
            instructions: extractSystemPrompt,
            max_output_tokens: 1500,
            temperature: 0.1,
          };
        } else {
          extractPayload = {
            messages: [
              { role: "system", content: extractSystemPrompt },
              { role: "user", content: userContent },
            ],
            temperature: 0.1,
            max_tokens: 1500,
          };
          if (!/\/openai\/deployments\//i.test(endpoint.url) && FOUNDRY_DEPLOYMENT) {
            extractPayload.model = FOUNDRY_DEPLOYMENT;
          }
        }

        try {
          const aiRes = await fetch(endpoint.url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "api-key": FOUNDRY_API_KEY,
              Authorization: `Bearer ${FOUNDRY_API_KEY}`,
            },
            body: JSON.stringify(extractPayload),
          });

          if (aiRes.ok) {
            const aiData = await aiRes.json();
            const rawText = extractAssistantMessage(aiData);
            let parsed = null;
            try {
              const jsonStr = rawText.replace(/^```(?:json)?\n?|```$/gm, "").trim();
              parsed = JSON.parse(jsonStr);
            } catch {
              const match = rawText.match(/\{[\s\S]*\}/);
              if (match) {
                try { parsed = JSON.parse(match[0]); } catch { /* fall through */ }
              }
            }
            if (parsed?.tickets && Array.isArray(parsed.tickets)) {
              ticketsToCreate = parsed.tickets.filter((t) => t?.summary);
            }
          }
        } catch (aiErr) {
          console.error("[AI Chat / JIRA extract] Foundry error:", aiErr.message);
          // Fall through to rule-based extraction below
        }
      }
    }

    // ── Fallback: build a single ticket from the message directly ───────
    if (!ticketsToCreate.length) {
      const summaryRaw = userMessage
        .replace(/\b(create|open|file|raise|log|make|submit|add)\s+(a\s+)?(jira\s+)?(ticket|issue|task|bug|story)\s+(for|about|on|regarding)?\s*/i, "")
        .trim()
        .slice(0, 100);
      const summary = summaryRaw || "Security Finding Ticket";
      const description = scanContext
        ? `${userMessage}\n\nScan context:\n${scanContext}`
        : userMessage;
      ticketsToCreate = [{ summary, description }];
    }

    // ── Resolve JIRA cloud then create tickets ───────────────────────────
    let cloud;
    try {
      cloud = await resolveJiraCloudByToken(jiraToken);
    } catch (err) {
      return res.status(502).json({ error: `Failed to resolve JIRA cloud: ${err.message}` });
    }

    const createdTickets = [];
    const ticketErrors = [];

    for (const ticketData of ticketsToCreate.slice(0, 10)) { // cap at 10 per request
      const jiraUrl = `https://api.atlassian.com/ex/jira/${cloud.cloudId}/rest/api/3/issue`;
      const payload = {
        fields: {
          project: { key: JIRA_PROJECT_KEY },
          summary: String(ticketData.summary || "Security Finding").slice(0, 255),
          issuetype: { name: JIRA_ISSUE_TYPE },
          description: {
            type: "doc",
            version: 1,
            content: [{
              type: "paragraph",
              content: [{ type: "text", text: String(ticketData.description || ticketData.summary || "") }],
            }],
          },
        },
      };

      try {
        const jiraRes = await fetch(jiraUrl, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${jiraToken}`,
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });

        const bodyText = await jiraRes.text();
        let body;
        try { body = JSON.parse(bodyText); } catch { body = { message: bodyText }; }

        if (jiraRes.ok && body?.key) {
          createdTickets.push({
            key: body.key,
            url: `${cloud.siteUrl.replace(/\/+$/, "")}/browse/${body.key}`,
            summary: ticketData.summary,
            severity: ticketData.severity || "Info",
          });
        } else {
          ticketErrors.push(body?.errorMessages?.join("; ") || body?.message || `HTTP ${jiraRes.status}`);
        }
      } catch (err) {
        ticketErrors.push(err.message);
      }
    }

    if (!createdTickets.length) {
      return res.status(502).json({
        error: `Failed to create JIRA tickets: ${ticketErrors.join("; ")}`,
      });
    }

    const ticketLines = createdTickets
      .map((t) => `• ${t.key}: ${t.summary} → ${t.url}`)
      .join("\n");
    const errorNote = ticketErrors.length
      ? `\n\n(${ticketErrors.length} ticket(s) failed to create: ${ticketErrors.join("; ")})`
      : "";
    const reply = createdTickets.length === 1
      ? `JIRA ticket created successfully!\n\n${ticketLines}`
      : `Created ${createdTickets.length} JIRA ticket(s):\n\n${ticketLines}`;

    return res.json({ reply: reply + errorNote, tickets: createdTickets });
  }

  if (!FOUNDRY_TARGET_URI || !FOUNDRY_API_KEY) {
    return res.status(500).json({
      error: "Microsoft Foundry is not configured. Set FOUNDRY_TARGET_URI and FOUNDRY_API_KEY in .env.",
    });
  }

  const endpoint = buildFoundryEndpoint();
  if (!endpoint) return res.status(500).json({ error: "Invalid FOUNDRY_TARGET_URI configuration." });

  const systemPrompt =
    "You are Checkmate AI Agent. Give concise, practical answers for security and workflow operations. " +
    "You can also create JIRA tickets and publish Confluence pages — just tell the user to say something like " +
    "'create a JIRA ticket for the high severity findings' or 'create a Confluence page for the latest security analysis'.";
  const contextPrompt = scanContext
    ? `Use this scan context to answer accurately:\n${scanContext}`
    : "";

  let payload;
  if (endpoint.mode === "responses") {
    payload = {
      model: FOUNDRY_DEPLOYMENT,
      input: contextPrompt ? `${contextPrompt}\n\nUser question: ${userMessage}` : userMessage,
      instructions: systemPrompt,
      max_output_tokens: 800,
      temperature: 0.2,
    };
  } else {
    payload = {
      messages: [
        { role: "system", content: systemPrompt },
        ...(contextPrompt ? [{ role: "system", content: contextPrompt }] : []),
        { role: "user", content: userMessage },
      ],
      temperature: 0.2,
      max_tokens: 800,
    };

    // Some Foundry endpoints use model, while deployment-based OpenAI endpoints do not need it.
    if (!/\/openai\/deployments\//i.test(endpoint.url) && FOUNDRY_DEPLOYMENT) {
      payload.model = FOUNDRY_DEPLOYMENT;
    }
  }

  try {
    const aiRes = await fetch(endpoint.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": FOUNDRY_API_KEY,
        Authorization: `Bearer ${FOUNDRY_API_KEY}`,
      },
      body: JSON.stringify(payload),
    });

    const text = await aiRes.text();
    let data = null;
    try { data = JSON.parse(text); } catch { data = null; }

    if (!aiRes.ok) {
      return res.status(aiRes.status).json({
        error:
          data?.error?.message ||
          data?.message ||
          `Foundry request failed with HTTP ${aiRes.status}`,
      });
    }

    const reply = extractAssistantMessage(data);
    if (!reply) {
      return res.status(502).json({ error: "Foundry returned an empty response." });
    }

    res.json({ reply });
  } catch (err) {
    console.error("[AI Chat] Error:", err.message);
    res.status(500).json({ error: "Failed to contact Microsoft Foundry." });
  }
});

// ── Check whether GitHub is already connected in Token Vault ───────────────
// GET /me/v1/connected-accounts/accounts  →  filter by connection name
app.get("/api/connection-status", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) return res.json({ connected: false, error: "No refresh token in session" });

  try {
    const match = await getConnectedAccount(refreshToken, AUTH0_GITHUB_CONNECTION, getUserSub(req));
    res.json({ connected: !!match, account: match || null });
  } catch (err) {
    console.error("[ConnectionStatus]", err.message);
    res.json({ connected: false, error: err.message });
  }
});

app.get("/api/integrations/statuses", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  const userSub = getUserSub(req);
  if (!refreshToken) return res.status(400).json({ error: "No refresh token in session." });

  try {
    const accounts = await listConnectedAccounts(refreshToken, userSub);
    const connectedConnections = new Set((accounts || []).map((account) => account.connection));
    const integrations = listIntegrationDefs().map((integration) => ({
      key: integration.key,
      label: integration.label,
      connection: integration.connection,
      category: integration.category,
      description: integration.description,
      connectPath: integration.connectPath,
      connected: connectedConnections.has(integration.connection),
    }));
    res.json({ integrations });
  } catch (err) {
    const limited = isRateLimitError(err);
    res.status(limited ? 429 : 500).json({
      error: limited
        ? "Auth0 rate limit reached while loading connected accounts. Try again in a few seconds."
        : err.message,
      rateLimited: limited,
      integrations: listIntegrationDefs().map((integration) => ({
        key: integration.key,
        label: integration.label,
        connection: integration.connection,
        category: integration.category,
        description: integration.description,
        connectPath: integration.connectPath,
        connected: false,
      })),
    });
  }
});

app.get("/api/activity", requiresAuth(), (req, res) => {
  res.json({ activity: getActivityForUser(getUserSub(req)) });
});

app.get("/api/teams/teams", requiresAuth(), async (req, res) => {
  try {
    const teams = await listTeams(req.oidc.refreshToken);
    res.json({ teams });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teams/teams/:teamId/channels", requiresAuth(), async (req, res) => {
  try {
    const channels = await listTeamChannels(req.oidc.refreshToken, req.params.teamId);
    res.json({ channels });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/confluence/spaces", requiresAuth(), async (req, res) => {
  try {
    const spaces = await listConfluenceSpaces(req.oidc.refreshToken);
    res.json({ spaces });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/confluence/space-by-key/:spaceKey", requiresAuth(), async (req, res) => {
  try {
    const space = await findConfluenceSpaceByKey(req.oidc.refreshToken, req.params.spaceKey);
    if (!space) {
      return res.status(404).json({
        error: `Confluence space key "${req.params.spaceKey}" was not found for the connected account.`,
      });
    }
    res.json({ space });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/teams/broadcast", requiresAuth(), async (req, res) => {
  try {
    const scan = await loadScanOrThrow(String(req.body?.scanId || ""));
    const result = await broadcastScanToTeams(req.oidc.refreshToken, scan, {
      teamId: String(req.body?.teamId || ""),
      channelId: String(req.body?.channelId || ""),
      note: String(req.body?.note || ""),
    });
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "teams",
      status: "success",
      message: `Broadcasted scan summary to Teams channel ${result.channelId}.`,
      detail: buildScanHeadline(scan),
    });
    res.json({ success: true, ...result });
  } catch (err) {
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "teams",
      status: "error",
      message: "Teams broadcast failed.",
      detail: err.message,
    });
    const response = buildTeamsSendErrorResponse(err, "post a Microsoft Teams channel message");
    res.status(response.status).json(response.body);
  }
});

app.post("/api/teams/message", requiresAuth(), async (req, res) => {
  try {
    const result = await sendCustomTeamsMessage(req.oidc.refreshToken, {
      teamId: String(req.body?.teamId || ""),
      channelId: String(req.body?.channelId || ""),
      message: String(req.body?.message || ""),
    });
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "teams",
      status: "success",
      message: `Sent custom Teams message to channel ${result.channelId}.`,
      detail: result.message,
    });
    res.json({ success: true, ...result });
  } catch (err) {
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "teams",
      status: "error",
      message: "Custom Teams message failed.",
      detail: err.message,
    });
    const response = buildTeamsSendErrorResponse(err, "send a custom Microsoft Teams channel message");
    res.status(response.status).json(response.body);
  }
});

app.post("/api/confluence/publish", requiresAuth(), async (req, res) => {
  try {
    const scan = await loadScanOrThrow(String(req.body?.scanId || ""));
    const result = await publishScanToConfluence(req.oidc.refreshToken, scan, {
      spaceId: String(req.body?.spaceId || ""),
      parentId: String(req.body?.parentId || ""),
      title: String(req.body?.title || ""),
      note: String(req.body?.note || ""),
    });
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "confluence",
      status: "success",
      message: `Published Confluence page "${result.title}".`,
      detail: result.url,
    });
    res.json({ success: true, ...result });
  } catch (err) {
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "confluence",
      status: "error",
      message: "Confluence publish failed.",
      detail: err.message,
    });
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/confluence/page", requiresAuth(), async (req, res) => {
  try {
    const result = await createConfluencePage(req.oidc.refreshToken, {
      spaceId: String(req.body?.spaceId || ""),
      title: String(req.body?.title || ""),
      content: String(req.body?.content || ""),
      parentId: String(req.body?.parentId || ""),
    });
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "confluence",
      status: "success",
      message: `Created Confluence page "${result.title}".`,
      detail: result.url,
    });
    res.json({ success: true, ...result });
  } catch (err) {
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "confluence",
      status: "error",
      message: "Confluence page creation failed.",
      detail: err.message,
    });
    const status = /title is required|content cannot be empty|Provide a Confluence space ID/i.test(String(err.message || ""))
      ? 400
      : 500;
    res.status(status).json({ error: err.message });
  }
});

app.post("/api/automation/preview", requiresAuth(), async (req, res) => {
  const userSub = getUserSub(req);
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: "No refresh token in session." });

  try {
    const scan = await loadScanOrThrow(String(req.body?.scanId || ""));
    const prompt = String(req.body?.prompt || "").trim();
    const destinations = {
      note: String(req.body?.note || "").trim(),
      teamsTeamId: String(req.body?.teamsTeamId || "").trim(),
      teamsChannelId: String(req.body?.teamsChannelId || "").trim(),
      confluenceSpaceId: String(req.body?.confluenceSpaceId || "").trim(),
      confluenceParentId: String(req.body?.confluenceParentId || "").trim(),
    };

    const planned = await inferAutomationActions(prompt, destinations);
    if (!planned.length) {
      return res.status(400).json({
        error: "No supported actions were detected. Mention JIRA, Teams, or Confluence in the instruction.",
      });
    }

    const accounts = await listConnectedAccounts(refreshToken, userSub).catch(() => []);
    const connectedConnections = new Set((accounts || []).map((account) => account.connection));
    const actions = planned.map((action) => {
      const integrationKey =
        action.type === "jira_ticket" ? "jira" :
        action.type === "teams_broadcast" ? "teams" :
        "confluence";
      const integration = getIntegrationDef(integrationKey);
      const connected = connectedConnections.has(integration.connection);
      const params =
        action.type === "teams_broadcast" ? { teamId: destinations.teamsTeamId || TEAMS_DEFAULT_TEAM_ID, channelId: destinations.teamsChannelId || TEAMS_DEFAULT_CHANNEL_ID, note: destinations.note } :
        action.type === "confluence_publish" ? { spaceId: destinations.confluenceSpaceId || CONFLUENCE_SPACE_ID, parentId: destinations.confluenceParentId, note: destinations.note, title: `Checkmate Report — ${buildScanHeadline(scan)}` } :
        { note: destinations.note };

      let ready = connected;
      let readinessNote = connected ? "Ready to execute." : `Connect ${integration.label} first.`;
      if (action.type === "teams_broadcast" && (!params.teamId || !params.channelId)) {
        ready = false;
        readinessNote = "Select a Teams team and channel.";
      }
      if (action.type === "confluence_publish" && !params.spaceId) {
        ready = false;
        readinessNote = "Select a Confluence space.";
      }

      return {
        type: action.type,
        label: action.label,
        integration: integrationKey,
        connected,
        ready,
        readinessNote,
        params,
      };
    });

    const approval = {
      id: crypto.randomUUID(),
      userSub,
      createdAt: new Date().toISOString(),
      status: "pending",
      prompt,
      scanId: scan.id,
      scanLabel: buildScanHeadline(scan),
      actions,
    };
    approvalsById.set(approval.id, approval);
    logActivity({
      userSub,
      type: "approval",
      integration: "orchestrator",
      status: "info",
      message: `Created approval with ${actions.length} action(s).`,
      detail: prompt || buildScanHeadline(scan),
      metadata: { approvalId: approval.id },
    });

    res.json({ approval });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/automation/approvals", requiresAuth(), (req, res) => {
  const userSub = getUserSub(req);
  const approvals = [...approvalsById.values()]
    .filter((approval) => approval.userSub === userSub)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  res.json({ approvals });
});

app.post("/api/automation/approvals/:id/execute", requiresAuth(), async (req, res) => {
  const approval = approvalsById.get(req.params.id);
  const userSub = getUserSub(req);
  const refreshToken = req.oidc.refreshToken;
  if (!approval || approval.userSub !== userSub) {
    return res.status(404).json({ error: "Approval not found." });
  }
  if (!refreshToken) return res.status(400).json({ error: "No refresh token in session." });
  if (approval.status === "completed") {
    return res.status(400).json({ error: "This approval has already been executed." });
  }

  try {
    const scan = await loadScanOrThrow(approval.scanId);
    const results = [];
    const errors = [];

    for (const action of approval.actions) {
      if (!action.ready) {
        errors.push({ type: action.type, error: action.readinessNote });
        continue;
      }
      try {
        const result = await executeApprovedAction(refreshToken, scan, {
          type: action.type,
          ...action.params,
        });
        results.push({ type: action.type, result });
        logActivity({
          userSub,
          type: "action",
          integration: action.integration,
          status: "success",
          message: action.label,
          detail: JSON.stringify(result),
          metadata: { approvalId: approval.id },
        });
      } catch (err) {
        errors.push({ type: action.type, error: err.message });
        logActivity({
          userSub,
          type: "action",
          integration: action.integration,
          status: "error",
          message: action.label,
          detail: err.message,
          metadata: { approvalId: approval.id },
        });
      }
    }

    approval.status = errors.length ? "completed_with_errors" : "completed";
    approval.executedAt = new Date().toISOString();
    approval.results = results;
    approval.errors = errors;

    logActivity({
      userSub,
      type: "approval",
      integration: "orchestrator",
      status: errors.length ? "warning" : "success",
      message: `Executed approval ${approval.id}.`,
      detail: errors.length ? `${errors.length} action(s) failed.` : "All actions succeeded.",
    });

    res.json({ approval });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Check whether Atlassian JIRA is connected via Token Vault ─────────────
app.get("/api/jira/status", requiresAuth(), async (req, res) => {
  const cfgErr = jiraConfigError();
  if (cfgErr) return res.status(500).json(buildJiraStatusPayload({ error: cfgErr }));

  try {
    const refreshToken = req.oidc.refreshToken;
    const userSub = getUserSub(req);
    if (!refreshToken) {
      return res.status(400).json(buildJiraStatusPayload({ error: "No refresh token in session" }));
    }

    try {
      const accessToken = await getJiraTokenFromVault(refreshToken);
      const cloud = await resolveJiraCloudByToken(accessToken);
      return res.json({
        connected: true,
        mode: "token-vault",
        project: JIRA_PROJECT_KEY,
        site: cloud.siteUrl,
        cloudId: cloud.cloudId,
        connection: AUTH0_JIRA_CONNECTION,
      });
    } catch (tokenErr) {
      let account = null;
      try {
        account = await getJiraConnectedAccount(refreshToken, userSub);
      } catch (accountErr) {
        if (isRateLimitError(accountErr)) {
          return res.status(429).json(buildJiraStatusPayload({
            rateLimited: true,
            error: "Auth0 rate limit reached while verifying the JIRA connection. Try again in a few seconds.",
          }));
        }
        console.error("[JiraStatus] Connection check failed:", accountErr.message);
        return res.status(502).json(buildJiraStatusPayload({
          error: `Unable to verify the JIRA connection: ${accountErr.message}`,
        }));
      }

      if (!account) {
        return res.json(buildJiraStatusPayload());
      }

      if (isRateLimitError(tokenErr)) {
        return res.status(429).json(buildJiraStatusPayload({
          rateLimited: true,
          error: "Auth0 rate limit reached while retrieving a JIRA token. Try again in a few seconds.",
        }));
      }

      return res.status(502).json(buildJiraStatusPayload({
        error: `JIRA is connected, but Token Vault could not mint an Atlassian access token: ${tokenErr.message}`,
      }));
    }
  } catch (err) {
    console.error("[JiraStatus]", err.message);
    res.status(500).json(buildJiraStatusPayload({ error: err.message }));
  }
});

// ── Connected Accounts flow — Step 1: initiate ────────────────────────────
// POST /me/v1/connected-accounts/connect
//
// IMPORTANT — "Invalid redirect_uri" fix:
//   The redirect_uri sent here MUST be registered in the Auth0 Dashboard
//   under Applications → your app → Settings → Allowed Callback URLs.
//   Add exactly:  {AUTH0_BASE_URL}/connect/github/complete
//   e.g.          http://localhost:3005/connect/github/complete
//
// After Auth0 validates the redirect_uri it returns:
//   { auth_session, connect_uri, connect_params: { ticket }, expires_in }
// We redirect the user directly to connect_uri (the full Auth0-issued URL)
// with the ticket appended as a query param, exactly as the docs show.
app.get("/connect/github/start", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.redirect("/?error=" + encodeURIComponent("No refresh token. Log out and log in again."));
  }

  let myAccountToken;
  try {
    myAccountToken = await getMyAccountToken(refreshToken);
  } catch (err) {
    console.error("[Connect/Start] My Account token error:", err.message);
    return res.redirect("/?error=" + encodeURIComponent(err.message));
  }

  // This MUST match exactly one of the Allowed Callback URLs registered in
  // the Auth0 Dashboard for this application.
  const redirectUri = `${AUTH0_BASE_URL}/connect/github/complete`;
  const state = crypto.randomBytes(16).toString("hex");
  const userSub = getUserSub(req);

  console.log("[Connect/Start] Using redirect_uri:", redirectUri);
  console.log("[Connect/Start] ⚠  Ensure this URL is in Auth0 Dashboard → App → Allowed Callback URLs");

  let initiateData;
  try {
    const initiateRes = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/connect`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${myAccountToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        connection: AUTH0_GITHUB_CONNECTION,
        redirect_uri: redirectUri,
        state,
        // GitHub App permission names (not OAuth scope names).
        // For GitHub Apps the token's effective access is determined entirely by
        // the App's configured permissions in:
        //   GitHub Settings → Developer Settings → GitHub Apps
        //   → [Your App] → Permissions & events → Repository permissions
        //   → Actions: Read (or Read and write)
        // This scopes array is forwarded by Auth0 but GitHub Apps do NOT honour
        // a "scope" query parameter — permissions come from the App config only.
        // If the Actions API still returns 404 after reconnecting, enable
        // "Actions: Read" in the GitHub App settings and re-install/re-authorize.
        scopes: ["actions", "contents"],
      }),
    });

    if (!initiateRes.ok) {
      const body = await initiateRes.text();
      console.error("[Connect/Start] Initiate error:", initiateRes.status, body);

      // Surface a specific, actionable message for the redirect_uri error
      let userMessage = `Failed to initiate Connected Accounts: ${body}`;
      if (body.includes("Invalid redirect_uri")) {
        userMessage =
          `Invalid redirect_uri. You must add "${redirectUri}" ` +
          `to Allowed Callback URLs in the Auth0 Dashboard for this application.`;
      }
      return res.redirect("/?error=" + encodeURIComponent(userMessage));
    }
    initiateData = await initiateRes.json();
  } catch (err) {
    console.error("[Connect/Start] Network error:", err.message);
    return res.redirect("/?error=" + encodeURIComponent(err.message));
  }

  // The response contains:
  //   auth_session  — opaque session ID, saved for completion step
  //   connect_uri   — the Auth0 /connect base URL  e.g. https://tenant.auth0.com/connect
  //   connect_params.ticket — one-time ticket for this session
  const { auth_session, connect_uri, connect_params } = initiateData;
  const ticket = connect_params?.ticket;

  if (!auth_session || !connect_uri || !ticket) {
    console.error("[Connect/Start] Unexpected response:", JSON.stringify(initiateData));
    return res.redirect("/?error=" + encodeURIComponent(
      "Unexpected response from My Account API: " + JSON.stringify(initiateData)
    ));
  }

  // Save for the callback — keyed on state for CSRF verification
  pendingStates.set(state, { auth_session, redirectUri, userSub, connection: AUTH0_GITHUB_CONNECTION });
  logActivity({
    userSub,
    type: "connect",
    integration: "github",
    status: "info",
    message: "Started GitHub connect flow.",
    detail: AUTH0_GITHUB_CONNECTION,
  });

  // Build the final URL: connect_uri + ?ticket={ticket}
  // Per docs: "navigate to the connect_uri with the ticket as a query parameter"
  const connectUrl = `${connect_uri}?ticket=${encodeURIComponent(ticket)}`;
  console.log("[Connect/Start] Redirecting user to:", connectUrl);
  res.redirect(connectUrl);
});

// ── JIRA Token Vault flow — Step 1: initiate connected account ────────────
app.get("/connect/jira/start", requiresAuth(), async (req, res) => {
  const cfgErr = jiraConfigError();
  if (cfgErr) return res.redirect(`/?error=${encodeURIComponent(cfgErr)}#jira-connect`);

  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.redirect(`/?error=${encodeURIComponent("No refresh token. Log out and log in again.")}#jira-connect`);
  }

  let myAccountToken;
  try {
    myAccountToken = await getMyAccountToken(refreshToken);
  } catch (err) {
    console.error("[JiraConnect/Start] My Account token error:", err.message);
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#jira-connect`);
  }

  const userSub = getUserSub(req);
  if (!userSub) {
    return res.redirect(`/?error=${encodeURIComponent("No authenticated user in session.")}#jira-connect`);
  }

  const redirectUri = JIRA_CONNECT_REDIRECT_URI;
  const state = crypto.randomBytes(16).toString("hex");

  console.log("[JiraConnect/Start] Using redirect_uri:", redirectUri);
  console.log("[JiraConnect/Start] Using Auth0 connection:", AUTH0_JIRA_CONNECTION);

  let initiateData;
  try {
    const initiateRes = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/connect`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${myAccountToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        connection: AUTH0_JIRA_CONNECTION,
        redirect_uri: redirectUri,
        state,
        scopes: parseScopeList(JIRA_CONNECT_SCOPES),
      }),
    });
    const bodyText = await initiateRes.text();
    try { initiateData = JSON.parse(bodyText); } catch { initiateData = null; }
    if (!initiateRes.ok) {
      console.error("[JiraConnect/Start] Initiate error:", initiateRes.status, bodyText);

      let userMessage = `Failed to initiate JIRA Connected Accounts flow: ${bodyText}`;
      if (bodyText.includes("Invalid redirect_uri")) {
        userMessage =
          `Invalid redirect_uri. You must add "${redirectUri}" ` +
          `to Allowed Callback URLs in the Auth0 Dashboard for this application.`;
      }
      return res.redirect(`/?error=${encodeURIComponent(userMessage)}#jira-connect`);
    }
  } catch (err) {
    console.error("[JiraConnect/Start] Network error:", err.message);
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#jira-connect`);
  }

  const { auth_session, connect_uri, connect_params } = initiateData;
  const ticket = connect_params?.ticket;

  if (!auth_session || !connect_uri || !ticket) {
    console.error("[JiraConnect/Start] Unexpected response:", JSON.stringify(initiateData));
    return res.redirect(`/?error=${encodeURIComponent(
      `Unexpected response from My Account API: ${JSON.stringify(initiateData)}`
    )}#jira-connect`);
  }

  pendingStates.set(state, {
    auth_session,
    redirectUri,
    userSub,
    connection: AUTH0_JIRA_CONNECTION,
    hash: "#jira-connect",
    successQuery: "jira_connected=1",
  });
  logActivity({
    userSub,
    type: "connect",
    integration: "jira",
    status: "info",
    message: "Started JIRA connect flow.",
    detail: AUTH0_JIRA_CONNECTION,
  });

  return res.redirect(`${connect_uri}?ticket=${encodeURIComponent(ticket)}`);
});

// ── Connected Accounts flow — Step 2: complete ────────────────────────────
// Auth0 redirects here with ?connect_code=…&state=…
app.get("/connect/github/complete", requiresAuth(), async (req, res) => {
  const { connect_code, state } = req.query;

  if (!connect_code) {
    return res.redirect("/?error=" + encodeURIComponent("Missing connect_code in callback"));
  }
  if (!state || !pendingStates.has(state)) {
    return res.redirect("/?error=" + encodeURIComponent("Invalid or expired state. Please try again."));
  }

  const record = pendingStates.get(state);
  pendingStates.delete(state);

  if (record.connection && record.connection !== AUTH0_GITHUB_CONNECTION) {
    return res.redirect("/?error=" + encodeURIComponent("Connection state does not belong to GitHub."));
  }

  const { auth_session, redirectUri, userSub: stateUserSub } = record;

  const userSub = getUserSub(req);
  if (stateUserSub && (!userSub || stateUserSub !== userSub)) {
    return res.redirect("/?error=" + encodeURIComponent("Connection state does not match current user session."));
  }

  const refreshToken = req.oidc.refreshToken;
  let myAccountToken;
  try {
    myAccountToken = await getMyAccountToken(refreshToken);
  } catch (err) {
    return res.redirect("/?error=" + encodeURIComponent(err.message));
  }

  // POST /me/v1/connected-accounts/complete  — include redirect_uri (per docs)
  try {
    const completeRes = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${myAccountToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ auth_session, connect_code, redirect_uri: redirectUri }),
    });

    if (!completeRes.ok) {
      const body = await completeRes.text();
      console.error("[Connect/Complete] Error:", completeRes.status, body);
      return res.redirect("/?error=" + encodeURIComponent(`Connection failed: ${body}`));
    }

    const result = await completeRes.json();
    console.log("[Connect/Complete] Success:", result);
    clearConnectedAccountsCache(userSub);
    logActivity({
      userSub,
      type: "connect",
      integration: "github",
      status: "success",
      message: "GitHub connected through Token Vault.",
      detail: AUTH0_GITHUB_CONNECTION,
    });
    res.redirect("/?connected=1");
  } catch (err) {
    console.error("[Connect/Complete] Network error:", err.message);
    res.redirect("/?error=" + encodeURIComponent(err.message));
  }
});

// ── JIRA Token Vault flow — Step 2: complete connected account ────────────
app.get("/connect/jira/complete", requiresAuth(), async (req, res) => {
  const { connect_code, state } = req.query;
  if (!connect_code) {
    return res.redirect(`/?error=${encodeURIComponent("Missing connect_code in JIRA callback")}#jira-connect`);
  }
  if (!state || !pendingStates.has(state)) {
    return res.redirect(`/?error=${encodeURIComponent("Invalid or expired JIRA state. Please try again.")}#jira-connect`);
  }

  const record = pendingStates.get(state);
  pendingStates.delete(state);

  if (record.connection && record.connection !== AUTH0_JIRA_CONNECTION) {
    return res.redirect(`/?error=${encodeURIComponent("Connection state does not belong to JIRA.")}#jira-connect`);
  }

  const userSub = getUserSub(req);
  if (!userSub || record.userSub !== userSub) {
    return res.redirect(`/?error=${encodeURIComponent("JIRA OAuth state does not match current user session.")}#jira-connect`);
  }

  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.redirect(`/?error=${encodeURIComponent("No refresh token. Log out and log in again.")}#jira-connect`);
  }

  let myAccountToken;
  try {
    myAccountToken = await getMyAccountToken(refreshToken);
  } catch (err) {
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#jira-connect`);
  }

  try {
    const completeRes = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${myAccountToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        auth_session: record.auth_session,
        connect_code,
        redirect_uri: record.redirectUri || JIRA_CONNECT_REDIRECT_URI,
      }),
    });

    if (!completeRes.ok) {
      const body = await completeRes.text();
      console.error("[JiraConnect/Complete] Error:", completeRes.status, body);
      return res.redirect(`/?error=${encodeURIComponent(`Connection failed: ${body}`)}#jira-connect`);
    }

    clearConnectedAccountsCache(userSub);
    logActivity({
      userSub,
      type: "connect",
      integration: "jira",
      status: "success",
      message: "JIRA connected through Token Vault.",
      detail: AUTH0_JIRA_CONNECTION,
    });
    return res.redirect(`/?${record.successQuery || "jira_connected=1"}${record.hash || "#jira-connect"}`);
  } catch (err) {
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#jira-connect`);
  }
});

app.get("/connect/integrations/:integration/start", requiresAuth(), async (req, res) => {
  const integration = getIntegrationDef(req.params.integration);
  if (!integration || integration.key === "github" || integration.key === "jira") {
    return res.redirect(`/?error=${encodeURIComponent("Unknown integration connect route.")}#integrations`);
  }

  const cfgErr = integrationConfigError(integration.key);
  if (cfgErr) return res.redirect(`/?error=${encodeURIComponent(cfgErr)}#integrations`);

  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.redirect(`/?error=${encodeURIComponent("No refresh token. Log out and log in again.")}#integrations`);
  }

  let myAccountToken;
  try {
    myAccountToken = await getMyAccountToken(refreshToken);
  } catch (err) {
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#integrations`);
  }

  const userSub = getUserSub(req);
  if (!userSub) {
    return res.redirect(`/?error=${encodeURIComponent("No authenticated user in session.")}#integrations`);
  }

  const state = crypto.randomBytes(16).toString("hex");
  let initiateData;
  try {
    const initiateRes = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/connect`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${myAccountToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        connection: integration.connection,
        redirect_uri: integration.redirectUri,
        state,
        scopes: integration.scopes,
      }),
    });

    const bodyText = await initiateRes.text();
    try { initiateData = JSON.parse(bodyText); } catch { initiateData = null; }
    if (!initiateRes.ok) {
      let message = `Failed to initiate ${integration.label} connection: ${bodyText}`;
      if (bodyText.includes("Invalid redirect_uri")) {
        message =
          `Invalid redirect_uri. You must add "${integration.redirectUri}" ` +
          `to Allowed Callback URLs in the Auth0 Dashboard for this application.`;
      } else if (
        String(initiateData?.detail || bodyText).includes("The specified connection was not found or not enabled for client")
      ) {
        message =
          `${integration.label} connection "${integration.connection}" was not found in Auth0 ` +
          `or is not enabled for this application.`;
        if (integration.key === "teams") {
          message +=
            ` If you are using a Microsoft enterprise connection, set AUTH0_TEAMS_CONNECTION ` +
            `to that enterprise connection's actual Auth0 name instead of a default/social name like "windowslive".`;
        }
        message += " Also verify the connection is enabled for this app in Auth0.";
      }
      return res.redirect(`/?error=${encodeURIComponent(message)}#integrations`);
    }
  } catch (err) {
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#integrations`);
  }

  const { auth_session, connect_uri, connect_params } = initiateData || {};
  const ticket = connect_params?.ticket;
  if (!auth_session || !connect_uri || !ticket) {
    return res.redirect(`/?error=${encodeURIComponent(
      `Unexpected response from My Account API: ${JSON.stringify(initiateData)}`
    )}#integrations`);
  }

  pendingStates.set(state, {
    auth_session,
    redirectUri: integration.redirectUri,
    userSub,
    connection: integration.connection,
    integrationKey: integration.key,
    hash: "#integrations",
    successQuery: `integration_connected=${integration.key}`,
  });

  logActivity({
    userSub,
    type: "connect",
    integration: integration.key,
    status: "info",
    message: `Started ${integration.label} connect flow.`,
    detail: integration.connection,
  });

  return res.redirect(`${connect_uri}?ticket=${encodeURIComponent(ticket)}`);
});

app.get("/connect/integrations/:integration/complete", requiresAuth(), async (req, res) => {
  const integration = getIntegrationDef(req.params.integration);
  if (!integration || integration.key === "github" || integration.key === "jira") {
    return res.redirect(`/?error=${encodeURIComponent("Unknown integration callback route.")}#integrations`);
  }

  const { connect_code, state } = req.query;
  if (!connect_code) {
    return res.redirect(`/?error=${encodeURIComponent(`Missing connect_code in ${integration.label} callback`)}#integrations`);
  }
  if (!state || !pendingStates.has(state)) {
    return res.redirect(`/?error=${encodeURIComponent(`Invalid or expired ${integration.label} state. Please try again.`)}#integrations`);
  }

  const record = pendingStates.get(state);
  pendingStates.delete(state);

  if (record.connection && record.connection !== integration.connection) {
    return res.redirect(`/?error=${encodeURIComponent("Connection state does not belong to this integration.")}#integrations`);
  }

  const userSub = getUserSub(req);
  if (!userSub || record.userSub !== userSub) {
    return res.redirect(`/?error=${encodeURIComponent("OAuth state does not match current user session.")}#integrations`);
  }

  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.redirect(`/?error=${encodeURIComponent("No refresh token. Log out and log in again.")}#integrations`);
  }

  let myAccountToken;
  try {
    myAccountToken = await getMyAccountToken(refreshToken);
  } catch (err) {
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#integrations`);
  }

  try {
    const completeRes = await fetch(`https://${AUTH0_DOMAIN}/me/v1/connected-accounts/complete`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${myAccountToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        auth_session: record.auth_session,
        connect_code,
        redirect_uri: record.redirectUri || integration.redirectUri,
      }),
    });

    if (!completeRes.ok) {
      const body = await completeRes.text();
      return res.redirect(`/?error=${encodeURIComponent(`Connection failed: ${body}`)}#integrations`);
    }

    clearConnectedAccountsCache(userSub);
    logActivity({
      userSub,
      type: "connect",
      integration: integration.key,
      status: "success",
      message: `${integration.label} connected through Token Vault.`,
      detail: integration.connection,
    });

    return res.redirect(`/?${record.successQuery || `integration_connected=${integration.key}`}${record.hash || "#integrations"}`);
  } catch (err) {
    return res.redirect(`/?error=${encodeURIComponent(err.message)}#integrations`);
  }
});

async function resolveJiraCloud(req) {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) throw new Error("No refresh token. Log out and log in again.");
  const jiraToken = await getJiraTokenFromVault(refreshToken);

  if (!jiraToken) throw new Error("JIRA is not connected. Please connect JIRA first.");
  const cloud = await resolveJiraCloudByToken(jiraToken);
  return { jiraToken, cloudId: cloud.cloudId, siteUrl: cloud.siteUrl };
}

// ── Create JIRA ticket in configured project ──────────────────────────────
app.post("/api/jira/tickets", requiresAuth(), async (req, res) => {
  const cfgErr = jiraConfigError();
  if (cfgErr) return res.status(500).json({ error: cfgErr });

  const summary = String(req.body?.summary || "").trim();
  const description = String(req.body?.description || "").trim();
  if (!summary) return res.status(400).json({ error: "Ticket summary is required." });

  try {
    const { jiraToken, cloudId, siteUrl } = await resolveJiraCloud(req);

    const url = `https://api.atlassian.com/ex/jira/${cloudId}/rest/api/3/issue`;
    const payload = {
      fields: {
        project: { key: JIRA_PROJECT_KEY },
        summary,
        issuetype: { name: JIRA_ISSUE_TYPE },
        description: {
          type: "doc",
          version: 1,
          content: [{ type: "paragraph", content: [{ type: "text", text: description || summary }] }],
        },
      },
    };

    const jiraRes = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jiraToken}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const bodyText = await jiraRes.text();
    let body;
    try { body = JSON.parse(bodyText); } catch { body = { message: bodyText }; }

    if (!jiraRes.ok) {
      return res.status(jiraRes.status).json({
        error: body?.errorMessages?.join("; ") || body?.message || "Failed to create JIRA ticket.",
        raw: body,
      });
    }

    const issueKey = body?.key;
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "jira",
      status: "success",
      message: `Created JIRA ticket ${issueKey || ""}`.trim(),
      detail: summary,
    });
    res.json({
      success: true,
      issueKey,
      issueUrl: issueKey ? `${siteUrl.replace(/\/+$/, "")}/browse/${issueKey}` : null,
    });
  } catch (err) {
    console.error("[JiraTicket] Error:", err.message);
    logActivity({
      userSub: getUserSub(req),
      type: "action",
      integration: "jira",
      status: "error",
      message: "Failed to create JIRA ticket.",
      detail: err.message,
    });
    res.status(500).json({ error: err.message || "Failed to create JIRA ticket." });
  }
});

// ── Debug: inspect vault token and GitHub permissions ─────────────────────
// GET /api/debug — returns token type, scopes header, and a test API call
// so you can see exactly why GitHub is returning 404.
app.get("/api/debug", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: "No refresh token." });

  let githubToken;
  try {
    githubToken = await getGitHubTokenFromVault(refreshToken);
  } catch (err) {
    return res.status(502).json({ vaultError: err.message });
  }

  // Mask the token — show only prefix (ghu_ = GitHub App user token, ghs_ = installation)
  const tokenPrefix = githubToken.slice(0, 10) + "...";

  // 1. Call /user to confirm the token is valid and see the login
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  const userBody = await userRes.json();
  // The X-OAuth-Scopes header lists granted scopes for OAuth tokens.
  // For GitHub App user tokens it will be empty — permissions come from the App config.
  const oauthScopes = userRes.headers.get("x-oauth-scopes") || "(none — GitHub App token, uses permissions not scopes)";
  const acceptedScopes = userRes.headers.get("x-accepted-oauth-scopes") || "";

  // 2. Check repo-level access (no Actions permission needed) — distinguishes
  //    "repo not accessible at all" from "Actions permission specifically missing".
  const repoUrl = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}`;
  const repoRes = await fetch(repoUrl, {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  const repoBody = await repoRes.json();

  // 3. List App installations the user has authorized — helps verify the App
  //    is installed and which repos it covers.
  const installationsRes = await fetch("https://api.github.com/user/installations?per_page=10", {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  const installationsBody = await installationsRes.json();

  // 4. Call the workflow endpoint directly and capture the full response
  const workflowUrl = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/actions/workflows/${GITHUB_WORKFLOW_ID}`;
  const wfRes = await fetch(workflowUrl, {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  const wfBody = await wfRes.json();

  // 5. List all workflows in the repo so we can see what file names exist
  const listUrl = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/actions/workflows`;
  const listRes = await fetch(listUrl, {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  const listBody = await listRes.json();

  // Derive a human-readable diagnosis from the status codes.
  let diagnosis = "OK — all checks passed";
  if (repoRes.status === 404) {
    diagnosis = "FAIL: Repo is not accessible to this token. " +
      "The GitHub App is likely not installed on this repository, or not installed at all. " +
      "Go to github.com/settings/installations → [Your App] → Repository access and add the repo.";
  } else if (listRes.status === 404) {
    diagnosis = "FAIL: Repo is accessible but Actions API returns 404. " +
      "Most likely cause: the GitHub App installation has NOT yet approved the updated permissions. " +
      "Go to github.com/settings/installations → [Your App] → look for a yellow \"Review request\" " +
      "banner and approve the new permissions. Then re-authorize the App in this application.";
  }

  res.json({
    diagnosis,
    tokenPrefix,
    tokenType: githubToken.startsWith("ghu_") ? "GitHub App user access token ✓" :
               githubToken.startsWith("ghs_") ? "GitHub App installation token" :
               githubToken.startsWith("ghp_") ? "Classic PAT" : "Unknown type: " + githubToken.slice(0, 4),
    oauthScopes,
    acceptedScopes,
    authenticatedAs: userBody.login,
    userStatus: userRes.status,
    repoAccess: {
      url: repoUrl,
      status: repoRes.status,
      name: repoBody.full_name || repoBody.message,
      private: repoBody.private,
    },
    installations: {
      status: installationsRes.status,
      // List app names and their repo selection type so it's easy to spot
      // whether the App is installed and whether it covers this repo.
      apps: (installationsBody.installations || []).map(i => ({
        appId: i.app_id,
        appSlug: i.app_slug,
        repoSelection: i.repository_selection, // "all" or "selected"
        permissions: i.permissions,
      })),
    },
    workflowLookup: {
      url: workflowUrl,
      status: wfRes.status,
      body: wfBody,
    },
    allWorkflows: {
      status: listRes.status,
      workflows: listBody.workflows?.map(w => ({ id: w.id, name: w.name, path: w.path, state: w.state })) || listBody,
    },
    config: {
      owner: GITHUB_REPO_OWNER,
      repo: GITHUB_REPO_NAME,
      workflowId: GITHUB_WORKFLOW_ID,
    },
  });
});

// ── Serve downloaded report files (authenticated) ────────────────────────
app.get("/reports/:filename", requiresAuth(), (req, res) => {
  const safeName = path.basename(req.params.filename);
  const filePath = path.join(REPORTS_DIR, safeName);
  if (!fs.existsSync(filePath)) return res.status(404).send("Report not found.");
  res.sendFile(filePath);
});

// ── Fetch reports from GitHub and download locally ───────────────────────
// GET /api/reports — lists files in the reports/ folder, downloads them to
// ./reports/ using a Token Vault GitHub token, upserts them into the DB,
// and returns the file metadata.
app.get("/api/reports", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: "No refresh token." });

  let githubToken;
  try {
    githubToken = await getGitHubTokenFromVault(refreshToken);
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }

  try {
    const result = await downloadAndImportReports(githubToken);
    res.json(result);
  } catch (err) {
    console.error("[Reports] Error:", err.message);
    const statusMatch = /^GitHub (\d+)/.exec(err.message);
    res.status(statusMatch ? Number(statusMatch[1]) : 500).json({ error: err.message });
  }
});

// ── Dashboard: list all scans from DB ─────────────────────────────────────
// GET /api/scans — returns every scan row ordered newest-first
app.get("/api/scans", requiresAuth(), async (req, res) => {
  try {
    const scans = await listScans();
    res.json({ scans });
  } catch (err) {
    console.error("[Scans] Error:", err.message);
    res.status(500).json({ error: "Failed to fetch scans." });
  }
});

// ── Dashboard: scan detail with findings ──────────────────────────────────
// GET /api/scans/:id — returns one scan + all findings + details
app.get("/api/scans/:id", requiresAuth(), async (req, res) => {
  // Basic UUID validation to avoid sending arbitrary strings to DB
  if (!/^[0-9a-f-]{36}$/.test(req.params.id)) {
    return res.status(400).json({ error: "Invalid scan id." });
  }
  try {
    const scan = await getScanWithFindings(req.params.id);
    if (!scan) return res.status(404).json({ error: "Scan not found." });
    res.json({ scan });
  } catch (err) {
    console.error("[ScanDetail] Error:", err.message);
    res.status(500).json({ error: "Failed to fetch scan." });
  }
});

// ── List workflows in the configured repository ────────────────────────────
// GET /api/workflows — returns all workflows for GITHUB_REPO_OWNER/GITHUB_REPO_NAME
app.get("/api/workflows", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: "No refresh token." });

  let githubToken;
  try {
    githubToken = await getGitHubTokenFromVault(refreshToken);
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }

  const url = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/actions/workflows`;
  try {
    const ghRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${githubToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!ghRes.ok) {
      const body = await ghRes.text();
      if (ghRes.status === 404) {
        // With a GitHub App user token (ghu_*) the Actions API returns 404 for
        // any of these reasons — check /api/debug for a step-by-step diagnosis:
        //
        // 1. App installation hasn't approved updated permissions.
        //    When App permissions are changed in GitHub Developer Settings,
        //    every existing installation must explicitly approve the change at
        //    github.com/settings/installations → [App] → "Review request".
        //    Re-authorizing the user (re-connecting in this app) is NOT enough.
        //
        // 2. App not installed on this specific repository.
        //    The App must be installed (github.com/settings/installations) with
        //    repository access that includes this repo.
        //
        // 3. App doesn't have "Actions: Read" permission.
        //    Set in GitHub → Developer Settings → GitHub Apps →
        //    [App] → Permissions & events → Repository permissions.
        return res.status(404).json({
          error: `GitHub returned 404 for ${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}. ` +
            `With a GitHub App token the most common causes are: ` +
            `(1) the App installation has not approved updated permissions — go to ` +
            `github.com/settings/installations → [Your App] and look for a "Review request" banner; ` +
            `(2) the App is not installed on this specific repository — check Repository access ` +
            `under github.com/settings/installations → [Your App]; ` +
            `(3) the App is missing "Actions: Read" permission in GitHub Developer Settings. ` +
            `Visit /api/debug for a full diagnosis.`,
          raw: body,
        });
      }
      return res.status(ghRes.status).json({ error: body });
    }
    const data = await ghRes.json();
    res.json({
      workflows: (data.workflows || []).map((w) => ({
        id: w.id,
        name: w.name,
        path: w.path,
        state: w.state,
        url: w.html_url,
      })),
    });
  } catch (err) {
    console.error("[Workflows] Error:", err.message);
    res.status(500).json({ error: "Failed to fetch workflows." });
  }
});

// ── Trigger GitHub Actions workflow ───────────────────────────────────────
app.post("/api/trigger", requiresAuth(), async (req, res) => {
  const { ref = "main" } = req.body;
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) {
    return res.status(400).json({ success: false, error: "No refresh token. Log out and log in again." });
  }

  const dispatch = await dispatchCheckmateWorkflow(refreshToken, ref);
  if (dispatch.success) {
    console.log(`[Trigger] Dispatched by ${req.oidc.user?.name}`);
    return res.json({ success: true, message: "Workflow dispatched." });
  }

  console.error(`[Trigger] Error:`, dispatch.error);
  return res.status(dispatch.status || 500).json({
    success: false,
    githubStatus: dispatch.status,
    githubError: dispatch.githubError,
    url: dispatch.url,
    error: dispatch.error,
  });
});

// ── Recent workflow runs ───────────────────────────────────────────────────
app.get("/api/runs", requiresAuth(), async (req, res) => {
  const refreshToken = req.oidc.refreshToken;
  if (!refreshToken) return res.status(400).json({ error: "No refresh token." });

  let githubToken;
  try {
    githubToken = await getGitHubTokenFromVault(refreshToken);
  } catch (err) {
    return res.status(502).json({ error: err.message });
  }

  const url = `https://api.github.com/repos/${GITHUB_REPO_OWNER}/${GITHUB_REPO_NAME}/actions/workflows/${GITHUB_WORKFLOW_ID}/runs?per_page=5`;
  try {
    const ghRes = await fetch(url, {
      headers: {
        Authorization: `Bearer ${githubToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!ghRes.ok) return res.status(ghRes.status).json({ error: await ghRes.text() });
    const data = await ghRes.json();
    res.json({
      runs: (data.workflow_runs || []).map((r) => ({
        id: r.id, status: r.status, conclusion: r.conclusion,
        createdAt: r.created_at, url: r.html_url, actor: r.triggering_actor?.login,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch runs." });
  }
});

// ── GitHub Actions Webhook — real-time scan completion ──────────────────
//
// Configure in GitHub: repo → Settings → Webhooks → Add webhook
//   Payload URL:  {AUTH0_BASE_URL}/webhooks/github
//   Content type: application/json
//   Secret:       value of GITHUB_WEBHOOK_SECRET in .env
//   Events:       ✅ Workflow runs  (or send me everything)
//
// Auth0 Token Vault value proposition:
//   The webhook handler has NO raw API keys. Signature is verified with
//   GITHUB_WEBHOOK_SECRET, and completion events are pushed to authenticated
//   dashboard sessions via Server-Sent Events — all without storing any
//   third-party credentials in the server process.
//
app.post("/webhooks/github", async (req, res) => {
  // Acknowledge immediately so GitHub doesn't mark the delivery as failed
  // while we do async Token Vault exchanges + API calls.
  res.status(202).json({ received: true });

  const event = req.headers["x-github-event"];
  const rawBody = req.rawBody;

  // ── Signature verification ─────────────────────────────────────────────
  if (GITHUB_WEBHOOK_SECRET) {
    const sig = req.headers["x-hub-signature-256"];
    if (!verifyGitHubWebhookSignature(rawBody, sig, GITHUB_WEBHOOK_SECRET)) {
      console.warn("[Webhook] ❌ Invalid signature — payload rejected.");
      return;
    }
  } else {
    console.warn("[Webhook] ⚠  GITHUB_WEBHOOK_SECRET not set — skipping signature verification.");
  }

  // Only handle workflow_run events
  if (event !== "workflow_run") return;

  const { action, workflow_run: run } = req.body;

  // Only act on successful completions
  if (action !== "completed") return;
  if (run?.conclusion !== "success") {
    console.log(`[Webhook] Workflow run #${run?.run_number} concluded: ${run?.conclusion} — skipping.`);
    return;
  }

  // Match the configured workflow by filename or display name.
  // Uses case-insensitive matching and partial name checks to handle
  // differences between the yaml filename and the workflow's display name.
  const workflowFile = path.basename(run?.path || "");
  const wfIdNoExt = GITHUB_WORKFLOW_ID.replace(/\.ya?ml$/i, "");
  const nameMatch =
    run?.name?.toLowerCase() === wfIdNoExt.toLowerCase() ||
    run?.name?.toLowerCase().includes(wfIdNoExt.toLowerCase());
  if (workflowFile.toLowerCase() !== GITHUB_WORKFLOW_ID.toLowerCase() && !nameMatch) {
    console.log(`[Webhook] Ignoring unrelated workflow: "${run?.name}" (${run?.path}). Expected: ${GITHUB_WORKFLOW_ID}`);
    return;
  }

  console.log(`[Webhook] ✅ '${run?.name}' completed — run #${run?.run_number} on ${run?.head_branch} (${run?.head_sha?.slice(0, 7)})`);

  // ── Broadcast to all connected dashboard sessions via SSE ──────────────
  // No Token Vault exchange needed here — the SSE clients are already
  // authenticated browser sessions. Auth0 Token Vault credentials stay
  // scoped to user-initiated actions in the dashboard.
  const eventPayload = {
    workflowName: run?.name || GITHUB_WORKFLOW_ID,
    runNumber: run?.run_number,
    branch: run?.head_branch || "main",
    sha: run?.head_sha?.slice(0, 7) || "",
    conclusion: run?.conclusion,
    runUrl: run?.html_url || "",
    at: new Date().toISOString(),
  };

  broadcastSSE("workflow_complete", eventPayload);
  console.log(`[Webhook] 📡 Broadcast workflow_complete to ${sseClients.size} connected dashboard client(s).`);

  logActivity({
    userSub: "webhook",
    type: "webhook",
    integration: "github",
    status: "success",
    message: `Workflow '${run?.name}' completed — notified ${sseClients.size} dashboard client(s).`,
    detail: `Run #${run?.run_number} on ${run?.head_branch} · ${run?.head_sha?.slice(0, 7)}`,
    metadata: { runId: run?.id, runNumber: run?.run_number },
  });

  if (!GITHUB_WEBHOOK_TOKEN) {
    console.warn("[Webhook] Skipping report import: set GITHUB_WEBHOOK_TOKEN (or GITHUB_TOKEN) to enable webhook-based sync.");
    return;
  }

  try {
    const imported = await downloadAndImportReports(GITHUB_WEBHOOK_TOKEN, {
      branch: run?.head_branch || "main",
    });
    console.log(`[Webhook] Imported reports after workflow completion: ${imported.files.length} file(s).`);
    // Broadcast a second event now that the DB has been updated so the
    // dashboard can refresh by calling loadScans() directly — no GitHub
    // Token Vault exchange needed from the client side.
    broadcastSSE("reports_imported", {
      files: imported.files.length,
      branch: run?.head_branch || "main",
      at: new Date().toISOString(),
    });
    console.log(`[Webhook] 📡 Broadcast reports_imported to ${sseClients.size} connected client(s).`);
    logActivity({
      userSub: "webhook",
      type: "report_sync",
      integration: "github",
      status: "success",
      message: `Imported ${imported.files.length} report file(s) from GitHub after workflow completion.`,
      detail: `Branch ${run?.head_branch || "main"} · run #${run?.run_number}`,
      metadata: { runId: run?.id, files: imported.files.length },
    });
  } catch (err) {
    console.error("[Webhook] Report import failed:", err.message);
    logActivity({
      userSub: "webhook",
      type: "report_sync",
      integration: "github",
      status: "error",
      message: "Webhook report sync failed.",
      detail: err.message,
      metadata: { runId: run?.id },
    });
  }
});

// ── Auth diagnostics ───────────────────────────────────────────────────────
// Adds route-level context to unauthorized errors so production logs can
// identify which endpoint is being called without a session cookie.
app.use((err, req, res, next) => {
  if (err?.name === "UnauthorizedError") {
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const ip = forwarded || req.ip || "unknown";
    const ua = req.get("user-agent") || "unknown";
    const referer = req.get("referer") || "";

    console.warn(
      `[Auth] Unauthorized route=${req.method} ${req.originalUrl} ip=${ip}` +
      `${referer ? ` referer=${referer}` : ""} ua=${ua}`
    );

    if (req.originalUrl.startsWith("/api/")) {
      return res.status(401).json({ error: "Authentication is required for this route." });
    }

    return res.status(401).send("Authentication is required for this route.");
  }

  return next(err);
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  Auth0 Checkmate Runner (Token Vault v6)`);
  console.log(`   App:      ${AUTH0_BASE_URL}`);
  console.log(`\n   ⚠  Auth0 Dashboard → Applications → your app → Settings`);
  console.log(`   Add these to "Allowed Callback URLs":`);
  console.log(`     ${AUTH0_BASE_URL}/callback`);
  console.log(`     ${AUTH0_BASE_URL}/connect/github/complete`);
  console.log(`   Add these to "Allowed Logout URLs":`);
  console.log(`     ${AUTH0_BASE_URL}`);
  console.log(`\n   🔔 GitHub Webhook (repo → Settings → Webhooks → Add webhook):`);
  console.log(`     Payload URL:  ${AUTH0_BASE_URL}/webhooks/github`);
  console.log(`     Content type: application/json`);
  console.log(`     Events:       Workflow runs`);
  if (!GITHUB_WEBHOOK_SECRET) {
    console.log(`     ⚠  GITHUB_WEBHOOK_SECRET not set — signature verification disabled.`);
  } else {
    console.log(`     ✅ GITHUB_WEBHOOK_SECRET is set.`);
  }
  console.log("");
});
