/**
 * E2E tests for the Jira Integration — mock backend.
 *
 * Sections:
 *   80 — Jira OAuth connect flow (1 test)
 *   81 — Jira connection lifecycle via DDB-seeded connection (5 tests)
 *   82 — Jira mock issue operations — direct mock endpoints (5 tests)
 *
 * Auth: Alice session cookies (from e2e_admin_session_setup.py).
 *
 * IMPORTANT: .env.local must have:
 *   JIRA_MOCK_ENABLED=1
 *   JIRA_API_BASE_URL=http://localhost:8000/mock/jira
 *   JIRA_SYNC_OAUTH_TOKEN_URL=http://localhost:8000/mock/jira/oauth/token
 *   JIRA_SYNC_OAUTH_RESOURCES_URL=http://localhost:8000/mock/jira/oauth/accessible-resources
 *   JIRA_SYNC_OAUTH_CLIENT_ID=e2e-test-jira-client-id
 *
 * The Jira OAuth callback (code exchange) requires the backend to call the mock
 * token endpoint.  For integration tests that need an active connection, we seed
 * the connection row directly into the tickets DynamoDB table — the same table
 * that JiraTicketSyncStore uses (pk=WORKSPACE#<ws>, sk=JIRA_CONN#<connId>).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const API      = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

const WORKSPACE_ID  = `ws_jira_e2e_${TS}`;
const CLOUD_ID      = "cloud-id-1";
const CONNECTION_ID = `jira_conn_e2e_${TS}`;
const SITE_URL      = "https://mock-site.atlassian.net";

const SEED_PROJECTS = [
  { id: "10001", key: "ALPHA", name: "Alpha Project", isPrivate: false },
  { id: "10002", key: "BETA",  name: "Beta Project",  isPrivate: true },
];

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_admin_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
      ...(extraHeaders ?? {}),
    },
  });
}

async function apiPut(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time, json
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

const PYTHON = "python3";

/**
 * Seed a Jira connection row directly in the tickets DynamoDB table.
 *
 * This bypasses the OAuth callback flow so we can test status, preferences,
 * and disconnect endpoints without a full OAuth round-trip.  The row matches
 * the schema JiraTicketSyncStore.upsert_connection writes (pk=WORKSPACE#<ws>,
 * sk=JIRA_CONN#<connId>) including all GSI projection keys.
 */
function seedJiraConnection(
  workspaceId: string,
  connectionId: string,
  userSub: string,
  cloudId: string,
  siteUrl: string,
): void {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 7200;
  const accessRef = `jira-oauth://access/e2e-${TS}`;
  const refreshRef = `jira-oauth://refresh/e2e-${TS}`;

  execSync(
    `${PYTHON} -c "
import sys; sys.path.insert(0, '${REPO_ROOT}')
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('TICKETS_TABLE_NAME', 'tickets'))
tbl.put_item(Item={
    'pk': 'WORKSPACE#${workspaceId}',
    'sk': 'JIRA_CONN#${connectionId}',
    'entity_type': 'jira_connection',
    'workspace_id': '${workspaceId}',
    'connection_id': '${connectionId}',
    'user_id': '${userSub}',
    'cloud_id': '${cloudId}',
    'site_url': '${siteUrl}',
    'auth_type': 'oauth',
    'scopes': ['read:jira-work', 'write:jira-work', 'offline_access'],
    'access_token_ref': '${accessRef}',
    'refresh_token_ref': '${refreshRef}',
    'expires_at': ${expiresAt},
    'status': 'active',
    'created_at': ${now},
    'updated_at': ${now},
    'gsi_jira_workspace_pk': 'WORKSPACE#${workspaceId}',
    'gsi_jira_workspace_sk': 'UPDATED#${String(now).padStart(13, '0')}#CONN#${connectionId}',
    'gsi_jira_sync_state_pk': 'SYNC_STATE#active',
    'gsi_jira_sync_state_sk': 'UPDATED#${String(now).padStart(13, '0')}#CONN#${connectionId}#ACTOR#${userSub}',
})
print('seeded connection')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Clean up the seeded Jira connection from DDB.
 */
function cleanupJiraConnection(workspaceId: string, connectionId: string): void {
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('TICKETS_TABLE_NAME', 'tickets'))
tbl.delete_item(Key={'pk': 'WORKSPACE#${workspaceId}', 'sk': 'JIRA_CONN#${connectionId}'})
print('cleaned up connection')
"`,
      { cwd: REPO_ROOT, timeout: 15_000 },
    );
  } catch {
    // best-effort cleanup
  }
}

/**
 * Clean up preferences from DDB.
 */
function cleanupJiraPreferences(workspaceId: string, userSub: string, cloudId: string): void {
  try {
    execSync(
      `${PYTHON} -c "
${DDB_PRELUDE}
tbl = ddb.Table(os.environ.get('TICKETS_TABLE_NAME', 'tickets'))
tbl.delete_item(Key={'pk': 'WORKSPACE#${workspaceId}', 'sk': 'JIRA_PREFS#${userSub}#${cloudId}'})
print('cleaned up preferences')
"`,
      { cwd: REPO_ROOT, timeout: 15_000 },
    );
  } catch {
    // best-effort cleanup
  }
}

// ─── Mock seed/reset helpers ─────────────────────────────────────────────────

async function seedMock(page: Page) {
  // Reset mock state first
  const resetResp = await page.request.post(`${API}/mock/jira/reset`);
  expect(resetResp.status()).toBe(200);

  // Seed mock with projects and sites
  const seedResp = await page.request.post(`${API}/mock/jira/seed`, {
    data: {
      tokens: {},
      sites: [
        {
          id: CLOUD_ID,
          url: SITE_URL,
          name: "Mock Site",
          scopes: ["read:jira-work", "write:jira-work", "offline_access"],
          avatarUrl: `${SITE_URL}/avatar`,
        },
      ],
      projects: {
        [CLOUD_ID]: SEED_PROJECTS,
      },
      issues: [],
    },
  });
  expect(seedResp.status()).toBe(200);
  const seedBody = await seedResp.json();
  expect(seedBody.ok).toBe(true);
}

// =============================================================================
// Section 80 — Jira OAuth connect flow
// =============================================================================

test.describe("80 · Jira OAuth connect flow", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    await seedMock(alicePage);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("80.1 connect returns authorization URL and state", async () => {
    const resp = await apiPost(alicePage, "alice", "/integrations/jira/connect", {
      workspace_id: WORKSPACE_ID,
      redirect_uri: `${BASE}/integrations/jira/callback`,
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.connect_url).toBeTruthy();
    expect(body.state).toBeTruthy();
    // The connect_url should contain the client_id and state
    expect(body.connect_url).toContain("client_id=");
    expect(body.connect_url).toContain(`state=${body.state}`);
    expect(body.connect_url).toContain("response_type=code");
    expect(body.connect_url).toContain("prompt=consent");
  });
});

// =============================================================================
// Section 81 — Jira connection lifecycle via DDB-seeded connection
// =============================================================================

test.describe("81 · Jira connection lifecycle", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    await seedMock(alicePage);

    // Seed a Jira connection directly in DDB
    seedJiraConnection(WORKSPACE_ID, CONNECTION_ID, ALICE_ID, CLOUD_ID, SITE_URL);
  });

  test.afterAll(async () => {
    cleanupJiraPreferences(WORKSPACE_ID, ALICE_ID, CLOUD_ID);
    cleanupJiraConnection(WORKSPACE_ID, CONNECTION_ID);
    await alicePage.close();
  });

  test("81.1 status shows connected after seeded connection", async () => {
    const resp = await apiGet(alicePage, "/integrations/jira/status", {
      workspace_id: WORKSPACE_ID,
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.connected).toBe(true);
    expect(body.items).toBeDefined();
    expect(body.items.length).toBeGreaterThanOrEqual(1);

    const conn = body.items.find(
      (c: { connection_id: string }) => c.connection_id === CONNECTION_ID,
    );
    expect(conn).toBeTruthy();
    expect(conn.cloud_id).toBe(CLOUD_ID);
    expect(conn.site_url).toBe(SITE_URL);
    expect(conn.status).toBe("active");
    expect(conn.workspace_id).toBe(WORKSPACE_ID);
  });

  test("81.2 set project preferences", async () => {
    const resp = await apiPut(alicePage, "alice", "/integrations/jira/preferences", {
      workspace_id: WORKSPACE_ID,
      cloud_id: CLOUD_ID,
      project_keys: ["ALPHA", "BETA"],
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.workspace_id).toBe(WORKSPACE_ID);
    expect(body.cloud_id).toBe(CLOUD_ID);
    expect(body.project_keys).toEqual(expect.arrayContaining(["ALPHA", "BETA"]));
    expect(body.updated_at).toBeTruthy();
  });

  test("81.3 get project preferences returns saved keys", async () => {
    const resp = await apiGet(alicePage, "/integrations/jira/preferences", {
      workspace_id: WORKSPACE_ID,
      cloud_id: CLOUD_ID,
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.workspace_id).toBe(WORKSPACE_ID);
    expect(body.cloud_id).toBe(CLOUD_ID);
    expect(body.project_keys).toEqual(expect.arrayContaining(["ALPHA", "BETA"]));
  });

  test("81.4 update preferences to subset", async () => {
    const resp = await apiPut(alicePage, "alice", "/integrations/jira/preferences", {
      workspace_id: WORKSPACE_ID,
      cloud_id: CLOUD_ID,
      project_keys: ["ALPHA"],
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.project_keys).toEqual(["ALPHA"]);

    // Verify with GET
    const getResp = await apiGet(alicePage, "/integrations/jira/preferences", {
      workspace_id: WORKSPACE_ID,
      cloud_id: CLOUD_ID,
    });
    const getBody = await getResp.json();
    expect(getBody.project_keys).toEqual(["ALPHA"]);
  });

  test("81.5 disconnect removes connection", async () => {
    // First verify connected
    const statusBefore = await apiGet(alicePage, "/integrations/jira/status", {
      workspace_id: WORKSPACE_ID,
    });
    const beforeBody = await statusBefore.json();
    expect(beforeBody.connected).toBe(true);

    // Disconnect
    const resp = await apiPost(alicePage, "alice", "/integrations/jira/disconnect", {
      workspace_id: WORKSPACE_ID,
      connection_id: CONNECTION_ID,
    });
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.ok).toBe(true);

    // Verify disconnected
    const statusAfter = await apiGet(alicePage, "/integrations/jira/status", {
      workspace_id: WORKSPACE_ID,
    });
    expect(statusAfter.status()).toBe(200);

    const afterBody = await statusAfter.json();
    // After disconnect, the connection should no longer appear
    const conn = afterBody.items.find(
      (c: { connection_id: string }) => c.connection_id === CONNECTION_ID,
    );
    expect(conn).toBeUndefined();
    expect(afterBody.connected).toBe(false);
  });
});

// =============================================================================
// Section 82 — Jira mock issue operations (direct mock endpoints)
// =============================================================================

test.describe("82 · Jira mock issue operations", () => {
  let alicePage: Page;
  const MOCK_TOKEN = "mock-e2e-section82";
  const MOCK_HEADERS = {
    Authorization: `Bearer ${MOCK_TOKEN}`,
    "Content-Type": "application/json",
  };

  /** Issue tracking across tests within this section */
  let createdIssueId: string;
  let createdIssueKey: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");

    // Reset + seed mock with projects for CLOUD_ID
    await seedMock(alicePage);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("82.1 list accessible resources returns seeded sites", async () => {
    const resp = await alicePage.request.get(
      `${API}/mock/jira/oauth/accessible-resources`,
      { headers: MOCK_HEADERS },
    );
    expect(resp.status()).toBe(200);

    const sites = await resp.json();
    expect(Array.isArray(sites)).toBe(true);
    expect(sites.length).toBeGreaterThanOrEqual(1);

    const site = sites.find((s: { id: string }) => s.id === CLOUD_ID);
    expect(site).toBeTruthy();
    expect(site.url).toBe(SITE_URL);
    expect(site.name).toBe("Mock Site");
    expect(site.scopes).toEqual(
      expect.arrayContaining(["read:jira-work", "write:jira-work"]),
    );
  });

  test("82.2 create issue via mock Jira REST API", async () => {
    const resp = await alicePage.request.post(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/issue`,
      {
        headers: MOCK_HEADERS,
        data: {
          fields: {
            project: { key: "ALPHA" },
            summary: `E2E issue ${TS}`,
            description: "Created by section 82 E2E test",
            issuetype: { name: "Bug" },
          },
        },
      },
    );
    expect(resp.status()).toBe(200);

    const body = await resp.json();
    expect(body.id).toBeTruthy();
    expect(body.key).toMatch(/^ALPHA-\d+$/);
    expect(body.self).toContain(`/ex/jira/${CLOUD_ID}/rest/api/3/issue/`);

    // Store for subsequent tests
    createdIssueId = body.id;
    createdIssueKey = body.key;
  });

  test("82.3 get issue details returns created issue", async () => {
    expect(createdIssueId).toBeTruthy();

    const resp = await alicePage.request.get(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/issue/${createdIssueId}`,
      { headers: MOCK_HEADERS },
    );
    expect(resp.status()).toBe(200);

    const issue = await resp.json();
    expect(issue.id).toBe(createdIssueId);
    expect(issue.key).toBe(createdIssueKey);
    expect(issue.fields).toBeTruthy();
    expect(issue.fields.summary).toBe(`E2E issue ${TS}`);
    expect(issue.fields.description).toBe("Created by section 82 E2E test");
    expect(issue.fields.issuetype.name).toBe("Bug");
    expect(issue.fields.project.key).toBe("ALPHA");
    expect(issue.fields.status.name).toBe("To Do");
    expect(issue.fields.created).toBeTruthy();
    expect(issue.fields.updated).toBeTruthy();

    // Also verify lookup by key works
    const respByKey = await alicePage.request.get(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/issue/${createdIssueKey}`,
      { headers: MOCK_HEADERS },
    );
    expect(respByKey.status()).toBe(200);
    const issueByKey = await respByKey.json();
    expect(issueByKey.id).toBe(createdIssueId);
  });

  test("82.4 update issue fields via PUT", async () => {
    expect(createdIssueId).toBeTruthy();

    const resp = await alicePage.request.put(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/issue/${createdIssueId}`,
      {
        headers: MOCK_HEADERS,
        data: {
          fields: {
            summary: `Updated issue ${TS}`,
            status: { name: "In Progress" },
          },
        },
      },
    );
    // Jira REST API returns 204 No Content on successful update
    expect(resp.status()).toBe(204);

    // Verify the update persisted
    const getResp = await alicePage.request.get(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/issue/${createdIssueId}`,
      { headers: MOCK_HEADERS },
    );
    expect(getResp.status()).toBe(200);
    const updated = await getResp.json();
    expect(updated.fields.summary).toBe(`Updated issue ${TS}`);
    expect(updated.fields.status.name).toBe("In Progress");
    // Original fields should be preserved
    expect(updated.fields.description).toBe("Created by section 82 E2E test");
    expect(updated.fields.issuetype.name).toBe("Bug");
  });

  test("82.5 search issues by JQL project filter", async () => {
    // Create a second issue in a different project for contrast
    const resp2 = await alicePage.request.post(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/issue`,
      {
        headers: MOCK_HEADERS,
        data: {
          fields: {
            project: { key: "BETA" },
            summary: `Beta issue ${TS}`,
            issuetype: { name: "Task" },
          },
        },
      },
    );
    expect(resp2.status()).toBe(200);

    // Search for ALPHA project issues only
    const searchResp = await alicePage.request.get(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/search`,
      {
        headers: MOCK_HEADERS,
        params: { jql: "project = ALPHA" },
      },
    );
    expect(searchResp.status()).toBe(200);

    const searchBody = await searchResp.json();
    expect(searchBody.issues).toBeDefined();
    expect(Array.isArray(searchBody.issues)).toBe(true);
    expect(searchBody.total).toBeGreaterThanOrEqual(1);
    expect(searchBody.startAt).toBe(0);

    // All returned issues should belong to ALPHA project
    for (const issue of searchBody.issues) {
      expect(issue.fields.project.key).toBe("ALPHA");
    }

    // The ALPHA issue we created should be in results
    const found = searchBody.issues.find(
      (i: { id: string }) => i.id === createdIssueId,
    );
    expect(found).toBeTruthy();
    // It should reflect the updated summary from test 82.4
    expect(found.fields.summary).toBe(`Updated issue ${TS}`);

    // Search without JQL — should return all issues for this cloud_id
    const allResp = await alicePage.request.get(
      `${API}/mock/jira/ex/jira/${CLOUD_ID}/rest/api/3/search`,
      {
        headers: MOCK_HEADERS,
        params: { jql: "" },
      },
    );
    expect(allResp.status()).toBe(200);
    const allBody = await allResp.json();
    // Should include both ALPHA and BETA issues
    expect(allBody.total).toBeGreaterThanOrEqual(2);
    const projectKeys = allBody.issues.map(
      (i: { fields: { project: { key: string } } }) => i.fields.project.key,
    );
    expect(projectKeys).toContain("ALPHA");
    expect(projectKeys).toContain("BETA");
  });
});
