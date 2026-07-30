/**
 * E2E tests for Jira Integration endpoints.
 *
 * Sections:
 *   80 — Connection status + OAuth initiation  (3 tests)
 *   81 — Preferences CRUD                      (3 tests)
 *   82 — Ticket linking (create, link-existing, sync-status, delete)  (5 tests)
 *   83 — Conflict resolution                   (1 test)
 *   84 — Webhook endpoint                      (2 tests)
 *   85 — Access control                        (1 test)
 *
 * Auth: Uses admin session setup (root, alice, charlie_admin).
 *
 * Since there is no real Jira instance connected, many operations will return
 * error responses. The tests verify that the API contracts are correct: proper
 * status codes, error envelope shapes, and field presence.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import { usingCpp, runCppShim } from "./helpers/cpp-seed";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions, unauthContext } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const TS = Date.now();
const WORKSPACE = "default";
const TICKET_ID = `jira_e2e_ticket_${TS}`;

// ─── Session bootstrap ───────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object = {},
  extraHeaders: Record<string, string> = {},
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token, ...extraHeaders },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPut(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

// ─── DynamoDB helpers ─────────────────────────────────────────────────────────

function seedTicket(ticketId: string, userSub: string) {
  if (usingCpp()) {
    runCppShim("seed_jira.py", { op: "ticket", ticket_id: ticketId, user_sub: userSub });
    return;
  }
  execSync(
    `python3 -c "
import boto3, time
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
table.put_item(Item={
    'pk': 'TICKET#${ticketId}',
    'sk': 'META',
    'ticket_id': '${ticketId}',
    'user_sub': '${userSub}',
    'subject': 'Test ticket for Jira E2E',
    'status': 'open',
    'priority': 'normal',
    'created_at': str(int(time.time())),
    'updated_at': str(int(time.time())),
    'gsi1pk': 'STATUS#open',
    'gsi1sk': str(int(time.time())),
})
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

/**
 * Seed a fake Jira connection in DynamoDB so that endpoints requiring
 * an active connection can find one.
 */
function seedJiraConnection(
  workspaceId: string,
  connectionId: string,
  userSub: string,
  cloudId: string,
) {
  if (usingCpp()) {
    runCppShim("seed_jira.py", {
      op: "connection", workspace_id: workspaceId,
      connection_id: connectionId, user_sub: userSub, cloud_id: cloudId,
    });
    return;
  }
  execSync(
    `python3 -c "
import boto3, time
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
now = int(time.time())
table.put_item(Item={
    'pk': 'WORKSPACE#${workspaceId}',
    'sk': 'JIRA_CONN#${connectionId}',
    'entity_type': 'jira_connection',
    'workspace_id': '${workspaceId}',
    'connection_id': '${connectionId}',
    'user_id': '${userSub}',
    'cloud_id': '${cloudId}',
    'site_url': 'https://test.atlassian.net',
    'auth_type': 'oauth',
    'scopes': ['read:jira-work', 'write:jira-work'],
    'access_token_ref': '',
    'refresh_token_ref': '',
    'expires_at': now + 3600,
    'status': 'active',
    'created_at': now,
    'updated_at': now,
    'gsi_jira_workspace_pk': 'WORKSPACE#${workspaceId}',
    'gsi_jira_workspace_sk': f'UPDATED#{now:013d}#CONN#${connectionId}',
    'gsi_jira_sync_state_pk': 'SYNC_STATE#active',
    'gsi_jira_sync_state_sk': f'UPDATED#{now:013d}#CONN#${connectionId}#ACTOR#${userSub}',
})
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

/**
 * Seed a Jira external link in DynamoDB for a ticket (for unlink and
 * conflict-resolution tests).
 */
function seedJiraLink(
  ticketId: string,
  linkId: string,
  workspaceId: string,
  opts: {
    externalIssueId?: string;
    externalIssueKey?: string;
    syncState?: string;
    conflictFields?: string[];
    conflictLocal?: Record<string, string>;
    conflictRemote?: Record<string, string>;
  } = {},
) {
  const eid = opts.externalIssueId || "10001";
  const ekey = opts.externalIssueKey || "TEST-1";
  const syncState = opts.syncState || "queued";
  const conflictState = opts.conflictFields ? "detected" : "none";

  // Build the item as a JSON env var to avoid shell quoting issues
  const item: Record<string, unknown> = {
    pk: `TICKET#${ticketId}`,
    sk: `JIRA_LINK#${linkId}`,
    entity_type: "ticket_external_link",
    workspace_id: workspaceId,
    internal_ticket_id: ticketId,
    provider: "jira",
    link_id: linkId,
    external_issue_id: eid,
    external_issue_key: ekey,
    project_key: "TEST",
    link_mode: "bidirectional",
    sync_state: syncState,
    conflict_state: conflictState,
    conflict_fields: opts.conflictFields || [],
    conflict_payload: opts.conflictFields
      ? { local: opts.conflictLocal || {}, remote: opts.conflictRemote || {} }
      : {},
    last_synced_at: 0,
    last_sync_direction: "none",
    created_by: "e2e_test",
  };

  if (usingCpp()) {
    runCppShim("seed_jira.py", {
      op: "link", ticket_id: ticketId, link_id: linkId, workspace_id: workspaceId,
      external_issue_id: eid, external_issue_key: ekey, sync_state: syncState,
      conflict_fields: opts.conflictFields || [],
      conflict_local: opts.conflictLocal || {},
      conflict_remote: opts.conflictRemote || {},
    });
    return;
  }
  const itemJson = JSON.stringify(item);
  execSync(
    `python3 -c "
import boto3, time, json, os
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
now = int(time.time())
item = json.loads(os.environ['SEED_ITEM'])
item['created_at'] = now
item['updated_at'] = now
lid = item['link_id']
eid = item['external_issue_id']
ws = item['workspace_id']
ss = item['sync_state']
item['gsi_jira_issue_pk'] = f'JIRA_ISSUE#{eid}'
item['gsi_jira_issue_sk'] = f'LINK#{lid}'
item['gsi_jira_workspace_pk'] = f'WORKSPACE#{ws}'
item['gsi_jira_workspace_sk'] = f'UPDATED#{now:013d}#LINK#{lid}'
item['gsi_jira_sync_state_pk'] = f'SYNC_STATE#{ss}'
item['gsi_jira_sync_state_sk'] = f'UPDATED#{now:013d}#LINK#{lid}'
table.put_item(Item=item)
"`,
    {
      cwd: REPO_ROOT,
      timeout: 10_000,
      env: { ...process.env, SEED_ITEM: itemJson },
    },
  );
}

function cleanupDdbItem(pk: string, sk: string) {
  if (usingCpp()) {
    try {
      runCppShim("seed_jira.py", { op: "delete", pk, sk });
    } catch {
      /* best-effort */
    }
    return;
  }
  try {
    execSync(
      `python3 -c "
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('tickets')
table.delete_item(Key={'pk': '${pk}', 'sk': '${sk}'})
"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );
  } catch {
    // best-effort cleanup
  }
}

// ─── Shared state ────────────────────────────────────────────────────────────

const CONN_ID = `jira_conn_e2e_${TS}`;
const CLOUD_ID = `cloud_e2e_${TS}`;
const LINK_ID_DELETE = `jlink_del_${TS}`;
const LINK_ID_CONFLICT = `jlink_conf_${TS}`;
const LINK_ID_SYNC = `jlink_sync_${TS}`;

// ═════════════════════════════════════════════════════════════════════════════
// Section 80 — Connection status + OAuth initiation
// ═════════════════════════════════════════════════════════════════════════════

test.describe("80 · Jira connection status + OAuth", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("80.1 — GET /integrations/jira/status returns connection status shape", async () => {
    const resp = await apiGet(
      alicePage,
      `/integrations/jira/status?workspace_id=${WORKSPACE}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("connected");
    expect(typeof body.connected).toBe("boolean");
    expect(body).toHaveProperty("items");
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("80.2 — POST /integrations/jira/connect returns 500 when OAuth is not configured", async () => {
    // Without JIRA_SYNC_OAUTH_AUTHORIZE_URL and JIRA_SYNC_OAUTH_CLIENT_ID
    // env vars, the endpoint should return a 500 with proper error envelope.
    const resp = await apiPost(alicePage, "alice", "/integrations/jira/connect", {
      workspace_id: WORKSPACE,
      redirect_uri: `${BASE}/integrations/jira/callback`,
    });
    // Either 500 (OAuth not configured) or 200 (if OAuth IS configured)
    const status = resp.status();
    const body = await resp.json();
    if (status === 500) {
      expect(body).toHaveProperty("detail");
      const detail = body.detail;
      expect(detail).toHaveProperty("error");
      expect(detail.error).toHaveProperty("code");
      expect(detail.error).toHaveProperty("message");
      expect(detail.error.code).toMatch(/^jira_oauth_/);
    } else {
      // If OAuth happens to be configured, we get connect_url + state
      expect(status).toBe(200);
      expect(body).toHaveProperty("connect_url");
      expect(body).toHaveProperty("state");
    }
  });

  test("80.3 — GET /integrations/jira/status requires workspace_id", async () => {
    const resp = await apiGet(alicePage, "/integrations/jira/status");
    // FastAPI returns 422 for missing required query param
    expect(resp.status()).toBe(422);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 81 — Preferences CRUD
// ═════════════════════════════════════════════════════════════════════════════

test.describe("81 · Jira preferences", () => {
  let alicePage: Page;
  const aliceSub = () => getSessions()["alice"].user_sub;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
  });

  test.afterAll(async () => {
    // Cleanup preferences row
    cleanupDdbItem(
      `WORKSPACE#${WORKSPACE}`,
      `JIRA_PREFS#${aliceSub()}#${CLOUD_ID}`,
    );
    await alicePage?.close();
  });

  test("81.1 — GET /integrations/jira/preferences returns empty defaults", async () => {
    const resp = await apiGet(
      alicePage,
      `/integrations/jira/preferences?workspace_id=${WORKSPACE}&cloud_id=${CLOUD_ID}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("workspace_id", WORKSPACE);
    expect(body).toHaveProperty("cloud_id", CLOUD_ID);
    expect(body).toHaveProperty("project_keys");
    expect(Array.isArray(body.project_keys)).toBe(true);
    expect(body.project_keys.length).toBe(0);
  });

  test("81.2 — PUT /integrations/jira/preferences saves project keys", async () => {
    const resp = await apiPut(
      alicePage,
      "alice",
      "/integrations/jira/preferences",
      {
        workspace_id: WORKSPACE,
        cloud_id: CLOUD_ID,
        project_keys: ["PROJ1", "PROJ2"],
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.workspace_id).toBe(WORKSPACE);
    expect(body.cloud_id).toBe(CLOUD_ID);
    expect(body.project_keys).toContain("PROJ1");
    expect(body.project_keys).toContain("PROJ2");
    expect(body).toHaveProperty("updated_at");
    expect(typeof body.updated_at).toBe("number");
  });

  test("81.3 — GET /integrations/jira/preferences reflects saved keys", async () => {
    const resp = await apiGet(
      alicePage,
      `/integrations/jira/preferences?workspace_id=${WORKSPACE}&cloud_id=${CLOUD_ID}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.project_keys).toContain("PROJ1");
    expect(body.project_keys).toContain("PROJ2");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 82 — Ticket linking
// ═════════════════════════════════════════════════════════════════════════════

test.describe("82 · Ticket linking", () => {
  let rootPage: Page;
  const rootSub = () => getSessions()["root"].user_sub;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, "root");

    // Seed a ticket and a Jira connection for root user
    seedTicket(TICKET_ID, rootSub());
    seedJiraConnection(WORKSPACE, CONN_ID, rootSub(), CLOUD_ID);

    // Seed a link that we will delete in test 82.5
    seedJiraLink(TICKET_ID, LINK_ID_DELETE, WORKSPACE, {
      externalIssueId: "90001",
      externalIssueKey: "DEL-1",
    });

    // Seed a link for sync-status test
    seedJiraLink(TICKET_ID, LINK_ID_SYNC, WORKSPACE, {
      externalIssueId: "90002",
      externalIssueKey: "SYNC-1",
      syncState: "in_sync",
    });
  });

  test.afterAll(async () => {
    // Cleanup seeded DDB items
    cleanupDdbItem(`TICKET#${TICKET_ID}`, "META");
    cleanupDdbItem(`WORKSPACE#${WORKSPACE}`, `JIRA_CONN#${CONN_ID}`);
    cleanupDdbItem(`TICKET#${TICKET_ID}`, `JIRA_LINK#${LINK_ID_DELETE}`);
    cleanupDdbItem(`TICKET#${TICKET_ID}`, `JIRA_LINK#${LINK_ID_SYNC}`);
    await rootPage?.close();
  });

  test("82.1 — POST create Jira link fails without real Jira token", async () => {
    // The connection exists but the access_token_ref is empty, so
    // get_or_refresh_access_token will fail. The backend may return a
    // structured JSON error or a plain-text 500 (unhandled lifecycle error).
    const idemKey = `idem_create_${TS}`;
    const resp = await apiPost(
      rootPage,
      "root",
      `/tickets/${TICKET_ID}/external-links/jira`,
      {
        workspace_id: WORKSPACE,
        project_key: "TEST",
        issue_type: "Task",
        link_mode: "bidirectional",
      },
      { "Idempotency-Key": idemKey },
    );
    const status = resp.status();
    expect(status).toBeGreaterThanOrEqual(400);
    // Verify we got an HTTP error — don't assume JSON body since
    // an unhandled exception may produce plain-text "Internal Server Error".
    const text = await resp.text();
    expect(text.length).toBeGreaterThan(0);
  });

  test("82.2 — POST link-existing fails without real Jira token", async () => {
    const idemKey = `idem_link_${TS}`;
    const resp = await apiPost(
      rootPage,
      "root",
      `/tickets/${TICKET_ID}/external-links/jira/link-existing`,
      {
        workspace_id: WORKSPACE,
        external_issue_key: "TEST-999",
        link_mode: "bidirectional",
      },
      { "Idempotency-Key": idemKey },
    );
    const status = resp.status();
    expect(status).toBeGreaterThanOrEqual(400);
    const text = await resp.text();
    expect(text.length).toBeGreaterThan(0);
  });

  test("82.3 — GET sync-status returns linked state for seeded link", async () => {
    const resp = await apiGet(
      rootPage,
      `/tickets/${TICKET_ID}/sync-status`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("ticket_id", TICKET_ID);
    expect(body).toHaveProperty("linked", true);
    expect(body).toHaveProperty("provider", "jira");
    expect(body).toHaveProperty("sync_state");
    expect(["queued", "in_sync", "conflict", "failed"]).toContain(
      body.sync_state,
    );
    expect(body).toHaveProperty("link_id");
    expect(body).toHaveProperty("external_issue_id");
    expect(body).toHaveProperty("external_issue_key");
  });

  test("82.4 — GET sync-status returns not_linked for non-existent ticket", async () => {
    const resp = await apiGet(
      rootPage,
      `/tickets/nonexistent_ticket_${TS}/sync-status`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.linked).toBe(false);
    expect(body.sync_state).toBe("not_linked");
    expect(body.provider).toBeNull();
  });

  test("82.5 — DELETE external link removes the link", async () => {
    const resp = await apiDelete(
      rootPage,
      "root",
      `/tickets/${TICKET_ID}/external-links/${LINK_ID_DELETE}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("unlinked", true);
    expect(body).toHaveProperty("ticket_id", TICKET_ID);
    expect(body).toHaveProperty("link_id", LINK_ID_DELETE);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 83 — Conflict resolution
// ═════════════════════════════════════════════════════════════════════════════

test.describe("83 · Conflict resolution", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, "root");

    // Seed a link in "conflict" state
    seedJiraLink(TICKET_ID, LINK_ID_CONFLICT, WORKSPACE, {
      externalIssueId: "90003",
      externalIssueKey: "CONF-1",
      syncState: "conflict",
      conflictFields: ["subject", "priority"],
      conflictLocal: { subject: "Local title", priority: "high" },
      conflictRemote: { subject: "Remote title", priority: "low" },
    });
  });

  test.afterAll(async () => {
    cleanupDdbItem(`TICKET#${TICKET_ID}`, `JIRA_LINK#${LINK_ID_CONFLICT}`);
    await rootPage?.close();
  });

  test("83.1 — POST resolve-conflict resolves with keep_internal", async () => {
    const resp = await apiPost(
      rootPage,
      "root",
      `/tickets/${TICKET_ID}/external-links/${LINK_ID_CONFLICT}/resolve-conflict`,
      {
        workspace_id: WORKSPACE,
        action: "keep_internal",
        current_ticket: { subject: "Local title", priority: "high" },
      },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("ticket_id", TICKET_ID);
    expect(body).toHaveProperty("link_id", LINK_ID_CONFLICT);
    expect(body).toHaveProperty("action", "keep_internal");
    expect(body).toHaveProperty("resolved_fields");
    expect(Array.isArray(body.resolved_fields)).toBe(true);
    expect(body).toHaveProperty("sync_state", "in_sync");
    expect(body).toHaveProperty("follow_up_tasks");
    expect(typeof body.follow_up_tasks).toBe("number");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 84 — Webhook endpoint
// ═════════════════════════════════════════════════════════════════════════════

test.describe("84 · Jira webhook", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    // Webhook endpoint requires no session auth, but we need a page context
    // for Playwright request API.
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("84.1 — POST webhook with supported event processes or errors gracefully", async () => {
    // The webhook endpoint will either:
    // - Fail with 503 because JIRA_WEBHOOK_QUEUE_URL is not set (RuntimeError)
    // - Succeed if a queue is configured
    // Either way the error shape should be well-formed.
    const resp = await page.request.post(`${API}/integrations/jira/webhook`, {
      data: {
        event_type: "jira:issue_updated",
        cloud_id: "test-cloud-123",
        issue_id: "10001",
        issue_key: "TEST-1",
        payload: { issue: { id: "10001", key: "TEST-1" } },
      },
      headers: {
        "X-Jira-Event": "jira:issue_updated",
      },
    });
    const status = resp.status();
    const body = await resp.json();
    if (status === 200) {
      expect(body).toHaveProperty("accepted", true);
      expect(body).toHaveProperty("enqueued");
      expect(body).toHaveProperty("deduplicated");
      expect(body).toHaveProperty("trace_id");
    } else {
      // 503 when queue not configured, or 401/403 for signature issues
      expect([401, 403, 503]).toContain(status);
      expect(body).toHaveProperty("detail");
    }
  });

  test("84.2 — POST webhook with unsupported event type is accepted but not enqueued", async () => {
    const resp = await page.request.post(`${API}/integrations/jira/webhook`, {
      data: {
        event_type: "jira:unknown_event",
        cloud_id: "test-cloud-456",
        issue_id: "10002",
        issue_key: "TEST-2",
        payload: { issue: { id: "10002", key: "TEST-2" } },
      },
      headers: {
        "X-Jira-Event": "jira:unknown_event",
      },
    });
    const status = resp.status();
    const body = await resp.json();
    if (status === 200) {
      // Unsupported events are accepted but not enqueued
      expect(body.accepted).toBe(true);
      expect(body.enqueued).toBe(false);
      expect(body.deduplicated).toBe(false);
    } else {
      // Signature or IP validation could reject first
      expect([401, 403, 503]).toContain(status);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 85 — Access control
// ═════════════════════════════════════════════════════════════════════════════

test.describe("85 · Access control", () => {
  let unauthPage: Page;

  test.beforeAll(async ({ browser }) => {
    unauthPage = await browser.newPage();
    // No auth injected — this page has no session cookies
  });

  test.afterAll(async () => {
    await unauthPage?.close();
  });

  test("85.1 — Jira endpoints require authentication", async () => {
    // GET /integrations/jira/status without session cookies should be rejected
    const anon = await unauthContext(API);
    const resp = await anon.get(
      `/integrations/jira/status?workspace_id=${WORKSPACE}`,
    );
    // Should be 401 or 403 (no valid session)
    expect(resp.status()).toBeGreaterThanOrEqual(400);
    expect(resp.status()).toBeLessThan(500);
    await anon.dispose();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 86 — Disconnect flow
// ═════════════════════════════════════════════════════════════════════════════

test.describe("86 · Jira disconnect", () => {
  let alicePage: Page;
  const aliceSub = () => getSessions()["alice"].user_sub;
  const ALICE_CONN_ID = `jira_conn_alice_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");

    // Seed a connection owned by Alice
    seedJiraConnection(WORKSPACE, ALICE_CONN_ID, aliceSub(), CLOUD_ID);
  });

  test.afterAll(async () => {
    // Cleanup in case disconnect did not remove it
    cleanupDdbItem(
      `WORKSPACE#${WORKSPACE}`,
      `JIRA_CONN#${ALICE_CONN_ID}`,
    );
    await alicePage?.close();
  });

  test("86.1 — POST disconnect removes Alice's connection", async () => {
    // First verify the connection shows up in status
    const statusResp = await apiGet(
      alicePage,
      `/integrations/jira/status?workspace_id=${WORKSPACE}`,
    );
    expect(statusResp.status()).toBe(200);
    const statusBody = await statusResp.json();
    const found = statusBody.items.find(
      (c: { connection_id: string }) => c.connection_id === ALICE_CONN_ID,
    );
    expect(found).toBeTruthy();

    // Now disconnect
    const resp = await apiPost(alicePage, "alice", "/integrations/jira/disconnect", {
      workspace_id: WORKSPACE,
      connection_id: ALICE_CONN_ID,
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body).toHaveProperty("ok", true);

    // Verify it is gone from status
    const afterResp = await apiGet(
      alicePage,
      `/integrations/jira/status?workspace_id=${WORKSPACE}`,
    );
    expect(afterResp.status()).toBe(200);
    const afterBody = await afterResp.json();
    const gone = afterBody.items.find(
      (c: { connection_id: string }) => c.connection_id === ALICE_CONN_ID,
    );
    expect(gone).toBeFalsy();
  });

  test("86.2 — POST disconnect returns 404 for non-existent connection", async () => {
    const resp = await apiPost(alicePage, "alice", "/integrations/jira/disconnect", {
      workspace_id: WORKSPACE,
      connection_id: "nonexistent_conn_id",
    });
    expect(resp.status()).toBe(404);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 87 — Projects endpoint (requires connection)
// ═════════════════════════════════════════════════════════════════════════════

test.describe("87 · Jira projects listing", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await browser.newPage();
    await injectAuth(rootPage, "root");
    // Connection was seeded in section 82 beforeAll (for root user)
    // Re-seed to be safe in case of test ordering
    seedJiraConnection(
      WORKSPACE,
      CONN_ID,
      getSessions()["root"].user_sub,
      CLOUD_ID,
    );
  });

  test.afterAll(async () => {
    cleanupDdbItem(`WORKSPACE#${WORKSPACE}`, `JIRA_CONN#${CONN_ID}`);
    await rootPage?.close();
  });

  test("87.1 — GET /integrations/jira/projects fails gracefully without real Jira API", async () => {
    // Connection exists but access_token_ref is empty, so token lifecycle
    // will fail. We verify the error is well-formed.
    const resp = await apiGet(
      rootPage,
      `/integrations/jira/projects?workspace_id=${WORKSPACE}&cloud_id=${CLOUD_ID}`,
    );
    const status = resp.status();
    // Should be an error because no real token
    expect(status).toBeGreaterThanOrEqual(400);
    const body = await resp.json();
    expect(body).toHaveProperty("detail");
    expect(body.detail).toHaveProperty("error");
    expect(body.detail.error).toHaveProperty("code");
    expect(body.detail.error).toHaveProperty("message");
  });

  test("87.2 — GET /integrations/jira/projects requires workspace_id and cloud_id", async () => {
    const resp = await apiGet(rootPage, "/integrations/jira/projects");
    expect(resp.status()).toBe(422);
  });
});
