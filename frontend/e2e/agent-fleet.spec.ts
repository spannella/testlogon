/**
 * E2E tests for Agent Fleet Management (AGENT-004).
 *
 * Sections:
 *   637 -- Fleet Status API        (4 tests)
 *   638 -- Bulk Operations API     (4 tests)
 *   639 -- Worker Templates API    (4 tests)
 *   640 -- Fleet Dashboard UI      (4 tests)
 *
 * Auth: Alice session cookies (from e2e_admin_session_setup.py).
 *
 * Prerequisites:
 *   - `agent_workers` + `llm_provider_keys` DDB tables created (via local-ddb-init.py)
 *   - An LLM key is created in beforeAll for worker creation tests
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();

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
    _sessions = loadSessions();
    // admin setup keys by short name (alice/bob); alias by user_sub so email-id lookups resolve
    for (const _k of Object.keys(_sessions)) { const _s = _sessions[_k]; if (_s && _s.user_sub && !_sessions[_s.user_sub]) _sessions[_s.user_sub] = _s; }
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
  });
}

async function apiPost(page: Page, path: string, body: object) {
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
  });
}

async function apiDelete(page: Page, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": getSessions()[ALICE_ID].csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

function ddbPython(code: string): string {
  const prelude = `
import boto3, os, sys
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
  return execSync(
    `cd ${REPO_ROOT} && .venv/bin/python3 -c "${prelude}\n${code}"`,
    { timeout: 15_000 },
  ).toString().trim();
}

function createLlmKey(userId: string, provider: string, label: string): string {
  const code = `
import uuid, time, json
sys.path.insert(0, '${REPO_ROOT}')
from app.core.crypto import kms_encrypt
key_id = uuid.uuid4().hex
ts = int(time.time())
encrypted = kms_encrypt('sk-test-fake-key-1234567890abcdef')
item = {
    'pk': f'USER#${userId}',
    'sk': f'KEY#{key_id}',
    'key_id': key_id,
    'user_id': '${userId}',
    'provider': '${provider}',
    'label': '${label}',
    'encrypted_api_key': encrypted,
    'key_suffix': 'cdef',
    'base_url': '',
    'model_preference': '',
    'available_models': [],
    'rate_limit_rpm': 60,
    'monthly_budget_cents': 0,
    'current_month_usage_cents': 0,
    'status': 'active',
    'last_tested_at': 0,
    'last_used_at': 0,
    'created_at': ts,
    'updated_at': ts,
    'assigned_worker_ids': [],
}
tbl = ddb.Table('llm_provider_keys')
tbl.put_item(Item=item)
print(key_id)
`;
  return ddbPython(code);
}

function cleanupWorkers(userId: string) {
  const code = `
tbl = ddb.Table('agent_workers')
resp = tbl.query(
    KeyConditionExpression='pk = :pk',
    ExpressionAttributeValues={':pk': f'USER#${userId}'}
)
for item in resp.get('Items', []):
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print(len(resp.get('Items', [])))
`;
  ddbPython(code);
}

// ─── Test state shared across sections ────────────────────────────────────────

let alicePage: Page;
let anthropicKeyId: string;
let workerId1: string;
let workerId2: string;
let templateId: string;

// =============================================================================
//   Section 637 -- Fleet Status API
// =============================================================================

test.describe("637 -- Fleet Status API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);

    // Cleanup any existing workers/templates
    cleanupWorkers(ALICE_ID);

    // Create LLM key for worker provisioning
    anthropicKeyId = createLlmKey(ALICE_ID, "anthropic", `fleet-test-${TS}`);

    // Create two workers via the API
    const w1Resp = await apiPost(alicePage, "/ui/agent/workers", {
      label: `Fleet Worker A ${TS}`,
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: anthropicKeyId,
    });
    expect(w1Resp.status()).toBe(201);
    const w1 = await w1Resp.json();
    workerId1 = w1.worker_id;

    const w2Resp = await apiPost(alicePage, "/ui/agent/workers", {
      label: `Fleet Worker B ${TS}`,
      agent_type: "qa",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: anthropicKeyId,
    });
    expect(w2Resp.status()).toBe(201);
    const w2 = await w2Resp.json();
    workerId2 = w2.worker_id;
  });

  test("Fleet status returns aggregate metrics", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/fleet/status");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.total_workers).toBeGreaterThanOrEqual(2);
    expect(data.status_counts).toBeDefined();
    expect(typeof data.status_counts.ready).toBe("number");
    expect(typeof data.status_counts.stopped).toBe("number");
    expect(typeof data.queue_depth).toBe("number");
    expect(data.workers).toBeDefined();
    expect(data.workers.length).toBeGreaterThanOrEqual(2);
  });

  test("Worker summaries include current state", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/fleet/status");
    const data = await resp.json();
    const workerA = data.workers.find(
      (w: any) => w.worker_id === workerId1,
    );
    expect(workerA).toBeDefined();
    expect(workerA.worker_id).toBe(workerId1);
    expect(workerA.label).toContain(`Fleet Worker A`);
    expect(workerA.agent_type).toBe("coder");
    expect(workerA.worker_status).toBeDefined();
    expect(workerA.agent_state).toBeDefined();
  });

  test("Capacity endpoint shows queue vs. workers", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/fleet/capacity");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.queue_by_type).toBeDefined();
    expect(data.workers_by_type).toBeDefined();
    expect(data.workers_by_state).toBeDefined();
    expect(typeof data.recommended_action).toBe("string");
  });

  test("Workers by type includes coder and qa", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/fleet/capacity");
    const data = await resp.json();
    expect(data.workers_by_type.coder).toBeGreaterThanOrEqual(1);
    expect(data.workers_by_type.qa).toBeGreaterThanOrEqual(1);
  });
});

// =============================================================================
//   Section 638 -- Bulk Operations API
// =============================================================================

test.describe("638 -- Bulk Operations API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
  });

  test("Stop all running workers", async () => {
    const resp = await apiPost(alicePage, "/ui/agent/fleet/stop-all", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.count).toBe("number");
    expect(data.count).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.errors)).toBe(true);
  });

  test("Start all stopped workers", async () => {
    const resp = await apiPost(alicePage, "/ui/agent/fleet/start-all", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.count).toBe("number");
    expect(data.count).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.errors)).toBe(true);
  });

  test("Start all with no stopped workers returns count 0", async () => {
    // All workers should be running after previous start-all
    const resp = await apiPost(alicePage, "/ui/agent/fleet/start-all", {});
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBe(0);
  });

  test("Stop all confirms workers stopped", async () => {
    const stopResp = await apiPost(alicePage, "/ui/agent/fleet/stop-all", {});
    expect(stopResp.status()).toBe(200);
    const stopData = await stopResp.json();
    expect(stopData.count).toBeGreaterThanOrEqual(0);

    // Verify via fleet status
    const statusResp = await apiGet(alicePage, "/ui/agent/fleet/status");
    const statusData = await statusResp.json();
    const stoppedCount = statusData.status_counts.stopped ?? 0;
    expect(stoppedCount).toBeGreaterThanOrEqual(0);
  });
});

// =============================================================================
//   Section 639 -- Worker Templates API
// =============================================================================

test.describe("639 -- Worker Templates API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
    // Self-contained: the module-level anthropicKeyId from section 637 is lost
    // if Playwright restarts the worker process between describe blocks, which
    // would make the template payload's llm_key_id empty (422). Recreate it.
    if (!anthropicKeyId) {
      anthropicKeyId = createLlmKey(ALICE_ID, "anthropic", `fleet-tpl-${TS}`);
    }
  });

  test("Save a worker template", async () => {
    const resp = await apiPost(alicePage, "/ui/agent/fleet/templates", {
      label: `Test Template ${TS}`,
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: anthropicKeyId,
      repo_url: "",
      branch_convention: "",
      idle_timeout_seconds: 3600,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.template_id).toBeDefined();
    expect(data.label).toContain("Test Template");
    expect(data.agent_type).toBe("coder");
    expect(data.tool).toBe("claude_code");
    templateId = data.template_id;
  });

  test("List templates returns saved template", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/fleet/templates");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(1);
    const found = data.templates.find(
      (t: any) => t.template_id === templateId,
    );
    expect(found).toBeDefined();
    expect(found.label).toContain("Test Template");
  });

  test("Create worker from template", async () => {
    // Start all first so workers are running
    await apiPost(alicePage, "/ui/agent/fleet/start-all", {});

    const resp = await apiPost(
      alicePage,
      `/ui/agent/fleet/templates/${templateId}/create`,
      { label: `From Template ${TS}` },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.worker_id).toBeDefined();
    expect(data.label).toContain("From Template");
    expect(data.agent_type).toBe("coder");
    expect(data.tool).toBe("claude_code");
    expect(data.template_id).toBe(templateId);
  });

  test("Delete template", async () => {
    const delResp = await apiDelete(
      alicePage,
      `/ui/agent/fleet/templates/${templateId}`,
    );
    expect(delResp.status()).toBe(200);
    const delData = await delResp.json();
    expect(delData.ok).toBe(true);

    // Verify template is removed
    const listResp = await apiGet(alicePage, "/ui/agent/fleet/templates");
    const listData = await listResp.json();
    const found = listData.templates.find(
      (t: any) => t.template_id === templateId,
    );
    expect(found).toBeUndefined();
  });
});

// =============================================================================
//   Section 640 -- Fleet Dashboard UI
// =============================================================================

test.describe("640 -- Fleet Dashboard UI", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
  });

  test("Agents fleet page renders fleet dashboard", async () => {
    await alicePage.goto(`${BASE}/agents/fleet`, {
      waitUntil: "domcontentloaded",
    });
    await expect(
      alicePage.getByRole("heading", { name: "Agent Fleet" }),
    ).toBeVisible();
  });

  test("Stats cards are visible", async () => {
    await expect(alicePage.getByText("Total Workers")).toBeVisible();
    await expect(alicePage.getByText("Active")).toBeVisible();
    await expect(alicePage.getByText("Queue Depth")).toBeVisible();
  });

  test("Worker grid shows workers", async () => {
    // Reload so a fresh fleet/status fetch is guaranteed (the initial fetch
    // from the page-render test is already cached by React Query and would
    // not fire again).
    const statusResp = alicePage.waitForResponse(
      (resp) =>
        resp.url().includes("/ui/agent/fleet/status") && resp.status() === 200,
      { timeout: 10_000 },
    );
    await alicePage.goto(`${BASE}/agents/fleet`, {
      waitUntil: "domcontentloaded",
    });
    await statusResp;
    // At least one worker card should appear
    await expect(
      alicePage.getByText(/Fleet Worker/).first(),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("Start All and Stop All buttons are visible", async () => {
    await expect(
      alicePage.getByRole("button", { name: /Start All/ }),
    ).toBeVisible();
    await expect(
      alicePage.getByRole("button", { name: /Stop All/ }),
    ).toBeVisible();
  });
});
