/**
 * E2E tests for Agent Worker Provisioning (AGENT-002).
 *
 * Sections:
 *   627 — Compute & Tool Options API (4 tests)
 *   628 — Worker CRUD API           (5 tests)
 *   629 — Worker Lifecycle API      (5 tests)
 *   630 — Worker Creation UI        (4 tests)
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
import { usingCpp, cppCreateLlmKey, cppCleanupWorkers } from "./helpers/cpp-seed";
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

const DDB_PRELUDE = `
import boto3, os
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

function ddbExec(code: string): string {
  return execSync(
    `python3 -c "${DDB_PRELUDE}\n${code}"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  ).toString().trim();
}

function createLlmKey(userId: string, provider: string, label: string): string {
  if (usingCpp()) return cppCreateLlmKey(userId, provider, label);
  // Create an LLM key directly in DDB and return the key_id
  const code = `
import uuid, time, json
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
  return execSync(
    `cd ${REPO_ROOT} && .venv/bin/python3 -c "${DDB_PRELUDE}\n${code}"`,
    { timeout: 15_000 },
  ).toString().trim();
}

function cleanupWorkers(userId: string) {
  if (usingCpp()) { cppCleanupWorkers(userId); return; }
  const code = `
tbl = ddb.Table('agent_workers')
resp = tbl.query(
    KeyConditionExpression='pk = :pk AND begins_with(sk, :prefix)',
    ExpressionAttributeValues={':pk': f'USER#${userId}', ':prefix': 'WORKER#'}
)
for item in resp.get('Items', []):
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print(len(resp.get('Items', [])))
`;
  ddbExec(code);
}

// ─── Test state shared across sections ────────────────────────────────────────

let alicePage: Page;
let anthropicKeyId: string;
let openaiKeyId: string;
let firstWorkerId: string;
let secondWorkerId: string;

// =============================================================================
//   Section 627 — Compute & Tool Options API
// =============================================================================

test.describe("627 — Compute & Tool Options API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);

    // Get Alice's user_sub
    const session = getSessions()[ALICE_ID];
    const userSub = session.user_sub;

    // Clean up any existing workers
    cleanupWorkers(userSub);

    // Create LLM keys for testing
    anthropicKeyId = createLlmKey(userSub, "anthropic", `E2E Anthropic Key ${TS}`);
    openaiKeyId = createLlmKey(userSub, "openai", `E2E OpenAI Key ${TS}`);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("List available AI tools", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/workers/tools");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.tools.length).toBeGreaterThanOrEqual(2);

    const claudeCode = data.tools.find((t: any) => t.tool === "claude_code");
    expect(claudeCode).toBeTruthy();
    expect(claudeCode.display_name).toBe("Claude Code");
    expect(claudeCode.install_time_seconds).toBeGreaterThan(0);

    const codex = data.tools.find((t: any) => t.tool === "codex");
    expect(codex).toBeTruthy();
    expect(codex.display_name).toBe("OpenAI Codex");
    expect(codex.install_time_seconds).toBeGreaterThan(0);
  });

  test("List compute options", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/workers/compute-options");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.options.length).toBeGreaterThanOrEqual(3);

    const ec2Options = data.options.filter((o: any) => o.compute_type === "ec2");
    const k8sOptions = data.options.filter((o: any) => o.compute_type === "k8s");
    expect(ec2Options.length).toBeGreaterThanOrEqual(2);
    expect(k8sOptions.length).toBeGreaterThanOrEqual(1);

    for (const o of data.options) {
      expect(o.vcpu).toBeGreaterThan(0);
      expect(o.memory_gb).toBeGreaterThan(0);
      expect(o.cost_cents_per_min).toBeGreaterThan(0);
    }
  });

  test("Compute options include startup time", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/workers/compute-options");
    const data = await resp.json();

    const k8sOptions = data.options.filter((o: any) => o.compute_type === "k8s");
    const ec2Options = data.options.filter((o: any) => o.compute_type === "ec2");

    for (const o of k8sOptions) {
      expect(o.startup_seconds).toBeLessThan(10);
    }
    for (const o of ec2Options) {
      expect(o.startup_seconds).toBeGreaterThan(20);
    }
  });

  test("Tools include required_provider", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/workers/tools");
    const data = await resp.json();

    const claudeCode = data.tools.find((t: any) => t.tool === "claude_code");
    expect(claudeCode.required_provider).toBe("anthropic");

    const codex = data.tools.find((t: any) => t.tool === "codex");
    expect(codex.required_provider).toBe("openai");

    const custom = data.tools.find((t: any) => t.tool === "custom");
    expect(custom.required_provider).toBe("");
  });
});

// =============================================================================
//   Section 628 — Worker CRUD API
// =============================================================================

test.describe("628 — Worker CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);

    const session = getSessions()[ALICE_ID];
    const userSub = session.user_sub;
    cleanupWorkers(userSub);

    anthropicKeyId = createLlmKey(userSub, "anthropic", `E2E Anthropic Key CRUD ${TS}`);
    openaiKeyId = createLlmKey(userSub, "openai", `E2E OpenAI Key CRUD ${TS}`);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("Alice creates a Claude Code worker on EC2", async () => {
    const resp = await apiPost(alicePage, "/ui/agent/workers", {
      label: `Coder Agent ${TS}`,
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: anthropicKeyId,
      repo_url: "https://github.com/acme/webapp.git",
    });
    expect(resp.status()).toBe(201);

    const data = await resp.json();
    expect(data.worker_id).toBeTruthy();
    expect(["provisioning", "installing", "ready"]).toContain(data.worker_status);
    expect(data.tool).toBe("claude_code");
    expect(data.compute_type).toBe("ec2");
    expect(data.llm_provider).toBe("anthropic");
    firstWorkerId = data.worker_id;
  });

  test("Worker provisioning completes to ready", async () => {
    // In dev mode, provisioning is synchronous, so it should already be ready
    const resp = await apiGet(alicePage, `/ui/agent/workers/${firstWorkerId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.worker_status).toBe("ready");
    expect(data.provision_log.length).toBeGreaterThanOrEqual(3);
    expect(data.public_ip).toBeTruthy();
    expect(data.host_id).toBeTruthy();
  });

  test("Alice lists workers", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/workers");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(1);
    const match = data.workers.find((w: any) => w.worker_id === firstWorkerId);
    expect(match).toBeTruthy();
  });

  test("Invalid LLM key_id returns 400", async () => {
    const resp = await apiPost(alicePage, "/ui/agent/workers", {
      label: `Bad Key Worker ${TS}`,
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: "nonexistent_key_id",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("not found");
  });

  test("Provider mismatch returns 400", async () => {
    // Try to create a claude_code worker with an OpenAI key
    const resp = await apiPost(alicePage, "/ui/agent/workers", {
      label: `Mismatch Worker ${TS}`,
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: openaiKeyId,
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("requires anthropic");
  });
});

// =============================================================================
//   Section 629 — Worker Lifecycle API
// =============================================================================

test.describe("629 — Worker Lifecycle API", () => {
  let lifecycleWorkerId: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);

    const session = getSessions()[ALICE_ID];
    const userSub = session.user_sub;
    cleanupWorkers(userSub);

    anthropicKeyId = createLlmKey(userSub, "anthropic", `E2E Anthropic Key Lifecycle ${TS}`);

    // Create a worker for lifecycle tests
    const resp = await apiPost(alicePage, "/ui/agent/workers", {
      label: `Lifecycle Worker ${TS}`,
      agent_type: "coder",
      tool: "claude_code",
      compute_type: "ec2",
      instance_type: "t3.medium",
      llm_key_id: anthropicKeyId,
    });
    const data = await resp.json();
    lifecycleWorkerId = data.worker_id;
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("Alice stops a running worker", async () => {
    const resp = await apiPost(
      alicePage,
      `/ui/agent/workers/${lifecycleWorkerId}/stop`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.worker_status).toBe("stopped");
    expect(data.stopped_at).toBeGreaterThan(0);
  });

  test("Alice starts a stopped worker", async () => {
    const resp = await apiPost(
      alicePage,
      `/ui/agent/workers/${lifecycleWorkerId}/start`,
      {},
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.worker_status).toBe("ready");
  });

  test("Alice terminates a worker", async () => {
    const resp = await apiDelete(
      alicePage,
      `/ui/agent/workers/${lifecycleWorkerId}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.worker_status).toBe("terminated");
    expect(data.terminated_at).toBeGreaterThan(0);
  });

  test("Cannot stop an already terminated worker", async () => {
    const resp = await apiPost(
      alicePage,
      `/ui/agent/workers/${lifecycleWorkerId}/stop`,
      {},
    );
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(data.detail).toContain("Cannot stop");
  });

  test("Provision log shows all steps", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/agent/workers/${lifecycleWorkerId}/provision-log`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data)).toBe(true);

    const steps = data.map((e: any) => e.step);
    expect(steps).toContain("compute_launch");
    expect(steps).toContain("tool_install");
    expect(steps).toContain("key_inject");
    expect(steps).toContain("verify");

    for (const entry of data) {
      expect(entry.step).toBeTruthy();
      expect(entry.status).toBeTruthy();
      expect(entry.ts).toBeGreaterThan(0);
    }
  });
});

// =============================================================================
//   Section 630 — Worker Creation UI
// =============================================================================

test.describe("630 — Worker Creation UI", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);

    const session = getSessions()[ALICE_ID];
    const userSub = session.user_sub;
    cleanupWorkers(userSub);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("Workers page renders empty state", async () => {
    await alicePage.goto(`${BASE}/agents/workers`, {
      waitUntil: "domcontentloaded",
    });
    await expect(alicePage.getByText("No workers yet")).toBeVisible();
    await expect(
      alicePage.getByText("Create your first agent worker to get started."),
    ).toBeVisible();
  });

  test("Create Worker wizard shows agent type selector", async () => {
    await alicePage.goto(`${BASE}/agents/workers`, {
      waitUntil: "domcontentloaded",
    });
    // Click the "Create Worker" button (either in header or empty state)
    const createBtn = alicePage
      .getByRole("button", { name: /Create Worker/i })
      .first();
    await createBtn.click();

    // Verify wizard cards are visible
    await expect(alicePage.getByText("Coder")).toBeVisible();
    await expect(alicePage.getByText("QA")).toBeVisible();
    await expect(alicePage.getByText("Reviewer")).toBeVisible();
    await expect(alicePage.getByText("DevOps")).toBeVisible();
  });

  test("Wizard progresses through steps", async () => {
    // Should be on step 1 from previous test. Select Coder and click Next.
    await alicePage.getByText("Writes and refactors code").click();
    await alicePage.getByRole("button", { name: "Next" }).click();

    // Step 2: Tool selector
    await expect(alicePage.getByText("Claude Code")).toBeVisible();
    await expect(alicePage.getByText("OpenAI Codex")).toBeVisible();
    await alicePage.getByText("Claude Code").click();
    await alicePage.getByRole("button", { name: "Next" }).click();

    // Step 3: Compute selector
    await expect(alicePage.getByText("t3.medium")).toBeVisible();
    await alicePage.getByText("t3.medium").click();
    await alicePage.getByRole("button", { name: "Next" }).click();

    // Step 4: LLM Key
    await expect(alicePage.getByText("LLM API Key ID")).toBeVisible();
  });

  test("Workers page shows heading", async () => {
    // Close dialog and verify heading
    await alicePage.keyboard.press("Escape");
    await expect(
      alicePage.getByRole("heading", { name: "Agent Workers" }),
    ).toBeVisible();
  });
});
