/**
 * E2E tests for Agent Memory & Context Injection (AGENT-005).
 *
 * Sections:
 *   641 — Identity & Project Context API (4 tests)
 *   642 — Memory Entries API             (5 tests)
 *   643 — Context Assembly & Export API   (4 tests)
 *   644 — Memory Page UI                 (3 tests)
 *
 * Auth: Alice session cookies (from e2e_admin_session_setup.py).
 *
 * Prerequisites:
 *   - `agent_memory` DDB table created (via local-ddb-init.py)
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

async function apiPut(page: Page, path: string, body: object) {
  return page.request.put(`${BASE}${path}`, {
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
    `cd ${REPO_ROOT} && .venv/bin/python3 -c "${DDB_PRELUDE}\n${code}"`,
    { timeout: 15_000 },
  ).toString().trim();
}

/**
 * Seed an identity + project record directly in DDB so the API can read them.
 */
function seedWorkerMemory(workerId: string): void {
  const code = `
import time, json
ts = int(time.time())
tbl = ddb.Table('agent_memory')
tbl.put_item(Item={
    'pk': f'WORKER#${workerId}',
    'sk': 'IDENTITY',
    'agent_type': 'coder',
    'identity_text': 'You are a Coder Agent. Your primary responsibilities:\\n- Read ticket requirements',
    'custom_instructions': '',
    'updated_at': ts,
    'created_at': ts,
    'category': 'identity',
})
tbl.put_item(Item={
    'pk': f'WORKER#${workerId}',
    'sk': 'PROJECT',
    'repo_url': '',
    'branch_convention': 'agent/{worker_id}/{ticket_id}',
    'coding_standards': '',
    'pr_template': '',
    'test_framework': '',
    'ci_commands': '',
    'file_structure_notes': '',
    'updated_at': ts,
    'created_at': ts,
    'category': 'project',
})
print('ok')
`;
  ddbExec(code);
}

function cleanupWorkerMemory(workerId: string): void {
  const code = `
tbl = ddb.Table('agent_memory')
resp = tbl.query(
    KeyConditionExpression='pk = :pk',
    ExpressionAttributeValues={':pk': f'WORKER#${workerId}'}
)
for item in resp.get('Items', []):
    tbl.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print(len(resp.get('Items', [])))
`;
  ddbExec(code);
}

// ─── Shared test state ────────────────────────────────────────────────────────

const WORKER_ID = `e2e_mem_${TS}`;
const WORKER_ID_2 = `e2e_mem2_${TS}`;
let alicePage: Page;
let firstMemoryId: string;

// =============================================================================
//   Section 641 — Identity & Project Context API
// =============================================================================

test.describe("641 — Identity & Project Context API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);

    // Clean up any existing data and seed fresh identity/project
    cleanupWorkerMemory(WORKER_ID);
    seedWorkerMemory(WORKER_ID);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("New worker has identity from template", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/identity`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.agent_type).toBe("coder");
    expect(data.identity_text).toContain("Coder Agent");
    expect(data.identity_text.length).toBeGreaterThan(0);
  });

  test("Update identity text", async () => {
    const newText = `You are a specialized Python agent for E2E ${TS}`;
    const resp = await apiPut(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/identity`,
      { identity_text: newText },
    );
    expect(resp.status()).toBe(200);

    const get = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/identity`,
    );
    const data = await get.json();
    expect(data.identity_text).toBe(newText);
  });

  test("Update custom instructions", async () => {
    const resp = await apiPut(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/identity`,
      { custom_instructions: "Always use type hints" },
    );
    expect(resp.status()).toBe(200);

    const get = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/identity`,
    );
    const data = await get.json();
    expect(data.custom_instructions).toContain("type hints");
  });

  test("Update project context", async () => {
    const resp = await apiPut(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/project`,
      {
        repo_url: "https://github.com/test/repo",
        branch_convention: "feat/{ticket_id}",
        test_framework: "pytest",
      },
    );
    expect(resp.status()).toBe(200);

    const get = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/project`,
    );
    const data = await get.json();
    expect(data.repo_url).toBe("https://github.com/test/repo");
    expect(data.branch_convention).toBe("feat/{ticket_id}");
    expect(data.test_framework).toBe("pytest");
  });
});

// =============================================================================
//   Section 642 — Memory Entry CRUD API
// =============================================================================

test.describe("642 — Memory Entry CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("Add a memory entry", async () => {
    const resp = await apiPost(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/entries`,
      {
        category: "learning",
        title: `DynamoDB pattern ${TS}`,
        content: "Always use begins_with for SK queries when scanning a partition",
        importance: 4,
      },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.memory_id).toBeTruthy();
    expect(data.token_count).toBeGreaterThan(0);
    expect(data.category).toBe("learning");
    firstMemoryId = data.memory_id;
  });

  test("Add multiple memories with categories", async () => {
    const categories = ["decision", "pattern", "error"];
    for (const cat of categories) {
      const resp = await apiPost(
        alicePage,
        `/ui/agent/memory/${WORKER_ID}/entries`,
        {
          category: cat,
          title: `${cat} entry ${TS}`,
          content: `Test content for ${cat} category`,
          importance: 3,
        },
      );
      expect(resp.status()).toBe(201);
      const data = await resp.json();
      expect(data.category).toBe(cat);
    }
  });

  test("List memories", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/entries`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThanOrEqual(4);
    expect(data.entries.length).toBeGreaterThanOrEqual(4);
    for (const entry of data.entries) {
      expect(entry.memory_id).toBeTruthy();
      expect(entry.category).toBeTruthy();
      expect(entry.title).toBeTruthy();
      expect(entry.content).toBeTruthy();
    }
  });

  test("Update memory importance", async () => {
    expect(firstMemoryId).toBeTruthy();
    const resp = await apiPut(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/entries/${firstMemoryId}`,
      { importance: 5 },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Number(data.importance)).toBe(5);
  });

  test("Delete memory entry", async () => {
    // Add a throw-away entry to delete
    const addResp = await apiPost(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/entries`,
      {
        category: "custom",
        title: `Deletable ${TS}`,
        content: "This entry will be deleted",
        importance: 1,
      },
    );
    expect(addResp.status()).toBe(201);
    const added = await addResp.json();

    const delResp = await apiDelete(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/entries/${added.memory_id}`,
    );
    expect(delResp.status()).toBe(200);

    // Verify the entry was deleted: should return 404
    const getResp = await apiPut(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/entries/${added.memory_id}`,
      { importance: 1 },
    );
    expect(getResp.status()).toBe(404);
  });
});

// =============================================================================
//   Section 643 — Context Assembly & Export API
// =============================================================================

test.describe("643 — Context Assembly & Export API", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
  });

  test.afterAll(async () => {
    await alicePage?.context().close();
  });

  test("Full context includes identity, project, and memories", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/full-context`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.context_text).toContain("AGENT IDENTITY");
    expect(data.context_text).toContain("PROJECT CONTEXT");
    expect(data.context_text).toContain("ACCUMULATED MEMORY");
    expect(data.total_tokens).toBeGreaterThan(0);
  });

  test("Export memory returns complete data", async () => {
    const resp = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/export`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.identity).toBeTruthy();
    expect(data.project_context).toBeTruthy();
    expect(data.memories.length).toBeGreaterThanOrEqual(3);
    expect(data.worker_id).toBe(WORKER_ID);
  });

  test("Import memory to new worker", async () => {
    // First export from existing worker
    const exportResp = await apiGet(
      alicePage,
      `/ui/agent/memory/${WORKER_ID}/export`,
    );
    const exportData = await exportResp.json();

    // Seed a minimal identity for the second worker so import can update it
    cleanupWorkerMemory(WORKER_ID_2);
    seedWorkerMemory(WORKER_ID_2);

    // Import to a new worker
    const importResp = await apiPost(
      alicePage,
      `/ui/agent/memory/${WORKER_ID_2}/import`,
      {
        identity: exportData.identity,
        project_context: exportData.project_context,
        memories: exportData.memories,
      },
    );
    expect(importResp.status()).toBe(200);
    const result = await importResp.json();
    expect(result.identity).toBe(true);
    expect(result.project).toBe(true);
    expect(result.memories).toBeGreaterThanOrEqual(3);

    // Clean up worker 2
    cleanupWorkerMemory(WORKER_ID_2);
  });

  test("List identity templates", async () => {
    const resp = await apiGet(alicePage, "/ui/agent/memory/templates");
    expect(resp.status()).toBe(200);
    const data = (await resp.json()) as Array<{
      agent_type: string;
      identity_text: string;
    }>;
    expect(data.length).toBeGreaterThanOrEqual(4);

    const types = data.map((t) => t.agent_type);
    expect(types).toContain("coder");
    expect(types).toContain("qa");
    expect(types).toContain("reviewer");
    expect(types).toContain("devops");

    for (const t of data) {
      expect(t.identity_text.length).toBeGreaterThan(0);
    }
  });
});

// =============================================================================
//   Section 644 — Memory Page UI
// =============================================================================

test.describe("644 — Memory Page UI", () => {
  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    alicePage = await ctx.newPage();
    await injectAuth(alicePage);
  });

  test.afterAll(async () => {
    cleanupWorkerMemory(WORKER_ID);
    await alicePage?.context().close();
  });

  test("Memory page loads with identity section", async () => {
    await alicePage.goto(`${BASE}/agents/memory/${WORKER_ID}`);
    await expect(
      alicePage.getByRole("heading", { name: "Agent Memory" }),
    ).toBeVisible();
    // Identity textarea should be visible
    await expect(
      alicePage.locator("textarea").first(),
    ).toBeVisible();
  });

  test("Memory entries list is visible", async () => {
    await alicePage.goto(`${BASE}/agents/memory/${WORKER_ID}`);
    // Wait for the entries card heading
    await expect(
      alicePage.getByRole("heading", { name: "Memory Entries" }),
    ).toBeVisible();
    // Should see category badges from the entries we created
    await expect(
      alicePage.getByText("learning").first(),
    ).toBeVisible();
  });

  test("Context preview shows assembled text", async () => {
    await alicePage.goto(`${BASE}/agents/memory/${WORKER_ID}`);
    // Click the Preview Context button
    await alicePage.getByRole("button", { name: /Preview Context/i }).click();
    // Wait for the preview card with context text
    await expect(
      alicePage.getByRole("heading", { name: "Context Preview" }),
    ).toBeVisible();
    // The assembled text should show AGENT IDENTITY section
    await expect(
      alicePage.locator("pre").filter({ hasText: "AGENT IDENTITY" }),
    ).toBeVisible();
  });
});
