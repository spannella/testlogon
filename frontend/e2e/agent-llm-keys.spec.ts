/**
 * E2E tests for LLM Provider Key Management (AGENT-001):
 *
 * Section 623: LLM Provider API (3 tests)
 * Section 624: Key CRUD API (5 tests)
 * Section 625: Key Test, Rotate & Usage API (5 tests)
 * Section 626: LLM Keys UI (5 tests)
 *
 * Auth: uses `e2e_admin_session_setup.py` sessions (Alice, Root).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ─────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const ROOT_SUB = "root.admin@testdev.local";

// ─── Session bootstrap ─────────────────────────────────────────────────────────

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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Page factory ──────────────────────────────────────────────────────────────

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ───────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}/${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

// ─── Shared state ──────────────────────────────────────────────────────────────

const TS = Date.now();
let alicePage: Page;
let rootPage: Page;
let createdKeyId = "";
let customKeyId = "";

test.describe.serial("agent-llm-keys", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await rootPage?.close();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 623: LLM Provider API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("623 — LLM Provider API", () => {
    test("List supported providers returns registry", async () => {
      const resp = await apiGet(alicePage, "ui/agent/llm-providers");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.providers.length).toBeGreaterThanOrEqual(5);
      const names = data.providers.map((p: any) => p.provider);
      expect(names).toContain("openai");
      expect(names).toContain("anthropic");
      expect(names).toContain("deepseek");
      expect(names).toContain("gemini");
      expect(names).toContain("custom");
      for (const p of data.providers) {
        expect(p.display_name).toBeTruthy();
      }
    });

    test("Provider info includes correct base URLs", async () => {
      const resp = await apiGet(alicePage, "ui/agent/llm-providers");
      const data = await resp.json();
      const openai = data.providers.find((p: any) => p.provider === "openai");
      expect(openai.base_url).toContain("api.openai.com");
      const anthropic = data.providers.find((p: any) => p.provider === "anthropic");
      expect(anthropic.base_url).toContain("api.anthropic.com");
    });

    test("Custom provider has empty base_url", async () => {
      const resp = await apiGet(alicePage, "ui/agent/llm-providers");
      const data = await resp.json();
      const custom = data.providers.find((p: any) => p.provider === "custom");
      expect(custom.base_url).toBe("");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 624: Key CRUD API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("624 — Key CRUD API", () => {
    test("Alice adds an Anthropic API key", async () => {
      const resp = await apiPost(alicePage, "alice", "ui/agent/llm-keys", {
        provider: "anthropic",
        label: `Test Claude Key ${TS}`,
        api_key: "sk-ant-test-1234567890abcdef",
        model_preference: "claude-sonnet-4-20250514",
        monthly_budget_cents: 50000,
      });
      expect(resp.status()).toBe(201);
      const data = await resp.json();
      expect(data.key_id).toBeTruthy();
      expect(data.provider).toBe("anthropic");
      expect(data.key_suffix).toBe("cdef");
      expect(data.status).toBe("active");
      // encrypted_api_key should NOT be in response
      expect(data.encrypted_api_key).toBeUndefined();
      createdKeyId = data.key_id;
    });

    test("Alice adds a custom OpenAI-compatible key", async () => {
      const resp = await apiPost(alicePage, "alice", "ui/agent/llm-keys", {
        provider: "custom",
        label: `Custom vLLM Key ${TS}`,
        api_key: "custom-key-abc12345",
        base_url: "https://my-vllm.example.com/v1",
      });
      expect(resp.status()).toBe(201);
      const data = await resp.json();
      expect(data.base_url).toBe("https://my-vllm.example.com/v1");
      expect(data.provider).toBe("custom");
      customKeyId = data.key_id;
    });

    test("Alice lists her LLM keys", async () => {
      const resp = await apiGet(alicePage, "ui/agent/llm-keys");
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.count).toBeGreaterThanOrEqual(2);
      for (const k of data.keys) {
        expect(k.key_id).toBeTruthy();
        expect(k.provider).toBeTruthy();
        expect(k.label).toBeTruthy();
        expect(k.key_suffix).toBeTruthy();
      }
    });

    test("Alice deletes a custom LLM key", async () => {
      const resp = await apiDelete(alicePage, "alice", `ui/agent/llm-keys/${customKeyId}`);
      expect(resp.status()).toBe(200);
      // Confirm it's gone
      const getResp = await apiGet(alicePage, `ui/agent/llm-keys/${customKeyId}`);
      expect(getResp.status()).toBe(404);
    });

    test("Custom provider without base_url returns 400", async () => {
      const resp = await apiPost(alicePage, "alice", "ui/agent/llm-keys", {
        provider: "custom",
        label: "Bad Custom Key",
        api_key: "some-key-12345678",
      });
      expect(resp.status()).toBe(400);
      const data = await resp.json();
      expect(JSON.stringify(data.detail).toLowerCase()).toContain("base_url");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 625: Key Test, Rotate & Usage API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("625 — Key Test, Rotate & Usage API", () => {
    test("Alice tests an API key (dev mode mock)", async () => {
      const resp = await apiPost(alicePage, "alice", `ui/agent/llm-keys/${createdKeyId}/test`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.models.length).toBeGreaterThan(0);
      expect(data.latency_ms).toBeGreaterThanOrEqual(0);
    });

    test("Alice rotates an API key", async () => {
      const resp = await apiPost(alicePage, "alice", `ui/agent/llm-keys/${createdKeyId}/rotate`, {
        new_api_key: "sk-ant-new-key-9876543210",
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.key_suffix).toBe("3210");
      expect(data.key_id).toBe(createdKeyId);
    });

    test("Alice checks key usage", async () => {
      const resp = await apiGet(alicePage, `ui/agent/llm-keys/${createdKeyId}/usage`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.key_id).toBe(createdKeyId);
      expect(typeof data.local_usage_cents).toBe("number");
      expect(typeof data.local_total_requests).toBe("number");
      expect(typeof data.local_total_tokens).toBe("number");
    });

    test("Alice assigns a key to a worker", async () => {
      const resp = await apiPost(alicePage, "alice", `ui/agent/llm-keys/${createdKeyId}/assign`, {
        worker_id: "worker_test_001",
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.assigned_worker_ids).toContain("worker_test_001");
    });

    test("Alice unassigns a key from a worker", async () => {
      const resp = await apiDelete(
        alicePage,
        "alice",
        `ui/agent/llm-keys/${createdKeyId}/assign/worker_test_001`,
      );
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.assigned_worker_ids).not.toContain("worker_test_001");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 626: LLM Keys UI
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("626 — LLM Keys UI", () => {
    test("LlmKeysPage renders key table", async () => {
      await alicePage.goto("/agents/llm-keys");
      await expect(alicePage.getByRole("heading", { name: "LLM API Keys" })).toBeVisible();
      // Should show at least the existing key from previous tests
      await expect(alicePage.getByText("Label").first()).toBeVisible();
      await expect(alicePage.getByText("Provider").first()).toBeVisible();
      await expect(alicePage.getByText("Status").first()).toBeVisible();
    });

    test("Add Key dialog shows provider selector", async () => {
      await alicePage.goto("/agents/llm-keys");
      await alicePage.getByRole("button", { name: /Add Key/i }).click();
      // Verify provider cards
      await expect(alicePage.getByText("OpenAI")).toBeVisible();
      await expect(alicePage.getByText("Anthropic (Claude)")).toBeVisible();
      await expect(alicePage.getByText("DeepSeek")).toBeVisible();
      await expect(alicePage.getByText("Google Gemini")).toBeVisible();
      await expect(alicePage.getByText("Custom (OpenAI-compatible)")).toBeVisible();
    });

    test("Add key through dialog creates key", async () => {
      await alicePage.goto("/agents/llm-keys");
      await alicePage.getByRole("button", { name: /Add Key/i }).click();
      // Select Anthropic
      await alicePage.getByTestId("provider-card-anthropic").click();
      // Fill form
      await alicePage.getByLabel("Label").fill(`E2E UI Key ${TS}`);
      await alicePage.getByLabel("API Key").fill("sk-ant-e2e-ui-test-key-abcd1234");
      // Submit
      await alicePage.getByRole("button", { name: /Add Key/i }).click();
      // Verify new row appears
      await expect(alicePage.getByText(`E2E UI Key ${TS}`)).toBeVisible({ timeout: 5000 });
    });

    test("Test button shows result", async () => {
      await alicePage.goto("/agents/llm-keys");
      // Wait for table to load
      await expect(alicePage.getByText(`Test Claude Key ${TS}`)).toBeVisible({ timeout: 5000 });
      // Find the row with the test key and click the actions menu
      const row = alicePage.locator("tr").filter({ hasText: `Test Claude Key ${TS}` });
      await row.getByRole("button").last().click();
      // Click Test
      await alicePage.getByRole("menuitem", { name: /Test/i }).click();
      // Should see a success toast
      await expect(alicePage.getByText(/test passed/i).or(alicePage.getByText(/models/i))).toBeVisible({ timeout: 5000 });
    });

    test("Delete button with confirmation removes key", async () => {
      await alicePage.goto("/agents/llm-keys");
      await expect(alicePage.getByText(`E2E UI Key ${TS}`)).toBeVisible({ timeout: 5000 });
      const row = alicePage.locator("tr").filter({ hasText: `E2E UI Key ${TS}` });
      await row.getByRole("button").last().click();
      await alicePage.getByRole("menuitem", { name: /Delete/i }).click();
      // Confirmation dialog
      await expect(alicePage.getByText(/Are you sure/i)).toBeVisible();
      await alicePage.getByRole("button", { name: /Delete$/i }).click();
      // Row should be gone
      await expect(alicePage.getByText(`E2E UI Key ${TS}`)).not.toBeVisible({ timeout: 5000 });
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Cleanup: delete remaining test keys
  // ═══════════════════════════════════════════════════════════════════════════

  test("Cleanup: delete remaining test keys", async () => {
    if (createdKeyId) {
      await apiDelete(alicePage, "alice", `ui/agent/llm-keys/${createdKeyId}`);
    }
  });
});
