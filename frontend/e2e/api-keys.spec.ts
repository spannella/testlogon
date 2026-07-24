/**
 * E2E tests for API Key management (/security → "API Keys" tab).
 *
 * Auth strategy:
 *   Alice (e2e_alice@test.local) has no MFA factors configured, so
 *   require_fresh_mfa() returns immediately for all /ui/api_keys endpoints.
 *   Her session is injected via cookies + localStorage, matching the pattern
 *   used in feed.spec.ts.
 *
 * Dialog roles:
 *   Create Key / IP Rules  → Radix Dialog  → role="dialog"
 *   Revoke confirmation     → Radix AlertDialog (ConfirmDialog) → role="alertdialog"
 *
 * API endpoints tested:
 *   GET  /ui/api_keys
 *   POST /ui/api_keys
 *   POST /ui/api_keys/revoke
 *   POST /ui/api_keys/ip_rules
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

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

// ─── Auth & navigation helpers ────────────────────────────────────────────────

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

/**
 * Navigate to /security and activate the "API Keys" tab.
 * Also sets up auth via injectAuth.
 */
async function gotoApiKeys(page: Page, userId = ALICE_ID) {
  await injectAuth(page, userId);
  await page.goto(`${BASE}/security`, { waitUntil: "load" });
  await page.waitForTimeout(600);
  await page.getByRole("tab", { name: "API Keys" }).click();
  await page.waitForTimeout(400);
}

// ─── Authenticated API helpers ────────────────────────────────────────────────

/** POST to the backend with session cookies + CSRF header. */
async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

/** GET from the backend (cookies come from the page context). */
async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/** Revoke every API key owned by Alice — used to start tests from a clean slate. */
async function revokeAllKeys(page: Page) {
  const resp = await apiGet(page, "/ui/api_keys");
  if (!resp.ok()) return;
  const { keys = [] } = (await resp.json()) as { keys: Array<{ key_id: string }> };
  for (const k of keys) {
    await apiPost(page, "/ui/api_keys/revoke", { key_id: k.key_id });
  }
}

// ─── 1. Page structure ────────────────────────────────────────────────────────

test.describe("1. API Keys — page structure", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoApiKeys(page);
  });

  test.afterAll(async () => page?.close());

  test("'API Keys' tab is present in the Security page tab list", async () => {
    await expect(page.getByRole("tab", { name: "API Keys" })).toBeVisible();
  });

  test("card shows the 'Manage API keys for programmatic access' description", async () => {
    await expect(page.getByText("Manage API keys for programmatic access")).toBeVisible();
  });

  test("'Create Key' button is visible on the API Keys tab", async () => {
    await expect(page.getByRole("button", { name: "Create Key" })).toBeVisible();
  });
});

// ─── 2. Empty state ───────────────────────────────────────────────────────────

test.describe("2. API Keys — empty state", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    // Revoke all keys so the empty state is guaranteed.
    await injectAuth(page);
    await revokeAllKeys(page);
    await page.goto(`${BASE}/security`, { waitUntil: "load" });
    await page.waitForTimeout(600);
    await page.getByRole("tab", { name: "API Keys" }).click();
    await page.waitForTimeout(400);
  });

  test.afterAll(async () => page?.close());

  test("shows 'No API keys' heading when the list is empty", async () => {
    await expect(page.getByText("No API keys")).toBeVisible({ timeout: 5000 });
  });

  test("empty state description tells the user how to get started", async () => {
    await expect(
      page.getByText("Create an API key to access the platform programmatically."),
    ).toBeVisible();
  });
});

// ─── 3. Create Key dialog — form structure ────────────────────────────────────

test.describe("3. Create Key dialog — form fields", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoApiKeys(page);
    await page.getByRole("button", { name: "Create Key" }).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 4000 });
  });

  test.afterAll(async () => page?.close());

  test("dialog title is 'Create API Key'", async () => {
    await expect(page.getByRole("dialog")).toContainText("Create API Key");
  });

  test("dialog description asks for an optional label", async () => {
    await expect(page.getByRole("dialog")).toContainText(
      "Give your key an optional label for identification.",
    );
  });

  test("Label input has placeholder 'e.g. CI/CD Pipeline'", async () => {
    const labelInput = page.getByLabel("Label (optional)");
    await expect(labelInput).toBeVisible();
    await expect(labelInput).toHaveAttribute("placeholder", "e.g. CI/CD Pipeline");
  });

  test("Expiry select defaults to 'No expiry'", async () => {
    // The SelectTrigger has id="key-expiry"
    await expect(page.locator("#key-expiry")).toContainText("No expiry");
  });

  test("dialog footer has a 'Create Key' submit button", async () => {
    await expect(
      page.getByRole("dialog").getByRole("button", { name: "Create Key" }),
    ).toBeVisible();
  });
});

// ─── 4. Key creation — submission result ──────────────────────────────────────

test.describe("4. Create Key — submission and result", () => {
  let page: Page;
  const LABEL = "E2E Test Key";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await gotoApiKeys(page);
    // Open dialog, fill label, submit.
    await page.getByRole("button", { name: "Create Key" }).click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 4000 });
    await page.getByLabel("Label (optional)").fill(LABEL);
    await page.getByRole("dialog").getByRole("button", { name: "Create Key" }).click();
    // Wait for the post-creation state.
    await expect(page.getByRole("dialog")).toContainText("API Key Created", {
      timeout: 8000,
    });
  });

  test.afterAll(async () => page?.close());

  test("dialog title changes to 'API Key Created' after submission", async () => {
    await expect(page.getByRole("dialog")).toContainText("API Key Created");
  });

  test("dialog shows 'Key ID' and 'Secret Key' labels", async () => {
    await expect(page.getByRole("dialog")).toContainText("Key ID");
    await expect(page.getByRole("dialog")).toContainText("Secret Key");
  });

  test("Key ID value is a non-empty string", async () => {
    const codes = page.getByRole("dialog").locator("code");
    const keyId = await codes.first().textContent();
    expect(keyId).toBeTruthy();
    expect(keyId!.length).toBeGreaterThan(8);
  });

  test("Secret Key starts with 'ak_' prefix", async () => {
    const codes = page.getByRole("dialog").locator("code");
    const secret = await codes.nth(1).textContent();
    expect(secret).toBeTruthy();
    expect(secret!.startsWith("ak_")).toBe(true);
  });

  test("warning banner says the secret is shown only once", async () => {
    await expect(page.getByRole("dialog")).toContainText(
      "The Secret Key is shown only once. Store it securely.",
    );
  });

  test("Download and Done buttons are present in the footer", async () => {
    await expect(
      page.getByRole("dialog").getByRole("button", { name: "Download" }),
    ).toBeVisible();
    await expect(
      page.getByRole("dialog").getByRole("button", { name: "Done" }),
    ).toBeVisible();
  });

  test("Done button closes the dialog and the key appears in the list", async () => {
    await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 3000 });
    await expect(page.getByText(LABEL)).toBeVisible({ timeout: 5000 });
  });

  test("key list entry shows 'ak_' prefix and a creation date", async () => {
    // Scope to the API Keys tab panel to avoid matching sidebar nav <ul> elements.
    const panel = page.getByRole("tabpanel", { name: "API Keys" });
    const prefix = panel.locator("code").first();
    await expect(prefix).toBeVisible({ timeout: 3000 });
    const prefixText = await prefix.textContent();
    // prefix column shows e.g. "ak_a1b2c3d4…" (the trailing … is part of the rendered text)
    expect(prefixText).toMatch(/^ak_/);
    await expect(panel).toContainText("Created");
  });
});

// ─── 5. Revoke flow ───────────────────────────────────────────────────────────

test.describe("5. Revoke flow", () => {
  let page: Page;
  const LABEL = "E2E Revoke Test";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    // Set up: clean state + one key to revoke.
    await injectAuth(page);
    await revokeAllKeys(page);
    await apiPost(page, "/ui/api_keys", { label: LABEL });
    await page.goto(`${BASE}/security`, { waitUntil: "load" });
    await page.waitForTimeout(600);
    await page.getByRole("tab", { name: "API Keys" }).click();
    await page.waitForTimeout(400);
    await expect(page.getByText(LABEL)).toBeVisible({ timeout: 5000 });
  });

  test.afterAll(async () => page?.close());

  test("clicking the trash icon opens the 'Revoke API Key' confirmation dialog", async () => {
    await page.getByRole("button", { name: "Revoke key" }).first().click();
    await expect(page.getByRole("alertdialog")).toContainText("Revoke API Key", {
      timeout: 3000,
    });
  });

  test("revoke dialog describes the consequence and shows a 'Revoke Key' button", async () => {
    // Dialog is still open from the previous test.
    await expect(page.getByRole("alertdialog")).toContainText(
      "This key will immediately stop working. This action cannot be undone.",
    );
    await expect(
      page.getByRole("alertdialog").getByRole("button", { name: "Revoke Key" }),
    ).toBeVisible();
  });

  test("cancelling the dialog leaves the key in the list", async () => {
    await page.getByRole("alertdialog").getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("alertdialog")).not.toBeVisible({ timeout: 2000 });
    await expect(page.getByText(LABEL)).toBeVisible();
  });

  test("confirming revoke removes the key from the list", async () => {
    // Re-open and confirm.
    await page.getByRole("button", { name: "Revoke key" }).first().click();
    await expect(page.getByRole("alertdialog")).toBeVisible({ timeout: 3000 });
    await page.getByRole("alertdialog").getByRole("button", { name: "Revoke Key" }).click();
    // Dialog closes and the key disappears.
    await expect(page.getByRole("alertdialog")).not.toBeVisible({ timeout: 3000 });
    await expect(page.getByText(LABEL)).not.toBeVisible({ timeout: 5000 });
    // Empty state returns because there are no more keys.
    await expect(page.getByText("No API keys")).toBeVisible({ timeout: 3000 });
  });
});

// ─── 6. IP access rules ───────────────────────────────────────────────────────

test.describe("6. IP access rules", () => {
  let page: Page;
  const LABEL = "E2E IP Rules Test";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await revokeAllKeys(page);
    await apiPost(page, "/ui/api_keys", { label: LABEL });
    await page.goto(`${BASE}/security`, { waitUntil: "load" });
    await page.waitForTimeout(600);
    await page.getByRole("tab", { name: "API Keys" }).click();
    await page.waitForTimeout(400);
    await expect(page.getByText(LABEL)).toBeVisible({ timeout: 5000 });
    // Open the IP rules dialog.
    await page.getByRole("button", { name: "Manage IP rules" }).first().click();
    await expect(page.getByRole("dialog")).toContainText("IP Access Rules", {
      timeout: 3000,
    });
  });

  test.afterAll(async () => page?.close());

  test("IP Access Rules dialog has the correct title and description", async () => {
    await expect(page.getByRole("dialog")).toContainText("IP Access Rules");
    await expect(page.getByRole("dialog")).toContainText("CIDR notation");
  });

  test("dialog contains Allow CIDRs and Deny CIDRs text areas", async () => {
    await expect(page.getByLabel("Allow CIDRs")).toBeVisible();
    await expect(page.getByLabel("Deny CIDRs")).toBeVisible();
  });

  test("saving IP rules triggers success toast and closes the dialog", async () => {
    // Fill the allow CIDR input — the frontend auto-adds it on save (no need to click Add first).
    await page.getByLabel("Allow CIDRs").fill("10.0.0.0/8");
    // Wait for the GET refetch to complete after saving so the keysQuery cache is fresh.
    const refetchDone = page.waitForResponse(
      (r) => r.url().includes("/ui/api_keys") && r.request().method() === "GET",
      { timeout: 8000 },
    );
    await page.getByRole("dialog").getByRole("button", { name: "Save Rules" }).click();
    await expect(page.getByText("IP rules updated", { exact: true }).first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 3000 });
    await refetchDone;
  });

  test("saved CIDR rules are pre-populated when the dialog is reopened", async () => {
    await page.getByRole("button", { name: "Manage IP rules" }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 3000 });
    // The saved CIDR appears as a chip/tag in the list — not as the text-input value.
    await expect(page.getByRole("dialog").getByText("10.0.0.0/8")).toBeVisible({ timeout: 3000 });
  });

  test("Cancel discards unsaved edits", async () => {
    // Fill the input with a new CIDR (without clicking Add) and then cancel.
    await page.getByLabel("Allow CIDRs").fill("192.168.0.0/16");
    await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 2000 });
    // Reopen — original saved CIDR should still be shown as a chip; unsaved edit discarded.
    await page.getByRole("button", { name: "Manage IP rules" }).first().click();
    await expect(page.getByRole("dialog")).toBeVisible({ timeout: 3000 });
    await expect(page.getByRole("dialog").getByText("10.0.0.0/8")).toBeVisible({ timeout: 3000 });
    await expect(page.getByRole("dialog").getByText("192.168.0.0/16")).not.toBeVisible({ timeout: 2000 });
  });
});

// ─── 7. REST API ──────────────────────────────────────────────────────────────

test.describe("7. REST API — /ui/api_keys", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await revokeAllKeys(page);
  });

  test.afterAll(async () => page?.close());

  test("GET /ui/api_keys returns a keys array", async () => {
    const resp = await apiGet(page, "/ui/api_keys");
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data).toHaveProperty("keys");
    expect(Array.isArray(data.keys)).toBe(true);
  });

  test("POST /ui/api_keys creates a key with the expected shape", async () => {
    const resp = await apiPost(page, "/ui/api_keys", {
      label: "API shape test",
      expires_in_days: 30,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.key_id).toBe("string");
    expect(data.key_id.length).toBeGreaterThan(8);
    expect(typeof data.key_secret).toBe("string");
    expect(data.key_secret.startsWith("ak_")).toBe(true);
    expect(data.label).toBe("API shape test");
    // expires_at should be set to roughly 30 days from now.
    const thirtyDays = 30 * 24 * 3600;
    expect(data.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000) + thirtyDays - 60);
  });

  test("key created without expiry has expires_at of 0 (never expires)", async () => {
    const resp = await apiPost(page, "/ui/api_keys", { label: "no expiry test" });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(data.expires_at).toBe(0);
  });

  test("POST /ui/api_keys/revoke removes the key from the list", async () => {
    const createResp = await apiPost(page, "/ui/api_keys", { label: "to revoke" });
    const { key_id } = await createResp.json();

    const revokeResp = await apiPost(page, "/ui/api_keys/revoke", { key_id });
    expect(revokeResp.ok()).toBe(true);
    expect((await revokeResp.json()).ok).toBe(true);

    // The key must no longer appear in the list.
    const listResp = await apiGet(page, "/ui/api_keys");
    const { keys } = (await listResp.json()) as { keys: Array<{ key_id: string }> };
    expect(keys.some((k) => k.key_id === key_id)).toBe(false);
  });

  test("POST /ui/api_keys/ip_rules saves and returns normalised CIDRs", async () => {
    const createResp = await apiPost(page, "/ui/api_keys", { label: "ip rules test" });
    const { key_id } = await createResp.json();

    const rulesResp = await apiPost(page, "/ui/api_keys/ip_rules", {
      key_id,
      allow_cidrs: ["10.0.0.0/8"],
      deny_cidrs: ["172.16.0.0/12"],
    });
    expect(rulesResp.ok()).toBe(true);
    const data = await rulesResp.json();
    expect(data.ok).toBe(true);
    expect(Array.isArray(data.allow_cidrs)).toBe(true);
    expect(data.allow_cidrs).toContain("10.0.0.0/8");
    expect(Array.isArray(data.deny_cidrs)).toBe(true);
    expect(data.deny_cidrs).toContain("172.16.0.0/12");
  });
});

// ─── 8. Capability scopes (GAP-0057) ───────────────────────────────────────────

test.describe("8. Capability scopes", () => {
  let page: Page;
  const LABEL = "E2E Scopes Test";

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    await revokeAllKeys(page);
    await page.goto(`${BASE}/security`, { waitUntil: "load" });
    await page.waitForTimeout(600);
    await page.getByRole("tab", { name: "API Keys" }).click();
    await page.waitForTimeout(400);
  });

  test.afterAll(async () => page?.close());

  test("create dialog exposes a grouped scope selector with ads checkboxes", async () => {
    await page.getByRole("button", { name: "Create Key" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible({ timeout: 4000 });
    await expect(dialog.getByText("Advertising")).toBeVisible();
    await expect(dialog.getByRole("checkbox", { name: "ads:read" })).toBeVisible();
    await expect(dialog.getByRole("checkbox", { name: "ads:manage" })).toBeVisible();
  });

  test("creating a key with only ads:read shows that scope (and not others) in details", async () => {
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Label (optional)").fill(LABEL);
    await dialog.getByRole("checkbox", { name: "ads:read" }).check();
    await dialog.getByRole("button", { name: "Create Key" }).click();
    await expect(dialog).toContainText("API Key Created", { timeout: 8000 });
    await dialog.getByRole("button", { name: "Done" }).click();
    await expect(dialog).not.toBeVisible({ timeout: 3000 });

    // Open the new key's details dialog and verify the scope badge.
    const panel = page.getByRole("tabpanel", { name: "API Keys" });
    await expect(panel.getByText(LABEL)).toBeVisible({ timeout: 5000 });
    await page.getByRole("button", { name: "View key details" }).first().click();
    const details = page.getByRole("dialog");
    await expect(details).toBeVisible({ timeout: 3000 });
    // exact match: the LABEL ("E2E Scopes Test") is the dialog heading and would
    // otherwise also match a substring "Scopes" lookup (strict-mode violation).
    await expect(details.getByText("Scopes", { exact: true })).toBeVisible();
    await expect(details.getByText("ads:read")).toBeVisible();
    await expect(details.getByText("ads:manage")).not.toBeVisible();
    await details.getByRole("button", { name: "Close" }).first().click();
  });

  test("POST /ui/api_keys honours a scoped capabilities list", async () => {
    const resp = await apiPost(page, "/ui/api_keys", {
      label: "scoped api key",
      capabilities: ["ads:read"],
    });
    expect(resp.ok()).toBe(true);
    const data = await resp.json();
    expect(Array.isArray(data.capabilities)).toBe(true);
    expect(data.capabilities).toContain("ads:read");
    expect(data.capabilities).not.toContain("ads:manage");
    expect(data.capabilities).not.toContain("kyc:admin");
  });
});
