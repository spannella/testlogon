/**
 * E2E tests for the CRM Contact SMS feature (EVT-014).
 *
 * Sections:
 *   80 — CRM Contact SMS — API
 *   81 — CrmSmsPage UI
 *
 * Auth: uses e2e_admin_session_setup.py (alice/bob/root).
 *
 * NOTE: CRM_CONTACT_SMS_ENABLED defaults OFF. When off, every endpoint
 * returns 404 and the page renders a "not enabled" state. These tests are
 * written to pass in BOTH states (gate-aware): they assert 404 when disabled
 * and the happy-path shape when enabled.
 *
 * Live backend: app/routers/crm_contact_sms.py
 *   POST /ui/crm/contacts/{contact_id}/sms  -> 201 CrmContactSmsOut
 *   GET  /ui/crm/contacts/{contact_id}/sms  -> CrmContactSmsLogListOut
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID   = "e2e_bob@test.local";
const TS       = Date.now();

interface AdminSessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean;
    sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getSessions()[identity];
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 80 — CRM Contact SMS — API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 80: CRM Contact SMS — API", () => {
  let alicePage: Page;
  // Bob is Alice's contact target (contact_id == bob's user_sub).
  const CONTACT_ID = BOB_ID;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    // Best-effort: ensure Bob is a contact of Alice (ignore if already exists).
    await apiPost(alicePage, "alice", "ui/contacts", { user_id: CONTACT_ID }).catch(() => {});
  });

  test("80.1 POST send — 201 (enabled) or 404 (disabled)", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/crm/contacts/${encodeURIComponent(CONTACT_ID)}/sms`,
      { body: `CRM SMS test ${TS}` },
    );
    expect([201, 404, 429]).toContain(resp.status());
    if (resp.status() === 201) {
      const data = await resp.json() as {
        sms_id: string; contact_id: string; contact_phone: string; status: string;
        message_id: string; sent_at_ts: number;
      };
      expect(typeof data.sms_id).toBe("string");
      expect(typeof data.status).toBe("string");
      expect(typeof data.sent_at_ts).toBe("number");
    }
  });

  test("80.2 POST empty body — 422 (enabled) or 404 (disabled)", async () => {
    const resp = await apiPost(
      alicePage,
      "alice",
      `ui/crm/contacts/${encodeURIComponent(CONTACT_ID)}/sms`,
      { body: "" },
    );
    expect([422, 404]).toContain(resp.status());
  });

  test("80.3 GET history — array shape (enabled) or 404 (disabled)", async () => {
    const resp = await apiGet(
      alicePage,
      `ui/crm/contacts/${encodeURIComponent(CONTACT_ID)}/sms`,
      { limit: "20" },
    );
    expect([200, 404]).toContain(resp.status());
    if (resp.status() === 200) {
      const data = await resp.json() as { items: unknown[]; cursor: string | null };
      expect(Array.isArray(data.items)).toBe(true);
    }
  });

  test("80.4 Unauthenticated POST — 401/403", async ({ request }) => {
    const resp = await request.post(
      `${API}/ui/crm/contacts/${encodeURIComponent(CONTACT_ID)}/sms`,
      { data: { body: "no auth" } },
    );
    expect([401, 403, 404]).toContain(resp.status());
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 81 — CrmSmsPage UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 81: CrmSmsPage UI", () => {
  test("81.1 Page renders (compose card or not-enabled state)", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    await page.goto(`${BASE}/crm/sms`, { waitUntil: "domcontentloaded" });
    // Either the compose form or the disabled card is visible.
    const heading = page.getByRole("heading", { name: "SMS Compose" });
    await expect(heading).toBeVisible();
    const composeOrDisabled = page
      .getByText("Compose", { exact: true })
      .or(page.getByText("SMS is not enabled"));
    await expect(composeOrDisabled.first()).toBeVisible();
  });

  test("81.2 Mocked enabled — send shows success toast", async ({ browser }) => {
    const page = await browser.newPage();
    await injectAuth(page, "alice");
    // Mock the log GET (so feature reads as enabled) + the send POST.
    await page.route(/\/ui\/crm\/contacts\/.*\/sms/, async (route) => {
      const req = route.request();
      if (req.method() === "POST") {
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify({
            sms_id: "sms_mock", contact_id: BOB_ID, contact_phone: "+*******4567",
            status: "dev_logged", message_id: "dev-1", sent_at_ts: Math.floor(Date.now() / 1000),
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ items: [], cursor: null }),
      });
    });
    // Mock contacts so the select has an option.
    await page.route(/\/ui\/contacts$/, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          contacts: [{
            owner_id: ALICE_ID, contact_id: BOB_ID, display_name: "Bob",
            is_favorite: false, is_blocked: false, added_at: "0",
          }],
        }),
      });
    });

    await page.goto(`${BASE}/crm/sms`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("Compose", { exact: true })).toBeVisible();

    // Select contact
    await page.getByRole("combobox").click();
    await page.getByRole("option", { name: "Bob" }).click();
    // Type message
    await page.getByLabel("Message").fill(`hello ${TS}`);
    await page.getByRole("button", { name: /Send SMS/ }).click();
    await expect(page.getByText(/dev_logged/)).toBeVisible({ timeout: 5000 });
  });
});
