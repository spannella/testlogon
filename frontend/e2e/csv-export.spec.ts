/**
 * E2E tests for PLATFORM-009: CSV Export
 *
 * Tests the server-side CSV export endpoint:
 *   GET /ui/export/csv?source={billing_ledger|contacts|questionnaire_responses}
 *
 * Sections:
 *   73 — CSV Export API (billing_ledger, contacts, error cases)
 *   74 — CSV Export UI (buttons visible on billing, contacts pages)
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// GAP-0327: GET /ui/export/csv is rate-limited to 5 exports / 60s / user. This
// section issues many exports as one user within a single window, so requests
// past the budget return 429. This helper retries once after waiting out the
// 60s window so each test asserts the export's real behavior, not the limiter.
// (The rate-limit check runs before validation, so 422 cases need it too.)
async function exportCsv(
  page: Page,
  params: Record<string, string>,
) {
  let resp = await page.request.get(`${API}/ui/export/csv`, { params });
  if (resp.status() === 429) {
    await sleep(61_000);
    resp = await page.request.get(`${API}/ui/export/csv`, { params });
  }
  return resp;
}

// ─── Seed helpers (write JSON to temp file to avoid shell escaping issues) ───

function ddbPutItem(tableName: string, item: Record<string, unknown>) {
  const tmpFile = join(tmpdir(), `csv_export_seed_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.json`);
  writeFileSync(tmpFile, JSON.stringify(item));
  try {
    execSync(
      `${REPO_ROOT}/.venv/bin/python3 -c "
import boto3, json, sys
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
table = ddb.Table('${tableName}')
with open('${tmpFile}') as f:
    table.put_item(Item=json.load(f))
"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );
  } finally {
    try { unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}

function seedBillingEntry(userSub: string, opts: { entry_type: string; amount_cents: number; reason: string; created_at: number }) {
  const uuid = Math.random().toString(36).slice(2, 14);
  ddbPutItem("billing", {
    pk: `USER#${userSub}`,
    sk: `LEDGER#${opts.created_at}#${uuid}`,
    entry_type: opts.entry_type,
    amount_cents: opts.amount_cents,
    currency: "USD",
    state: "settled",
    reason: opts.reason,
    created_at: opts.created_at,
  });
}

function seedContact(userSub: string, contactId: string, displayName: string) {
  ddbPutItem("Contacts", {
    owner_id: userSub,
    contact_id: contactId,
    display_name: displayName,
    is_favorite: false,
    is_blocked: false,
    added_at: new Date().toISOString(),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Section 73: CSV Export API
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("73 — CSV Export API", () => {
  const TS = Date.now();
  // GAP-0327: exports beyond the 5/60s budget wait out the window once.
  test.describe.configure({ timeout: 90_000 });

  test.beforeAll(() => {
    const sessions = getSessions();
    const aliceSub = sessions[ALICE_ID].user_sub;

    // Seed billing entries with known timestamps
    seedBillingEntry(aliceSub, {
      entry_type: "tip_debit",
      amount_cents: 500,
      reason: `csv_test_tip_${TS}`,
      created_at: 1700000100,
    });
    seedBillingEntry(aliceSub, {
      entry_type: "deposit_credit",
      amount_cents: 10000,
      reason: `csv_test_deposit_${TS}`,
      created_at: 1700000200,
    });
    seedBillingEntry(aliceSub, {
      entry_type: "unlock_debit",
      amount_cents: 150,
      reason: `csv_test_unlock_${TS}`,
      created_at: 1700000300,
    });

    // Seed a contact
    seedContact(aliceSub, `csv_contact_${TS}@test.local`, `CSV Test Contact ${TS}`);
  });

  test("GET billing_ledger returns CSV with correct Content-Type", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "billing_ledger" });
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("text/csv");
  });

  test("GET billing_ledger CSV has correct header row", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "billing_ledger" });
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    // BOM + header
    expect(body).toContain("Date,Type,Amount,Currency,Status,Reason,Transaction ID");
  });

  test("GET billing_ledger CSV contains seeded data", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "billing_ledger" });
    const body = await resp.text();
    expect(body).toContain(`csv_test_tip_${TS}`);
    expect(body).toContain("5.00");
  });

  test("GET billing_ledger with date range filters entries", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    // Only include the middle entry (created_at=1700000200)
    const resp = await exportCsv(page, { source: "billing_ledger", from_date: "1700000150", to_date: "1700000250" });
    const body = await resp.text();
    expect(body).toContain(`csv_test_deposit_${TS}`);
    expect(body).not.toContain(`csv_test_tip_${TS}`);
    expect(body).not.toContain(`csv_test_unlock_${TS}`);
  });

  test("GET billing_ledger CSV has Content-Disposition header", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "billing_ledger" });
    const disposition = resp.headers()["content-disposition"];
    expect(disposition).toBeDefined();
    expect(disposition).toContain("attachment");
    expect(disposition).toContain("billing_ledger_");
    expect(disposition).toContain(".csv");
  });

  test("GET billing_ledger CSV starts with UTF-8 BOM", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "billing_ledger" });
    const body = await resp.text();
    // UTF-8 BOM is
    expect(body.charCodeAt(0)).toBe(0xFEFF);
  });

  test("GET contacts returns CSV with correct headers", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "contacts" });
    expect(resp.status()).toBe(200);
    expect(resp.headers()["content-type"]).toContain("text/csv");
    const body = await resp.text();
    expect(body).toContain("Name,Email,Phone,Company,Tags,Is Favorite,Is Blocked,Created At");
  });

  test("GET contacts CSV contains seeded contact", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "contacts" });
    const body = await resp.text();
    expect(body).toContain(`CSV Test Contact ${TS}`);
  });

  test("GET with invalid source returns 422", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "invalid_source" });
    expect(resp.status()).toBe(422);
  });

  test("GET questionnaire_responses without questionnaire_id returns 422", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "questionnaire_responses" });
    expect(resp.status()).toBe(422);
  });

  test("GET with from_date > to_date returns 422", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    const resp = await exportCsv(page, { source: "billing_ledger", from_date: "9999999999", to_date: "1000000000" });
    expect(resp.status()).toBe(422);
  });

  test("Unauthenticated request returns 401", async ({ page }) => {
    // No auth injected
    const resp = await exportCsv(page, { source: "billing_ledger" });
    expect(resp.status()).toBe(401);
  });

  test("GET billing_ledger with no matching entries returns headers-only CSV", async ({ page }) => {
    await injectAuth(page, ALICE_ID);

    // Use a date range that has no entries
    const resp = await exportCsv(page, { source: "billing_ledger", from_date: "1", to_date: "2" });
    expect(resp.status()).toBe(200);
    const body = await resp.text();
    const lines = body.trim().split("\n");
    // BOM is part of first line, so first line is BOM+header
    expect(lines.length).toBe(1);
    expect(lines[0]).toContain("Date,Type,Amount");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 74: CSV Export UI
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("74 — CSV Export UI", () => {
  test("Export CSV button visible on billing ledger tab", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/billing?tab=ledger`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("export-csv-btn")).toBeVisible();
  });

  test("Export CSV button visible on contacts page", async ({ page }) => {
    await injectAuth(page, ALICE_ID);
    await page.goto(`${BASE}/contacts`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("export-csv-btn")).toBeVisible();
  });
});
