/**
 * E2E tests for Internal Dev Tools (PR #125).
 *
 * Sections:
 *   75 — Internal dev-tools API contract (backend, no auth required)
 *   76 — Dev Tools Log UI frontend (mocked API responses, session auth)
 *
 * Prerequisites:
 *   DEV_MODE=1 in .env.local (backend) — gates all /internal/dev-tools/* endpoints
 *   Backend running on port 8000, Vite dev servers on port 3000 (main) and 3001 (devtools)
 *
 * Auth:
 *   Section 75 — no auth (endpoints are unauthenticated, only gated by DEV_MODE)
 *   Section 76 — no auth needed (devtools is a standalone app on port 3001)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API      = "http://localhost:8000";
const BASE     = "http://localhost:3000";
const DEVTOOLS = "http://localhost:3001/devtools.html";  // standalone devtools UI

const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;

function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── Mock payloads (shared between UI tests) ──────────────────────────────────

const MOCK_EMAIL = {
  mailboxes: [
    { id: "mb1", id_strategy: "hash", mailbox: "qa@example.com", thread_count: 1, unread_count: 1 },
  ],
  threads: [
    {
      id: "th1", id_strategy: "hash", mailbox: "qa@example.com",
      subject: "OTP for login", message_count: 1, unread_count: 1,
      participant_emails: ["qa@example.com"], latest_message_at: "2026-01-01T12:00:00Z",
    },
  ],
  messages: [
    {
      id: "msg1", id_strategy: "hash", thread_id: "th1", mailbox: "qa@example.com",
      sent_at: "2026-01-01T12:00:00Z", event_kind: "mfa_email_code", direction: "outbound",
      from_email: "noreply@testlogon.dev", to_emails: ["qa@example.com"],
      subject: "OTP for login", body_text: "Your OTP code is 987654", status: "delivered",
      parse_warnings: [],
    },
  ],
  parse_warnings: [], next_cursor: null,
};

const MOCK_SMS = {
  conversations: [
    {
      id: "conv1", id_strategy: "hash", participant_numbers: ["+15550001234"],
      message_count: 1, latest_message_at: "2026-01-01T12:01:00Z", latest_preview: "Your code: 112233",
    },
  ],
  messages: [
    {
      id: "sms1", id_strategy: "hash", conversation_id: "conv1",
      sent_at: "2026-01-01T12:01:00Z", from_number: "+15559999999", to_number: "+15550001234",
      direction: "outbound", body_text: "Your code: 112233", status: "sent",
      provider_message_id: "p1", event_kind: "mfa_sms_code", parse_warnings: [],
    },
  ],
  parse_warnings: [], next_cursor: null,
};

const MOCK_BILLING_LEDGER = {
  entries: [
    {
      id: "bill1", id_strategy: "hash", provider: "stripe", event_type: "charge.succeeded",
      status: "completed", occurred_at: "2026-01-01T12:02:00Z", external_id: "ch_test123",
      amount: 25.0, fee: 1.0, net: 24.0, currency: "usd", source_path: "stripe.log",
      raw_payload: { id: "ch_test123", amount: 2500 }, parse_warnings: [],
    },
  ],
  parse_warnings: [], next_cursor: null,
};

const MOCK_BILLING_SUMMARY = {
  gross_inflow: 25.0, fees: 1.0, net_total_balance: 24.0,
  transaction_count: 1, provider_counts: { stripe: 1 }, status_counts: { completed: 1 },
  parse_warnings: [],
};

// ═════════════════════════════════════════════════════════════════════════════
// Section 75 — Internal dev-tools API contract
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 75: Internal dev-tools API", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    // API endpoints are unauthenticated — any page context works
    page = await browser.newPage();
  });

  test.afterAll(async () => {
    await page.close();
  });

  // ── Email endpoint ─────────────────────────────────────────────────────────

  test("75.1 GET /internal/dev-tools/email/messages → 200 with correct envelope shape", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/email/messages`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.mailboxes)).toBe(true);
    expect(Array.isArray(body.threads)).toBe(true);
    expect(Array.isArray(body.messages)).toBe(true);
    expect(Array.isArray(body.parse_warnings)).toBe(true);
    // next_cursor is null or a string
    expect(body.next_cursor === null || typeof body.next_cursor === "string").toBe(true);
  });

  test("75.2 GET /internal/dev-tools/email/messages accepts state, mailbox, q, limit filters", async () => {
    const r1 = await page.request.get(`${API}/internal/dev-tools/email/messages?state=unread&limit=5`);
    expect(r1.status()).toBe(200);
    const b1 = await r1.json();
    expect(Array.isArray(b1.messages)).toBe(true);

    const r2 = await page.request.get(`${API}/internal/dev-tools/email/messages?state=sent&q=otp&limit=10`);
    expect(r2.status()).toBe(200);
    expect(Array.isArray((await r2.json()).messages)).toBe(true);

    const r3 = await page.request.get(`${API}/internal/dev-tools/email/messages?mailbox=qa%40example.com`);
    expect(r3.status()).toBe(200);
  });

  // ── SMS endpoint ───────────────────────────────────────────────────────────

  test("75.3 GET /internal/dev-tools/sms/conversations → 200 with correct envelope shape", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/sms/conversations`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.conversations)).toBe(true);
    expect(Array.isArray(body.messages)).toBe(true);
    expect(Array.isArray(body.parse_warnings)).toBe(true);
    expect(body.next_cursor === null || typeof body.next_cursor === "string").toBe(true);
  });

  test("75.4 GET /internal/dev-tools/sms/conversations accepts participant, q, limit filters", async () => {
    const r1 = await page.request.get(`${API}/internal/dev-tools/sms/conversations?limit=5&q=code`);
    expect(r1.status()).toBe(200);
    const r2 = await page.request.get(`${API}/internal/dev-tools/sms/conversations?participant=%2B15550001234`);
    expect(r2.status()).toBe(200);
  });

  // ── Billing endpoints ──────────────────────────────────────────────────────

  test("75.5 GET /internal/dev-tools/billing/ledger → 200 with correct envelope shape", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/ledger`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.entries)).toBe(true);
    expect(Array.isArray(body.parse_warnings)).toBe(true);
    expect(body.next_cursor === null || typeof body.next_cursor === "string").toBe(true);
  });

  test("75.6 GET /internal/dev-tools/billing/ledger accepts provider, status, from, to, limit filters", async () => {
    const r1 = await page.request.get(`${API}/internal/dev-tools/billing/ledger?provider=stripe&status=completed&limit=5`);
    expect(r1.status()).toBe(200);
    const r2 = await page.request.get(`${API}/internal/dev-tools/billing/ledger?from=2026-01-01&to=2026-12-31`);
    expect(r2.status()).toBe(200);
  });

  test("75.7 GET /internal/dev-tools/billing/summary → 200 with numeric aggregates", async () => {
    const resp = await page.request.get(`${API}/internal/dev-tools/billing/summary`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.gross_inflow).toBe("number");
    expect(typeof body.fees).toBe("number");
    expect(typeof body.net_total_balance).toBe("number");
    expect(typeof body.transaction_count).toBe("number");
    expect(typeof body.provider_counts).toBe("object");
    expect(typeof body.status_counts).toBe("object");
    expect(Array.isArray(body.parse_warnings)).toBe(true);
  });

  test("75.8 GET /internal/dev-tools/billing/summary accepts provider and status filters", async () => {
    const r1 = await page.request.get(`${API}/internal/dev-tools/billing/summary?provider=stripe&status=completed`);
    expect(r1.status()).toBe(200);
    const body = await r1.json();
    expect(typeof body.gross_inflow).toBe("number");
  });

  // ── Cursor pagination ──────────────────────────────────────────────────────

  test("75.9 malformed cursor → 400 with code: invalid_cursor", async () => {
    const urls = [
      `${API}/internal/dev-tools/email/messages?cursor=NOTVALIDBASE64!!!`,
      `${API}/internal/dev-tools/sms/conversations?cursor=NOTVALIDBASE64!!!`,
      `${API}/internal/dev-tools/billing/ledger?cursor=NOTVALIDBASE64!!!`,
    ];
    for (const url of urls) {
      const resp = await page.request.get(url);
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail?.code).toBe("invalid_cursor");
    }
  });

  test("75.10 valid base64 cursor with negative offset → 400 invalid_cursor", async () => {
    // Encode {"offset": -1} as urlsafe base64
    const payload = Buffer.from(JSON.stringify({ offset: -1 })).toString("base64url");
    const resp = await page.request.get(`${API}/internal/dev-tools/email/messages?cursor=${payload}`);
    expect(resp.status()).toBe(400);
    expect((await resp.json()).detail?.code).toBe("invalid_cursor");
  });

  test("75.11 valid cursor with offset=0 → 200 (same as no cursor)", async () => {
    const payload = Buffer.from(JSON.stringify({ offset: 0 })).toString("base64url");
    const resp = await page.request.get(`${API}/internal/dev-tools/email/messages?cursor=${payload}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.messages)).toBe(true);
  });

  // ── limit=200 (max) accepted ───────────────────────────────────────────────

  test("75.12 limit=200 (maximum) is accepted without error", async () => {
    const r1 = await page.request.get(`${API}/internal/dev-tools/email/messages?limit=200`);
    expect(r1.status()).toBe(200);
    const r2 = await page.request.get(`${API}/internal/dev-tools/sms/conversations?limit=200`);
    expect(r2.status()).toBe(200);
    const r3 = await page.request.get(`${API}/internal/dev-tools/billing/ledger?limit=200`);
    expect(r3.status()).toBe(200);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 76 — Dev Tools Log UI frontend
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 76: Dev Tools Log UI frontend", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    // Mock all four devtools API endpoints with deterministic data
    await page.route("**/internal/dev-tools/email/messages**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_EMAIL) }),
    );
    await page.route("**/internal/dev-tools/sms/conversations**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_SMS) }),
    );
    await page.route("**/internal/dev-tools/billing/ledger**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_BILLING_LEDGER) }),
    );
    await page.route("**/internal/dev-tools/billing/summary**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_BILLING_SUMMARY) }),
    );
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("76.1 /dev-tools/log-ui route loads with Dev Tools Log UI heading", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "Dev Tools Log UI" })).toBeVisible();
  });

  test("76.3 Email tab: shows mailbox sidebar, thread list, and message body", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    // Email tab is active by default
    await expect(page.getByText("All Inboxes")).toBeVisible();
    await expect(page.getByText("OTP for login").first()).toBeVisible();
    await expect(page.getByText("Your OTP code is 987654")).toBeVisible();
  });

  test("76.4 Email tab: no Send or Delete buttons (read-only)", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("button", { name: /send/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /delete/i })).toHaveCount(0);
  });

  test("76.5 SMS tab: shows conversation and message content", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "SMS" }).click();
    await expect(page.getByText("+15550001234").first()).toBeVisible();
    await expect(page.getByText("Your code: 112233").first()).toBeVisible();
  });

  test("76.6 SMS tab: Message metadata section visible, no Edit buttons", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "SMS" }).click();
    await expect(page.getByText("Message metadata")).toBeVisible();
    await expect(page.getByRole("button", { name: /edit/i })).toHaveCount(0);
  });

  test("76.7 MFA (TOTP) tab: shows local-only tool notice and TOTP input area", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "MFA (TOTP)" }).click();
    await expect(page.getByText(/Local-only tool:/)).toBeVisible();
    await expect(page.getByText("Provide a valid TOTP configuration to generate live codes.")).toBeVisible();
  });

  test("76.8 Billing tab: shows summary figures and ledger entry", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Billing" }).click();
    await expect(page.getByText("Gross inflow")).toBeVisible();
    await expect(page.getByText("charge.succeeded")).toBeVisible();
  });

  test("76.9 Billing tab: View raw dialog shows raw payload, no Refund or Charge buttons", async () => {
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Billing" }).click();
    await page.getByRole("button", { name: "View raw" }).click();
    await expect(page.getByText("Raw billing payload")).toBeVisible();
    await expect(page.getByRole("button", { name: /refund/i })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /charge/i })).toHaveCount(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 77 — MFA (TOTP) code generator: interactive tool tests
// ═════════════════════════════════════════════════════════════════════════════
// The MFA tab is a fully client-side tool — no backend or API mocks required.
// All TOTP parsing and code generation runs in the browser via Web Crypto API.

test.describe("Section 77: MFA (TOTP) code generator", () => {
  let page: Page;

  // 16-char Base32 secret from RFC 4226 test vectors (well-known, deterministic algorithm)
  const SECRET = "JBSWY3DPEHPK3PXP";
  const OTPAUTH_URI = `otpauth://totp/TestLogon:devtest%40example.com?secret=${SECRET}&issuer=TestLogon`;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);
    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "MFA (TOTP)" }).click();
    await expect(page.getByText(/Local-only tool:/)).toBeVisible();
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("77.1 empty state shows local-only notice and live-code placeholder", async () => {
    await expect(page.getByText(/Local-only tool:/)).toBeVisible();
    await expect(page.getByText("Provide a valid TOTP configuration to generate live codes.")).toBeVisible();
    // The code display element only renders when mfaConfig is valid — empty state shows placeholder text only
    await expect(page.locator("div.font-mono.text-4xl")).toHaveCount(0);
  });

  test("77.2 invalid Base32 characters show a validation error", async () => {
    await page.getByLabel("Paste TOTP configuration").fill("NOT-VALID-$€£");
    await expect(page.getByText("TOTP secret must be valid Base32 characters (A-Z and 2-7).")).toBeVisible();
    // Code display element only renders when mfaConfig is valid — error state has no code div
    await expect(page.locator("div.font-mono.text-4xl")).toHaveCount(0);
  });

  test("77.3 too-short Base32 secret (< 16 chars) shows length error", async () => {
    await page.getByLabel("Paste TOTP configuration").fill("AAAAAAA"); // 7 chars
    await expect(page.getByText(/TOTP secret is too short/)).toBeVisible();
  });

  test("77.4 valid 16-char Base32 secret generates a 6-digit live code", async () => {
    await page.getByLabel("Paste TOTP configuration").fill(SECRET);
    const codeDisplay = page.locator("div.font-mono.text-4xl");
    // Code transitions from "------" to a 6-digit number
    await expect(codeDisplay).not.toHaveText("------");
    await expect(codeDisplay).toHaveText(/^\d{6}$/);
  });

  test("77.5 countdown timer and cadence are shown after valid secret", async () => {
    // Re-apply the valid secret so this test is self-contained
    await page.getByLabel("Paste TOTP configuration").fill(SECRET);
    await expect(page.locator("div.font-mono.text-4xl")).toHaveText(/^\d{6}$/);
    // "Rollover in" card is visible alongside the live code
    await expect(page.getByText("Rollover in")).toBeVisible();
    // Cadence defaults to 30 s for a raw Base32 secret — use specific locator to avoid
    // strict-mode violation when rollover card also shows "30s" at a period boundary
    const cadenceCard = page.locator(".rounded-md.border.p-3").filter({ hasText: "Cadence" });
    await expect(cadenceCard.locator("div.mt-1.text-xl")).toHaveText(/^\d+s$/);
    // The countdown value is "Xs" (1–30 s)
    const rolloverCard = page.locator(".rounded-md.border.p-3").filter({ hasText: "Rollover in" });
    await expect(rolloverCard.locator("div.mt-1.text-xl")).toHaveText(/^\d{1,2}s$/);
  });

  test("77.6 Clear / Reset button resets input and returns to empty state", async () => {
    await page.getByRole("button", { name: "Clear / Reset" }).click();
    await expect(page.getByLabel("Paste TOTP configuration")).toHaveValue("");
    // After reset mfaConfig becomes null — code display div is unmounted
    await expect(page.locator("div.font-mono.text-4xl")).toHaveCount(0);
    await expect(page.getByText("Provide a valid TOTP configuration to generate live codes.")).toBeVisible();
  });

  test("77.7 valid otpauth:// URI generates a code and shows issuer metadata", async () => {
    await page.getByLabel("Paste TOTP configuration").fill(OTPAUTH_URI);
    await expect(page.locator("div.font-mono.text-4xl")).not.toHaveText("------");
    await expect(page.locator("div.font-mono.text-4xl")).toHaveText(/^\d{6}$/);
    // Issuer extracted from URI and shown in the config detail list
    await expect(page.locator("dd").filter({ hasText: "TestLogon" })).toBeVisible();
    // Account name extracted from label
    await expect(page.locator("dd").filter({ hasText: /devtest/ })).toBeVisible();
  });

  test("77.8 URI with unsupported algorithm shows warning but still generates code", async () => {
    await page.getByLabel("Paste TOTP configuration").fill(
      `otpauth://totp/Test:user@example.com?secret=${SECRET}&algorithm=MD5`,
    );
    // Non-blocking warning displayed
    await expect(page.getByText(/Falling back to SHA1/)).toBeVisible();
    // Code is still generated using the fallback SHA1 algorithm
    await expect(page.locator("div.font-mono.text-4xl")).toHaveText(/^\d{6}$/);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Section 78 — Billing log filter and display interactions
// ═════════════════════════════════════════════════════════════════════════════

test.describe("Section 78: Billing log filter and display", () => {
  let page: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    page = await browser.newPage();
    await injectAuth(page, ALICE_ID);

    await page.route("**/internal/dev-tools/billing/ledger**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_BILLING_LEDGER) }),
    );
    await page.route("**/internal/dev-tools/billing/summary**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_BILLING_SUMMARY) }),
    );

    await page.goto(`${DEVTOOLS}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("tab", { name: "Billing" }).click();
    // Wait for actual ledger data (confirms mock responded and React re-rendered)
    await expect(page.getByText("charge.succeeded")).toBeVisible();
  });

  test.afterAll(async () => {
    await page.close();
  });

  test("78.1 summary cards display mock aggregate values", async () => {
    // Summary card labels
    await expect(page.getByText("Gross inflow")).toBeVisible();
    await expect(page.getByText("Fees")).toBeVisible();
    await expect(page.getByText("Net balance")).toBeVisible();
    await expect(page.getByText("Transactions")).toBeVisible();
    // $25.00 also appears in the ledger Amount cell — scope to the summary card div
    await expect(page.locator("div.text-2xl.font-semibold").filter({ hasText: "$25.00" })).toBeVisible();
  });

  test("78.2 provider filter select can be changed to Stripe", async () => {
    const trigger = page.getByRole("combobox", { name: "Billing provider filter" });
    await expect(trigger).toBeVisible();
    await trigger.click();
    await page.getByRole("option", { name: "Stripe" }).click();
    await expect(trigger).toContainText("Stripe");
  });

  test("78.3 status filter select can be changed to Completed", async () => {
    const trigger = page.getByRole("combobox", { name: "Billing status filter" });
    await expect(trigger).toBeVisible();
    await trigger.click();
    await page.getByRole("option", { name: "Completed" }).click();
    await expect(trigger).toContainText("Completed");
  });

  test("78.4 Reset filters restores provider and status to all-items state", async () => {
    await page.getByRole("button", { name: "Reset filters" }).click();
    const providerTrigger = page.getByRole("combobox", { name: "Billing provider filter" });
    const statusTrigger  = page.getByRole("combobox", { name: "Billing status filter" });
    await expect(providerTrigger).toContainText(/All providers/i);
    await expect(statusTrigger).toContainText(/All statuses/i);
  });

  test("78.5 ledger table has all expected column headers", async () => {
    await expect(page.getByRole("columnheader", { name: "Occurred" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Provider" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Event" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Status" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Amount" })).toBeVisible();
  });

  test("78.6 ledger entry shows correct provider, event type, status, and external ID", async () => {
    await expect(page.getByText("charge.succeeded")).toBeVisible();
    await expect(page.getByText("ch_test123")).toBeVisible();
    // Provider badge and status badge from mock data
    await expect(page.getByText("stripe").first()).toBeVisible();
    await expect(page.getByText("completed").first()).toBeVisible();
  });

  test("78.7 Load more button absent when ledger has no next page", async () => {
    // MOCK_BILLING_LEDGER has next_cursor: null → hasNextPage is false
    await expect(page.getByRole("button", { name: "Load more" })).toHaveCount(0);
  });
});
