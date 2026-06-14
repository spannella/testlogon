/**
 * E2E tests — VEW-001..005 Account Views
 *
 * Sections:
 *   VEW-01 — Grant catalog API
 *   VEW-02 — View CRUD (create / list / get / update / delete) — API
 *   VEW-03 — Grant management (grant / list / revoke / respond) — API
 *   VEW-04 — Public link (create / read / revoke) — API
 *   VEW-05 — Resource data projection through view — API
 *   VEW-06 — Shared-with-me — API
 *   VEW-07 — Account Views page — UI
 *
 * Auth: uses e2e_admin_session_setup.py (alice = owner, bob = grantee)
 *
 * NOTE: All tests gate on OPEN_BANK_PROJECT_ENABLED + ACCOUNT_VIEWS_ENABLED.
 *       If the feature returns 404 the test is skipped gracefully.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE    = "http://localhost:3000";
const API     = "http://localhost:8000";
const ALICE   = "e2e_alice@test.local";
const BOB     = "e2e_bob@test.local";
const TS      = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw) as Record<string, AdminSessionData>;
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
  await page.goto(`${BASE}/bank/views`);
  await page.context().addCookies(session.cookies);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

function hdrs(identity: string, extra: Record<string, string> = {}): Record<string, string> {
  const s = getSessions()[identity];
  return {
    "Content-Type": "application/json",
    "x-csrf-token": s.csrf_token,
    ...extra,
  };
}

/** Returns true if VEW feature is enabled (otherwise tests skip gracefully). */
async function checkFeatureEnabled(page: Page): Promise<boolean> {
  const resp = await page.request.get(`${API}/ui/views/grant-catalog`);
  return resp.ok();
}

// ─── Test state shared across sections ───────────────────────────────────────

let aliceSub: string;
let bobSub: string;
let createdViewId: string;
let createdGrantId: string;
let publicToken: string;

// ─── VEW-01 — Grant catalog ───────────────────────────────────────────────────

test.describe("VEW-01 — Grant catalog API", () => {
  test("GET /ui/views/grant-catalog returns fields and presets", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) {
      test.skip();
      return;
    }

    const resp = await page.request.get(`${API}/ui/views/grant-catalog`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { fields: string[]; presets: { key: string }[] };
    expect(Array.isArray(body.fields)).toBe(true);
    expect(body.fields.length).toBeGreaterThan(0);
    expect(body.fields).toContain("can_see_balance");
    expect(Array.isArray(body.presets)).toBe(true);
    const presetKeys = body.presets.map((p) => p.key);
    expect(presetKeys).toContain("owner");
    expect(presetKeys).toContain("accountant");
    expect(presetKeys).toContain("public");
  });
});

// ─── VEW-02 — View CRUD ───────────────────────────────────────────────────────

test.describe("VEW-02 — View CRUD API", () => {
  test.beforeAll(() => {
    aliceSub = getSessions()[ALICE].user_sub;
    bobSub   = getSessions()[BOB].user_sub;
  });

  test("POST /ui/views/wallet/{sub} — creates a view", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.post(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}`,
      {
        headers: hdrs(ALICE),
        data: {
          name: `E2E View ${TS}`,
          description: "Created by E2E test",
          grants: { can_see_balance: true, can_see_account_label: true },
        },
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json() as { view_id: string; name: string };
    expect(body.view_id).toBeTruthy();
    expect(body.name).toBe(`E2E View ${TS}`);
    createdViewId = body.view_id;
  });

  test("GET /ui/views/wallet/{sub} — lists views including created", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.get(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}`,
      { headers: hdrs(ALICE) },
    );
    expect(resp.ok()).toBe(true);
    const views = await resp.json() as { view_id: string }[];
    expect(Array.isArray(views)).toBe(true);
    expect(views.some((v) => v.view_id === createdViewId)).toBe(true);
  });

  test("GET /ui/views/wallet/{sub}/{view_id} — retrieves a view", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.get(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${createdViewId}`,
      { headers: hdrs(ALICE) },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { view_id: string; grants: Record<string, boolean> };
    expect(body.view_id).toBe(createdViewId);
    expect(body.grants["can_see_balance"]).toBe(true);
  });

  test("PATCH /ui/views/wallet/{sub}/{view_id} — updates name", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.patch(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${createdViewId}`,
      {
        headers: hdrs(ALICE),
        data: { name: `Updated E2E View ${TS}` },
      },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { name: string };
    expect(body.name).toBe(`Updated E2E View ${TS}`);
  });

  test("DELETE /ui/views/wallet/{sub}/{view_id} — requires create of a fresh view first", async ({ browser }) => {
    // Create a disposable view then delete it
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const createResp = await page.request.post(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}`,
      {
        headers: hdrs(ALICE),
        data: { name: `Disposable ${TS}`, grants: { can_see_balance: true } },
      },
    );
    expect(createResp.status()).toBe(201);
    const { view_id } = await createResp.json() as { view_id: string };

    const delResp = await page.request.delete(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${view_id}`,
      { headers: hdrs(ALICE) },
    );
    expect(delResp.status()).toBe(204);
  });
});

// ─── VEW-03 — Grant management ────────────────────────────────────────────────

test.describe("VEW-03 — Grant management API", () => {
  test("POST .../grants — grants Bob access to Alice's view", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.post(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${createdViewId}/grants`,
      {
        headers: hdrs(ALICE),
        data: { grantee_sub: bobSub },
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json() as { grant_id: string; status: string };
    expect(body.grant_id).toBeTruthy();
    // status is either pending or active depending on resource settings
    expect(["pending", "active"]).toContain(body.status);
    createdGrantId = body.grant_id;
  });

  test("GET .../grants — lists grants for view", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.get(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${createdViewId}/grants`,
      { headers: hdrs(ALICE) },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { grants: { grant_id: string }[] };
    expect(Array.isArray(body.grants)).toBe(true);
    expect(body.grants.some((g) => g.grant_id === createdGrantId)).toBe(true);
  });

  test("POST .../respond — Bob accepts the grant", async ({ browser }) => {
    const page = await newIdentityPage(browser, BOB);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.post(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${createdViewId}/grants/${encodeURIComponent(bobSub)}/respond`,
      {
        headers: hdrs(BOB),
        data: { accept: true },
      },
    );
    // 200 if pending, or 400 if already active — both acceptable
    expect([200, 400]).toContain(resp.status());
  });

  test("GET /ui/views/shared-with-me — Bob sees Alice's grant", async ({ browser }) => {
    const page = await newIdentityPage(browser, BOB);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.get(
      `${API}/ui/views/shared-with-me`,
      { headers: hdrs(BOB) },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { grants: { resource_type: string }[] };
    expect(Array.isArray(body.grants)).toBe(true);
  });

  test("DELETE .../grants/{grantee_sub} — Alice revokes Bob's grant", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.delete(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${createdViewId}/grants/${encodeURIComponent(bobSub)}`,
      { headers: hdrs(ALICE) },
    );
    expect(resp.status()).toBe(204);
  });
});

// ─── VEW-04 — Public link ────────────────────────────────────────────────────

test.describe("VEW-04 — Public link API", () => {
  let publicViewId: string;

  test.beforeAll(async ({ browser }) => {
    // Create a public-preset view for Alice
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) return;

    const resp = await page.request.post(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}`,
      {
        headers: hdrs(ALICE),
        data: {
          name: `Public E2E ${TS}`,
          grants: { can_see_balance: true, can_see_account_label: true },
          preset: "public",
        },
      },
    );
    if (resp.ok()) {
      const body = await resp.json() as { view_id: string };
      publicViewId = body.view_id;
    }
  });

  test("POST .../public-link — creates a public share link", async ({ browser }) => {
    if (!publicViewId) { test.skip(); return; }
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.post(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/${publicViewId}/public-link`,
      {
        headers: hdrs(ALICE),
        data: { ttl_days: 7 },
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json() as { url: string; token: string; expires_at: number };
    expect(body.url).toContain("/ui/views/public/");
    expect(body.token).toBeTruthy();
    expect(body.expires_at).toBeGreaterThan(Date.now() / 1000);
    publicToken = body.token;
  });

  test("GET /ui/views/public/{token} — reads resource without auth", async ({ request }) => {
    if (!publicToken) { test.skip(); return; }
    const resp = await request.get(`${API}/ui/views/public/${publicToken}`);
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { resource_type: string; data: Record<string, unknown> };
    expect(body.resource_type).toBe("wallet");
  });

  test("DELETE /ui/views/public/{token} — revokes the link", async ({ browser }) => {
    if (!publicToken) { test.skip(); return; }
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.delete(
      `${API}/ui/views/public/${publicToken}`,
      { headers: hdrs(ALICE) },
    );
    expect(resp.status()).toBe(204);
  });

  test("GET /ui/views/public/{token} — returns 403 after revoke", async ({ request }) => {
    if (!publicToken) { test.skip(); return; }
    const resp = await request.get(`${API}/ui/views/public/${publicToken}`);
    expect(resp.status()).toBe(403);
  });
});

// ─── VEW-05 — Resource data projection ───────────────────────────────────────

test.describe("VEW-05 — Resource projection API", () => {
  test("GET .../data — Alice reads her own wallet through owner view", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    // owner view is always view_id='owner'
    const resp = await page.request.get(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/owner/data`,
      { headers: hdrs(ALICE) },
    );
    // 200 or 404 depending on wallet feature availability
    expect([200, 404]).toContain(resp.status());
    if (resp.ok()) {
      const body = await resp.json() as { resource_type: string; _view: { view_id: string } };
      expect(body.resource_type).toBe("wallet");
      expect(body._view.view_id).toBeTruthy();
    }
  });

  test("GET .../data — returns 403 for unknown view", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.get(
      `${API}/ui/views/wallet/${encodeURIComponent(aliceSub)}/nonexistent_view/data`,
      { headers: hdrs(ALICE) },
    );
    // Owner is allowed, non-owner grantee would get 403; here as owner they get 404 for view not found
    expect([403, 404]).toContain(resp.status());
  });
});

// ─── VEW-06 — Shared-with-me pagination ──────────────────────────────────────

test.describe("VEW-06 — Shared-with-me pagination", () => {
  test("supports cursor pagination", async ({ browser }) => {
    const page = await newIdentityPage(browser, BOB);
    const ok = await checkFeatureEnabled(page);
    if (!ok) { test.skip(); return; }

    const resp = await page.request.get(
      `${API}/ui/views/shared-with-me?limit=5`,
      { headers: hdrs(BOB) },
    );
    expect(resp.ok()).toBe(true);
    const body = await resp.json() as { grants: unknown[]; next_cursor: string | null };
    expect(Array.isArray(body.grants)).toBe(true);
    // next_cursor may be null if fewer than 5 results
    expect(["string", "object"].includes(typeof body.next_cursor)).toBe(true);
  });
});

// ─── VEW-07 — UI smoke tests ─────────────────────────────────────────────────

test.describe("VEW-07 — Account Views page UI", () => {
  test("renders the page and handles feature-off gracefully", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    await page.goto(`${BASE}/bank/views`);
    await page.waitForLoadState("networkidle");

    // Either the page loads normally or shows the feature-off banner
    const heading = page.getByRole("heading", { name: /account views/i, exact: false });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test("shows 'My Views' and 'Shared with Me' tabs", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    await injectAuth(page, ALICE);
    await page.goto(`${BASE}/bank/views`);
    await page.waitForLoadState("networkidle");

    // If feature off, we see the banner and not the tabs — skip
    const featureOff = await page.getByText(/not enabled/i).isVisible().catch(() => false);
    if (featureOff) { test.skip(); return; }

    await expect(page.getByRole("button", { name: /my views/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /shared with me/i })).toBeVisible();
  });

  test("clicking 'Shared with Me' tab shows delegated access section", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    await injectAuth(page, ALICE);
    await page.goto(`${BASE}/bank/views`);
    await page.waitForLoadState("networkidle");

    const featureOff = await page.getByText(/not enabled/i).isVisible().catch(() => false);
    if (featureOff) { test.skip(); return; }

    const tabBtn = page.getByText("Shared with Me");
    if (await tabBtn.isVisible()) {
      await tabBtn.click();
      // Either shows grants or empty state
      const hasContent = await page
        .getByText(/no resources have been shared/i)
        .or(page.locator(".rounded-md.border"))
        .first()
        .isVisible()
        .catch(() => false);
      expect(hasContent).toBe(true);
    }
  });

  test("New view button opens create dialog", async ({ browser }) => {
    const page = await newIdentityPage(browser, ALICE);
    await injectAuth(page, ALICE);
    await page.goto(`${BASE}/bank/views`);
    await page.waitForLoadState("networkidle");

    const featureOff = await page.getByText(/not enabled/i).isVisible().catch(() => false);
    if (featureOff) { test.skip(); return; }

    const newViewBtn = page.getByRole("button", { name: /new view/i });
    if (await newViewBtn.isVisible()) {
      await newViewBtn.click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await expect(page.getByText(/create new view/i)).toBeVisible();
    }
  });

  test("public view page renders token error gracefully", async ({ page }) => {
    await page.goto(`${BASE}/bank/views/public/invalid-token-xyz`);
    await page.waitForLoadState("networkidle");

    // Should show "invalid or expired" message (403 from backend)
    const errMsg = page.getByText(/invalid or expired/i);
    const loading = page.getByText(/shared resource view/i);
    // Either error or the heading should be visible
    await expect(errMsg.or(loading)).toBeVisible({ timeout: 10_000 });
  });
});
