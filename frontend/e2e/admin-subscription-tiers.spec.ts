/**
 * E2E tests for the Admin Subscription Tier Manager (ADMIN-001).
 *
 * Endpoints under /ui/admin/subscription-tiers require an admin or root session
 * (require_admin_or_root). Tiers are scoped to the authenticated operator's sub.
 *
 *   root          – role=root  (primary creator for tier operations)
 *   charlie_admin – role=admin (separate creator, scoping isolation)
 *   alice / bob   – role=user  (403 rejection tests)
 *
 * Auth strategy mirrors frontend/e2e/admin-roles.spec.ts: each identity gets a
 * Playwright page with its role-bearing cookies injected; non-GET requests carry
 * the x-csrf-token header.
 *
 * Sections 547-550b (30 tests).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "ui/admin/subscription-tiers";

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  // Seed the client-side auth store so ProtectedRoute treats the page as
  // authenticated (cookies alone only satisfy server-side API auth).
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
  return page;
}

type ReqParams = Record<string, string>;

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: ReqParams) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();

// ─── 547. Tier CRUD API ─────────────────────────────────────────────────────

test.describe("547. Subscription tier CRUD API", () => {
  let rootPage: Page;
  let goldId = "";
  let silverId = "";

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Gold_${TS}`,
      price_cents: 1999,
      billing_cycle: "monthly",
      benefits: ["Exclusive posts"],
      access_level: "premium",
    });
    expect(r.status()).toBe(201);
    goldId = (await r.json()).tier_id;
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("creator creates a subscription tier", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Silver_${TS}`,
      price_cents: 999,
      billing_cycle: "monthly",
      benefits: ["Exclusive posts", "Early access"],
    });
    expect(r.status()).toBe(201);
    const data = await r.json();
    silverId = data.tier_id;
    expect(typeof data.tier_id).toBe("string");
    expect(data.status).toBe("active");
    expect(data.subscriber_count).toBe(0);
  });

  test("creator lists their tiers sorted by display_order", async () => {
    const r = await apiGet(rootPage, BASE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<Record<string, unknown>>;
    const names = data.map((t) => t.name);
    expect(names).toContain(`E2E_Gold_${TS}`);
    expect(names).toContain(`E2E_Silver_${TS}`);
    const orders = data.map((t) => t.display_order as number);
    const sorted = [...orders].sort((a, b) => a - b);
    expect(orders).toEqual(sorted);
  });

  test("creator updates tier description", async () => {
    const r = await apiPatch(rootPage, "root", `${BASE}/${silverId}`, {
      description: "Best value tier",
    });
    expect(r.status()).toBe(200);
    const get = await apiGet(rootPage, `${BASE}/${silverId}`);
    expect((await get.json()).description).toBe("Best value tier");
  });

  test("creator deletes tier with zero subscribers", async () => {
    const r = await apiDelete(rootPage, "root", `${BASE}/${silverId}`);
    expect(r.status()).toBe(200);
    expect((await r.json()).deleted).toBe(true);
    const list = await apiGet(rootPage, BASE);
    const names = ((await list.json()) as Array<Record<string, unknown>>).map((t) => t.name);
    expect(names).not.toContain(`E2E_Silver_${TS}`);
  });

  // ─── 548. Lifecycle ───────────────────────────────────────────────────────

  test("creator archives a tier", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/${goldId}/archive`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.status).toBe("archived");
    expect(typeof data.archived_at).toBe("number");
  });

  test("archived tier excluded from default list", async () => {
    const r = await apiGet(rootPage, BASE);
    const names = ((await r.json()) as Array<Record<string, unknown>>).map((t) => t.name);
    expect(names).not.toContain(`E2E_Gold_${TS}`);
  });

  test("archived tier included with include_archived flag", async () => {
    const r = await apiGet(rootPage, BASE, { include_archived: "true" });
    const found = ((await r.json()) as Array<Record<string, unknown>>).find(
      (t) => t.name === `E2E_Gold_${TS}`,
    );
    expect(found).toBeTruthy();
    expect(found!.status).toBe("archived");
  });

  test("creator unarchives a tier", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/${goldId}/unarchive`);
    expect(r.status()).toBe(200);
    expect((await r.json()).status).toBe("active");
  });

  // ─── 549. Reorder & preview ───────────────────────────────────────────────

  test("creator creates second tier for reorder test", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Platinum_${TS}`,
      price_cents: 2999,
    });
    expect(r.status()).toBe(201);
  });

  test("creator reorders tiers (Platinum first)", async () => {
    const list = await apiGet(rootPage, BASE);
    const all = (await list.json()) as Array<Record<string, unknown>>;
    const platinum = all.find((t) => t.name === `E2E_Platinum_${TS}`)!;
    const gold = all.find((t) => t.name === `E2E_Gold_${TS}`)!;
    const r = await apiPut(rootPage, "root", `${BASE}/reorder`, {
      tier_ids: [platinum.tier_id, gold.tier_id],
    });
    expect(r.status()).toBe(200);
    const reGet = await apiGet(rootPage, BASE);
    const reAll = (await reGet.json()) as Array<Record<string, unknown>>;
    const platinumAfter = reAll.find((t) => t.name === `E2E_Platinum_${TS}`)!;
    expect(platinumAfter.display_order).toBe(0);
  });

  test("preview returns subscriber-facing active tiers", async () => {
    const r = await apiGet(rootPage, `${BASE}/preview`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(Array.isArray(data.tiers)).toBe(true);
    for (const t of data.tiers) {
      expect(typeof t.name).toBe("string");
      expect(typeof t.price_cents).toBe("number");
      expect(Array.isArray(t.benefits)).toBe(true);
    }
  });

  test("preview respects display order (Platinum first)", async () => {
    const r = await apiGet(rootPage, `${BASE}/preview`);
    const data = await r.json();
    // The dev creator accumulates tiers across runs; scope to THIS run's tiers
    // (name suffixed with _${TS}) and assert Platinum (display_order 0) leads.
    const mine = (data.tiers as Array<{ name: string }>).filter((t) =>
      t.name.endsWith(`_${TS}`),
    );
    expect(mine.length).toBeGreaterThan(0);
    expect(mine[0].name).toBe(`E2E_Platinum_${TS}`);
  });

  // ─── 550. Analytics ───────────────────────────────────────────────────────

  test("creator views tier analytics", async () => {
    const r = await apiGet(rootPage, `${BASE}/analytics`);
    expect(r.status()).toBe(200);
    const data = await r.json();
    expect(data.total_subscribers).toBeGreaterThanOrEqual(0);
    expect(data.total_revenue_cents).toBeGreaterThanOrEqual(0);
    expect(Array.isArray(data.tiers)).toBe(true);
  });

  test("analytics includes per-tier subscriber count", async () => {
    const r = await apiGet(rootPage, `${BASE}/analytics`);
    const data = await r.json();
    for (const row of data.tiers) {
      expect(typeof row.subscriber_count).toBe("number");
    }
  });

  test("delete tier with subscribers returns 409", async () => {
    // Seed a subscriber count directly on the Gold tier, then attempt delete.
    execSync(
      `python3 -c "
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('ADMIN_SUBSCRIPTION_TIERS_TABLE_NAME','admin_subscription_tiers'))
tbl.update_item(Key={'pk':'CREATOR#root.admin@testdev.local','sk':'TIER#${goldId}'}, UpdateExpression='SET subscriber_count=:c', ExpressionAttributeValues={':c':3})
print('seeded subscriber_count')
"`,
      { cwd: REPO_ROOT, timeout: 10_000 },
    );
    const r = await apiDelete(rootPage, "root", `${BASE}/${goldId}`);
    expect(r.status()).toBe(409);
  });

  test("price validation rejects zero", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Free_${TS}`,
      price_cents: 0,
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 547b. Input validation ─────────────────────────────────────────────────

test.describe("547b. Tier input validation", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("name exceeding 100 chars rejected", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: "x".repeat(101),
      price_cents: 999,
    });
    expect(r.status()).toBe(422);
  });

  test("price above $1000 rejected", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_High_${TS}`,
      price_cents: 100001,
    });
    expect(r.status()).toBe(422);
  });

  test("benefits exceeding 20 items rejected", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Many_${TS}`,
      price_cents: 999,
      benefits: Array.from({ length: 21 }, (_, i) => `b${i}`),
    });
    expect(r.status()).toBe(422);
  });

  test("invalid billing cycle rejected", async () => {
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Biannual_${TS}`,
      price_cents: 999,
      billing_cycle: "biannual",
    });
    expect(r.status()).toBe(422);
  });

  test("empty name rejected", async () => {
    const r = await apiPost(rootPage, "root", BASE, { name: "", price_cents: 999 });
    expect(r.status()).toBe(422);
  });
});

// ─── 548b. Concurrency & idempotency ────────────────────────────────────────

test.describe("548b. Tier concurrency & idempotency", () => {
  let rootPage: Page;
  let tierId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const r = await apiPost(rootPage, "root", BASE, {
      name: `E2E_Idem_${TS}`,
      price_cents: 999,
    });
    tierId = (await r.json()).tier_id;
  });
  test.afterAll(async () => {
    await apiDelete(rootPage, "root", `${BASE}/${tierId}`).catch(() => {});
    await rootPage?.close();
  });

  test("archive already-archived tier returns 400", async () => {
    const first = await apiPost(rootPage, "root", `${BASE}/${tierId}/archive`);
    expect(first.status()).toBe(200);
    const second = await apiPost(rootPage, "root", `${BASE}/${tierId}/archive`);
    expect(second.status()).toBe(400);
  });

  test("unarchive already-active tier returns 400", async () => {
    await apiPost(rootPage, "root", `${BASE}/${tierId}/unarchive`);
    const r = await apiPost(rootPage, "root", `${BASE}/${tierId}/unarchive`);
    expect(r.status()).toBe(400);
  });

  test("reorder with unknown tier ID returns 400", async () => {
    const r = await apiPut(rootPage, "root", `${BASE}/reorder`, {
      tier_ids: [tierId, "tier_does_not_exist"],
    });
    expect(r.status()).toBe(400);
  });

  test("reorder with duplicate IDs returns 422", async () => {
    const r = await apiPut(rootPage, "root", `${BASE}/reorder`, {
      tier_ids: [tierId, tierId],
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 549b. Authorization & CSRF ─────────────────────────────────────────────

test.describe("549b. Tier authorization & CSRF", () => {
  let rootPage: Page;
  let alicePage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
    await charliePage?.close();
  });

  test("regular user (alice) cannot manage tiers (403)", async () => {
    const r = await apiPost(alicePage, "alice", BASE, {
      name: `E2E_AliceDenied_${TS}`,
      price_cents: 999,
    });
    expect(r.status()).toBe(403);
  });

  test("tiers are scoped per operator (charlie sees none of root's)", async () => {
    const r = await apiGet(charliePage, BASE, { include_archived: "true" });
    expect(r.status()).toBe(200);
    const names = ((await r.json()) as Array<Record<string, unknown>>).map((t) => t.name);
    expect(names).not.toContain(`E2E_Gold_${TS}`);
  });

  test("unauthenticated request gets 401", async ({ request }) => {
    const r = await request.get(`${API}/${BASE}`);
    expect(r.status()).toBe(401);
  });

  test("missing CSRF on POST returns 403", async () => {
    const r = await rootPage.request.post(`${API}/${BASE}`, {
      data: { name: `E2E_NoCsrf_${TS}`, price_cents: 999 },
      headers: { "Content-Type": "application/json" },
    });
    expect(r.status()).toBe(403);
  });
});

// ─── 550b. UI ────────────────────────────────────────────────────────────────

test.describe("550b. Tier manager UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    // Ensure at least one tier exists for the UI list.
    await apiPost(rootPage, "root", BASE, {
      name: `E2E_UiTier_${TS}`,
      price_cents: 1299,
      benefits: ["UI benefit"],
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("tier manager page renders tier cards", async () => {
    await rootPage.goto("/admin/subscription-tiers");
    await expect(
      rootPage.getByRole("heading", { name: "Subscription Tiers" }),
    ).toBeVisible();
    await expect(rootPage.getByTestId("tier-card").first()).toBeVisible({ timeout: 15_000 });
  });

  test("create tier dialog opens and submits", async () => {
    await rootPage.goto("/admin/subscription-tiers");
    await rootPage.getByRole("button", { name: /create tier/i }).click();
    const uniqueName = `E2E_DialogTier_${TS}`;
    await rootPage.getByLabel("Name").fill(uniqueName);
    await rootPage.getByLabel("Price (USD)").fill("14.99");
    await rootPage.getByRole("button", { name: "Save" }).click();
    // The new tier renders as a card whose title (a div, not a heading) shows
    // the tier name. Assert the tier card containing the name is visible.
    await expect(
      rootPage
        .getByTestId("tier-card")
        .filter({ hasText: uniqueName })
        .first(),
    ).toBeVisible({ timeout: 15_000 });
  });
});
