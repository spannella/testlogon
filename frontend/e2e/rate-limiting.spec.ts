/**
 * E2E tests for PLATFORM-001: API Rate Limiting & Abuse Prevention.
 *
 * Section A: Global IP Rate Limit (4 tests)
 * Section B: Per-Endpoint Group Limits (5 tests)
 * Section C: Rate Limit Headers (3 tests)
 * Section D: Admin Dashboard API (4 tests)
 * Section E: Admin Dashboard UI (3 tests)
 *
 * ── Authentication strategy ─────────────────────────────────────────────────
 *
 * Uses `e2e_admin_session_setup.py` to get cookie-based sessions with:
 *   root           – role=root
 *   alice          – role=user
 *   bob            – role=user
 *   charlie_admin  – role=admin, admin_profile={type:general}
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────


// ─── Session bootstrap ─────────────────────────────────────────────────────────

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

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

// ─── Identity page factory ─────────────────────────────────────────────────────

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ───────────────────────────────────────────────────────────

async function apiGet(
  page: Page,
  path: string,
  params?: Record<string, string>,
) {
  return page.request.get(`${API}${path}`, { params });
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiPut(
  page: Page,
  identity: string,
  path: string,
  body?: unknown,
) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiDelete(
  page: Page,
  identity: string,
  path: string,
) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: {
      "x-csrf-token": sess.csrf_token,
    },
  });
}

// ─── DDB helpers ───────────────────────────────────────────────────────────────

const DDB_PYTHON_PREAMBLE = `
import boto3, os
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ[k.strip()] = v.strip()
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1')
t = ddb.Table('rate_limits')
`;

function setTestRateLimits(
  group: string,
  perUser: number,
  perIp: number,
  windowSec: number,
  bypassRoles: string[] = [],
): void {
  const rolesStr = bypassRoles.map((r) => `'${r}'`).join(", ");
  execSync(
    `python3 -c "${DDB_PYTHON_PREAMBLE}
t.put_item(Item={
    'pk': 'CONFIG#global',
    'sk': 'GROUP#${group}',
    'window_seconds': ${windowSec},
    'max_requests_per_user': ${perUser},
    'max_requests_per_ip': ${perIp},
    'bypass_roles': [${rolesStr}],
    'updated_by': 'e2e-test',
    'updated_at': 0,
})
print('OK')
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function clearTestRateLimits(group: string): void {
  execSync(
    `python3 -c "${DDB_PYTHON_PREAMBLE}
t.delete_item(Key={'pk': 'CONFIG#global', 'sk': 'GROUP#${group}'})
print('OK')
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function clearRateLimitCounters(prefix: string): void {
  execSync(
    `python3 -c "${DDB_PYTHON_PREAMBLE}
resp = t.scan(
    FilterExpression='begins_with(pk, :prefix)',
    ExpressionAttributeValues={':prefix': '${prefix}'},
)
items = resp.get('Items', [])
for item in items:
    t.delete_item(Key={'pk': item['pk'], 'sk': item['sk']})
print('Cleared ' + str(len(items)) + ' items')
"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

test.describe("PLATFORM-001: Rate Limiting", () => {
  let rootPage: Page;
  let alicePage: Page;
  let bobPage: Page;
  let charlieAdminPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions(); // warm up sessions
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    charlieAdminPage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    // Clean up test overrides
    try { clearTestRateLimits("messaging"); } catch { /* ignore */ }
    try { clearTestRateLimits("auth"); } catch { /* ignore */ }
    try { clearTestRateLimits("search"); } catch { /* ignore */ }
    try { clearRateLimitCounters("ENDPOINT#"); } catch { /* ignore */ }
    await rootPage?.close();
    await alicePage?.close();
    await bobPage?.close();
    await charlieAdminPage?.close();
  });

  // ─── Section A: Global IP Rate Limit ───────────────────────────────────────

  test.describe("Section A: Global IP Rate Limit", () => {
    test("A1 -- Requests below global limit succeed", async () => {
      // The default global limit is 300/60s. A few requests should be fine.
      for (let i = 0; i < 3; i++) {
        const resp = await apiGet(alicePage, "/ui/alerts");
        expect(resp.status()).toBeLessThan(429);
      }
    });

    test("A2 -- Requests exceeding per-endpoint limit return 429", async () => {
      test.setTimeout(60_000);
      // Use a per-endpoint limit (Layer 2 in middleware) with a very low threshold.
      // Set messaging group to 3 requests per user, 3 per IP, 300s window, no bypass.
      setTestRateLimits("messaging", 3, 3, 300, []);
      clearRateLimitCounters("ENDPOINT#messaging");

      // Also PUT via admin API to bust the backend in-memory cache
      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 300,
        max_requests_per_user: 3,
        max_requests_per_ip: 3,
        bypass_roles: [],
      });

      // Send requests to a messaging endpoint. The 4th should be 429.
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) {
        const resp = await apiGet(alicePage, "/messaging/conversations");
        statuses.push(resp.status());
        if (resp.status() === 429) break;
      }

      expect(statuses).toContain(429);

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });

    test("A3 -- 429 response includes Retry-After header", async () => {
      test.setTimeout(60_000);
      setTestRateLimits("messaging", 2, 2, 300, []);
      clearRateLimitCounters("ENDPOINT#messaging");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 300,
        max_requests_per_user: 2,
        max_requests_per_ip: 2,
        bypass_roles: [],
      });

      let rateLimitedResp;
      for (let i = 0; i < 5; i++) {
        const resp = await apiGet(alicePage, "/messaging/conversations");
        if (resp.status() === 429) {
          rateLimitedResp = resp;
          break;
        }
      }

      expect(rateLimitedResp).toBeDefined();
      const retryAfter = rateLimitedResp!.headers()["retry-after"];
      expect(retryAfter).toBeDefined();
      expect(Number(retryAfter)).toBeGreaterThan(0);

      // Verify the body has the correct structure
      const body = await rateLimitedResp!.json();
      expect(body.detail).toBeDefined();
      expect(body.detail.code).toBe("rate_limited");
      expect(body.detail.retry_after).toBeGreaterThan(0);
      expect(body.detail.group).toBe("messaging");

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });

    test("A4 -- Rate limit resets after window expires", async () => {
      test.setTimeout(30_000);
      // Set a very short window (10 sec) and low limit
      setTestRateLimits("messaging", 2, 2, 10, []);
      clearRateLimitCounters("ENDPOINT#messaging");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 10,
        max_requests_per_user: 2,
        max_requests_per_ip: 2,
        bypass_roles: [],
      });

      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        await apiGet(alicePage, "/messaging/conversations");
      }

      // Wait for the window to expire
      await new Promise((r) => setTimeout(r, 11_000));

      // Requests should succeed again
      const resp = await apiGet(alicePage, "/messaging/conversations");
      expect(resp.status()).toBeLessThan(429);

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });
  });

  // ─── Section B: Per-Endpoint Group Limits ──────────────────────────────────

  test.describe("Section B: Per-Endpoint Group Limits", () => {
    test("B5 -- Messaging endpoint respects per-user limit", async () => {
      test.setTimeout(60_000);
      setTestRateLimits("messaging", 3, 100, 300, []);
      clearRateLimitCounters("ENDPOINT#messaging");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 300,
        max_requests_per_user: 3,
        max_requests_per_ip: 100,
        bypass_roles: [],
      });

      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) {
        const resp = await apiGet(alicePage, "/messaging/conversations");
        statuses.push(resp.status());
        if (resp.status() === 429) break;
      }

      expect(statuses.filter((s) => s === 429).length).toBeGreaterThanOrEqual(1);

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });

    test("B6 -- Different users have independent limits", async () => {
      test.setTimeout(60_000);
      setTestRateLimits("messaging", 3, 100, 300, []);
      clearRateLimitCounters("ENDPOINT#messaging");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 300,
        max_requests_per_user: 3,
        max_requests_per_ip: 100,
        bypass_roles: [],
      });

      // Exhaust Alice's limit
      for (let i = 0; i < 5; i++) {
        await apiGet(alicePage, "/messaging/conversations");
      }

      // Bob should still be able to make requests
      const bobResp = await apiGet(bobPage, "/messaging/conversations");
      expect(bobResp.status()).toBeLessThan(429);

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });

    test("B7 -- Admin user bypasses messaging rate limit when role is in bypass list", async () => {
      test.setTimeout(60_000);
      // Set bypass_roles to include admin
      setTestRateLimits("messaging", 2, 100, 300, ["admin", "root"]);
      clearRateLimitCounters("ENDPOINT#messaging");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 300,
        max_requests_per_user: 2,
        max_requests_per_ip: 100,
        bypass_roles: ["admin", "root"],
      });

      // Charlie (admin) should be able to exceed the limit
      const statuses: number[] = [];
      for (let i = 0; i < 5; i++) {
        const resp = await apiGet(charlieAdminPage, "/messaging/conversations");
        statuses.push(resp.status());
      }

      // None should be 429
      expect(statuses.filter((s) => s === 429).length).toBe(0);

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });

    test("B8 -- Root user bypasses all rate limits", async () => {
      test.setTimeout(60_000);
      setTestRateLimits("messaging", 2, 2, 300, ["root"]);
      clearRateLimitCounters("ENDPOINT#messaging");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "messaging",
        window_seconds: 300,
        max_requests_per_user: 2,
        max_requests_per_ip: 2,
        bypass_roles: ["root"],
      });

      // Root should be able to exceed the limit
      const statuses: number[] = [];
      for (let i = 0; i < 5; i++) {
        const resp = await apiGet(rootPage, "/messaging/conversations");
        statuses.push(resp.status());
      }

      // None should be 429
      expect(statuses.filter((s) => s === 429).length).toBe(0);

      // Cleanup
      clearTestRateLimits("messaging");
      clearRateLimitCounters("ENDPOINT#messaging");
    });

    test("B9 -- Auth endpoints have no role bypass when configured", async () => {
      test.setTimeout(60_000);
      // Set auth group with no bypass_roles
      setTestRateLimits("auth", 100, 100, 300, []);
      clearRateLimitCounters("ENDPOINT#auth");

      await apiPut(rootPage, "root", "/ui/admin/rate-limits/config", {
        group: "auth",
        window_seconds: 300,
        max_requests_per_user: 100,
        max_requests_per_ip: 100,
        bypass_roles: [],
      });

      // Verify via the admin config API that the auth group has empty bypass_roles
      const configResp = await apiGet(rootPage, "/ui/admin/rate-limits/config");
      expect(configResp.status()).toBe(200);
      const config = await configResp.json();
      expect(config.groups?.auth).toBeDefined();
      expect(config.groups.auth.bypass_roles).toEqual([]);

      // Cleanup
      clearTestRateLimits("auth");
      clearRateLimitCounters("ENDPOINT#auth");
    });
  });

  // ─── Section C: Rate Limit Headers ─────────────────────────────────────────

  test.describe("Section C: Rate Limit Headers", () => {
    test("C10 -- Successful response includes X-RateLimit-* headers", async () => {
      // The global IP middleware injects X-RateLimit-* headers on all responses
      const resp = await apiGet(alicePage, "/ui/alerts");
      const headers = resp.headers();
      expect(headers["x-ratelimit-limit"]).toBeDefined();
      expect(Number(headers["x-ratelimit-limit"])).toBeGreaterThan(0);
    });

    test("C11 -- Remaining decrements with each request", async () => {
      // Clear global IP counters for a clean test
      clearRateLimitCounters("IP#");

      const remainingValues: number[] = [];
      for (let i = 0; i < 3; i++) {
        const resp = await apiGet(bobPage, "/ui/alerts");
        const remaining = resp.headers()["x-ratelimit-remaining"];
        if (remaining !== undefined) {
          remainingValues.push(Number(remaining));
        }
      }

      // Should have at least 2 values and they should decrease
      expect(remainingValues.length).toBeGreaterThanOrEqual(2);
      for (let i = 1; i < remainingValues.length; i++) {
        expect(remainingValues[i]).toBeLessThan(remainingValues[i - 1]!);
      }
    });

    test("C12 -- Reset header shows correct window expiry", async () => {
      const resp = await apiGet(alicePage, "/ui/alerts");
      const reset = resp.headers()["x-ratelimit-reset"];
      expect(reset).toBeDefined();

      const resetTs = Number(reset);
      const nowTs = Math.floor(Date.now() / 1000);
      // Reset should be in the future (within the window)
      expect(resetTs).toBeGreaterThan(nowTs);
      // But not more than the window size away (default 60s + small buffer)
      expect(resetTs).toBeLessThan(nowTs + 120);
    });
  });

  // ─── Section D: Admin Dashboard API ────────────────────────────────────────

  test.describe("Section D: Admin Dashboard API", () => {
    test("D13 -- Admin can view rate limit configuration", async () => {
      const resp = await apiGet(rootPage, "/ui/admin/rate-limits/config");
      expect(resp.status()).toBe(200);

      const data = await resp.json();
      expect(data.global_ip).toBeDefined();
      expect(data.global_ip.enabled).toBe(true);
      expect(data.global_ip.window_seconds).toBeGreaterThan(0);
      expect(data.global_ip.max_requests).toBeGreaterThan(0);

      expect(data.groups).toBeDefined();
      // Should have at least the messaging and auth groups
      expect(data.groups.messaging).toBeDefined();
      expect(data.groups.auth).toBeDefined();
      expect(data.groups.messaging.window_seconds).toBeGreaterThan(0);
      expect(data.groups.messaging.max_requests_per_user).toBeGreaterThan(0);
    });

    test("D14 -- Admin can update rate limit for a group", async () => {
      const resp = await apiPut(
        rootPage,
        "root",
        "/ui/admin/rate-limits/config",
        {
          group: "messaging",
          window_seconds: 120,
          max_requests_per_user: 500,
          max_requests_per_ip: 1000,
        },
      );
      expect(resp.status()).toBe(200);

      const data = await resp.json();
      expect(data.ok).toBe(true);
      expect(data.group).toBe("messaging");

      // Verify the new config shows override
      const configResp = await apiGet(
        rootPage,
        "/ui/admin/rate-limits/config",
      );
      const config = await configResp.json();
      expect(config.groups.messaging.is_override).toBe(true);

      // Cleanup
      clearTestRateLimits("messaging");
    });

    test("D15 -- Admin can add IP to allowlist", async () => {
      const addResp = await apiPost(
        rootPage,
        "root",
        "/ui/admin/rate-limits/allowlist",
        { cidr: "198.51.100.0/24", reason: "E2E test allowlist" },
      );
      expect(addResp.status()).toBe(201);
      const addData = await addResp.json();
      expect(addData.ok).toBe(true);

      // Verify it appears in the list
      const listResp = await apiGet(
        rootPage,
        "/ui/admin/rate-limits/allowlist",
      );
      expect(listResp.status()).toBe(200);
      const listData = await listResp.json();
      const entry = listData.entries.find(
        (e: any) => e.sk === "198.51.100.0/24",
      );
      expect(entry).toBeDefined();
      expect(entry.reason).toBe("E2E test allowlist");

      // Cleanup
      const delResp = await apiDelete(
        rootPage,
        "root",
        "/ui/admin/rate-limits/allowlist/198.51.100.0%2F24",
      );
      expect(delResp.status()).toBe(200);
    });

    test("D16 -- Admin can view top offenders", async () => {
      const resp = await apiGet(
        rootPage,
        "/ui/admin/rate-limits/top-offenders",
        { hours: "1", limit: "10" },
      );
      expect(resp.status()).toBe(200);

      const data = await resp.json();
      expect(data.top_ips).toBeDefined();
      expect(data.top_users).toBeDefined();
      expect(Array.isArray(data.top_ips)).toBe(true);
      expect(Array.isArray(data.top_users)).toBe(true);
    });
  });

  // ─── Section E: Admin Dashboard UI ─────────────────────────────────────────

  test.describe("Section E: Admin Dashboard UI", () => {
    let uiRootPage: Page;

    test.beforeAll(async ({ browser }) => {
      // Create a fresh page for UI tests
      const sessions = getSessions();
      uiRootPage = await browser.newPage();
      await uiRootPage.context().addCookies(sessions["root"].cookies);
      // Navigate to /login first so localStorage is available
      await uiRootPage.goto("/login", { waitUntil: "domcontentloaded" });
      // Set auth-store in localStorage so ProtectedRoute passes
      await uiRootPage.evaluate((uid: string) => {
        const state = { userId: uid, accessToken: null, isAuthenticated: true };
        localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
      }, sessions["root"].user_sub);
    });

    test.afterAll(async () => {
      await uiRootPage?.close();
    });

    test("E17 -- Dashboard loads with summary cards", async () => {
      await uiRootPage.goto("/admin/rate-limits");
      await uiRootPage.waitForLoadState("domcontentloaded");

      // Should see the Rate Limit Dashboard heading
      await expect(
        uiRootPage.getByRole("heading", { name: "Rate Limit Dashboard" }),
      ).toBeVisible({ timeout: 15_000 });

      // The live summary cards live on the "Live Dashboard" tab.
      await uiRootPage.getByRole("tab", { name: "Live Dashboard" }).click();
      await expect(uiRootPage.getByText(/Total Hits/)).toBeVisible({ timeout: 10_000 });
      await expect(uiRootPage.getByText("Top Group", { exact: true })).toBeVisible();
      await expect(uiRootPage.getByText("Top Source", { exact: true })).toBeVisible();
    });

    test("E18 -- Endpoint group config table renders", async () => {
      await uiRootPage.goto("/admin/rate-limits");
      await uiRootPage.waitForLoadState("domcontentloaded");

      // The "Rules" tab (default) shows the endpoint group configuration.
      await uiRootPage.getByRole("tab", { name: "Rules" }).click();

      // CardTitle renders as <div>, not <heading>, so use getByText.
      await expect(
        uiRootPage.getByText("Endpoint Group Configuration"),
      ).toBeVisible({ timeout: 10_000 });
      await expect(
        uiRootPage.getByText("Global IP Rate Limit"),
      ).toBeVisible();
    });

    test("E19 -- Non-root user cannot access rate limit dashboard API", async () => {
      // Alice (user role) should get 403 from the admin rate limits API
      const resp = await apiGet(alicePage, "/ui/admin/rate-limits/config");
      expect(resp.status()).toBe(403);
    });
  });
});
