/**
 * E2E tests for ADMIN-003: Rate Limit Admin UI.
 *
 * Section 555: Rate Limit Config API (4 tests)
 * Section 556: Blocklist & Allowlist API (4 tests)
 * Section 557: Events & Top Offenders API (4 tests)
 * Section 558: Live Summary API (3 tests)
 * Section 559: Input Validation Edge Cases (4 tests)
 * Section 560: Concurrent Operations (3 tests)
 * Section 561: Authorization Boundary Tests (4 tests)
 * Section 562: Rate Limit Dashboard UI (4 tests)
 *
 * ── Authentication strategy ─────────────────────────────────────────────────
 * All rate-limit admin endpoints require ROOT role via `require_root`
 * (app/auth/policy.py). Cookie auth is resolved from the HS256 `ui_access_token`
 * cookie minted by `e2e_admin_session_setup.py`. Non-GET cookie requests carry
 * an `x-csrf-token` header.
 *
 *   root  – role=root  (full access)
 *   alice – role=user  (403 boundary tests)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ─────────────────────────────────────────────────────────────────

const RL = "ui/admin/rate-limits";

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

// ─── Request helpers ───────────────────────────────────────────────────────────

type ReqParams = Record<string, string>;

async function apiGet(page: Page, path: string, params?: ReqParams) {
  return page.request.get(`${API}/${path}`, { params });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.post(`${API}/${path}`, {
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

// ─── DDB event seeding ─────────────────────────────────────────────────────────

/** Seed N rate-limit events directly into the rate_limit_events table. */
function seedEvents(): void {
  execSync(
    `python3 -c "
import boto3, os, time, uuid
from datetime import datetime, timezone
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('RATE_LIMIT_EVENTS_TABLE_NAME','rate_limit_events'))
now = int(time.time())
seeds = [
    ('auth','ip','203.0.113.42','/ui/login','POST','rejected'),
    ('auth','ip','203.0.113.42','/ui/login','POST','rejected'),
    ('messaging','ip','198.51.100.17','/messaging/send','POST','allowed'),
    ('search','user','e2e_alice@test.local','/ui/discover/search','GET','rejected'),
    ('messaging','ip','198.51.100.17','/messaging/send','POST','rejected'),
]
for i,(grp,it,iv,ep,m,st) in enumerate(seeds):
    ts = now - 60 - i*30
    date_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d')
    eid = 'evt_' + uuid.uuid4().hex[:12]
    tbl.put_item(Item={'pk': f'DATE#{date_str}', 'sk': f'{ts}#{eid}', 'endpoint_group': grp, 'identity_type': it, 'identity_value': iv, 'endpoint': ep, 'method': m, 'status': st, 'count': 5, 'limit': 3, 'ttl_epoch': ts + 86400})
print('seeded', len(seeds))
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/** Reset the 'messaging' config override (cleanup after PUT). */
function resetMessagingConfig(rootPage: Page): void {
  // best-effort via API in afterAll
  void rootPage;
}

// Unique-per-run IP to avoid cross-retry collisions.
const RUN_IP = `192.168.${Math.floor(Date.now() % 254) + 1}.123`;
const RUN_CIDR = `172.16.${Math.floor(Date.now() % 254) + 1}.0/24`;

// ─── 555. Rate Limit Config API ─────────────────────────────────────────────────

test.describe("555. Rate Limit Config API", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedEvents();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, "root", `${RL}/config/messaging`);
    } catch {
      /* ignore */
    }
    await rootPage?.close();
    await alicePage?.close();
  });

  test("Root retrieves all rate limit configs", async () => {
    const res = await apiGet(rootPage, `${RL}/config`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.groups).toBeTruthy();
    expect(body.groups.messaging).toBeTruthy();
    expect(typeof body.groups.messaging.max_requests_per_user).toBe("number");
    expect(typeof body.groups.messaging.window_seconds).toBe("number");
  });

  test("Root updates group config", async () => {
    const res = await apiPut(rootPage, "root", `${RL}/config`, {
      group: "messaging",
      max_requests_per_user: 777,
    });
    expect(res.status()).toBe(200);
    const reget = await apiGet(rootPage, `${RL}/config`);
    const body = await reget.json();
    expect(body.groups.messaging.max_requests_per_user).toBe(777);
  });

  test("Updated config marked as override", async () => {
    const res = await apiGet(rootPage, `${RL}/config`);
    const body = await res.json();
    expect(body.groups.messaging.is_override).toBe(true);
  });

  test("Non-root cannot access config", async () => {
    const res = await apiGet(alicePage, `${RL}/config`);
    expect(res.status()).toBe(403);
  });
});

// ─── 556. Blocklist & Allowlist API ──────────────────────────────────────────────

test.describe("556. Blocklist & Allowlist API", () => {
  let rootPage: Page;
  let seededEntryId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    // Seed one blocklist entry
    const seedIp = "192.168.1.50";
    await apiPost(rootPage, "root", `${RL}/blocklist`, { ip: seedIp, reason: "seed" });
    seededEntryId = seedIp;
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, "root", `${RL}/blocklist/${RUN_IP}`);
      await apiDelete(rootPage, "root", `${RL}/blocklist/${seededEntryId}`);
      await apiDelete(rootPage, "root", `${RL}/allowlist/${encodeURIComponent(RUN_CIDR)}`);
    } catch {
      /* ignore */
    }
    await rootPage?.close();
  });

  test("Root views blocklist", async () => {
    const res = await apiGet(rootPage, `${RL}/blocklist`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.entries)).toBe(true);
    expect(body.entries.some((e: any) => e.sk === seededEntryId)).toBe(true);
  });

  test("Root adds IP to blocklist", async () => {
    const res = await apiPost(rootPage, "root", `${RL}/blocklist`, { ip: RUN_IP, reason: "bot" });
    expect(res.status()).toBe(201);
    const reget = await apiGet(rootPage, `${RL}/blocklist`);
    const body = await reget.json();
    expect(body.entries.some((e: any) => e.sk === RUN_IP)).toBe(true);
  });

  test("Root removes IP from blocklist", async () => {
    const res = await apiDelete(rootPage, "root", `${RL}/blocklist/${RUN_IP}`);
    expect(res.status()).toBe(200);
    const reget = await apiGet(rootPage, `${RL}/blocklist`);
    const body = await reget.json();
    expect(body.entries.some((e: any) => e.sk === RUN_IP)).toBe(false);
  });

  test("Root adds CIDR to allowlist", async () => {
    const res = await apiPost(rootPage, "root", `${RL}/allowlist`, { cidr: RUN_CIDR, reason: "internal" });
    expect(res.status()).toBe(201);
    const reget = await apiGet(rootPage, `${RL}/allowlist`);
    const body = await reget.json();
    expect(body.entries.some((e: any) => e.sk === RUN_CIDR)).toBe(true);
  });
});

// ─── 557. Events & Top Offenders API ──────────────────────────────────────────────

test.describe("557. Events & Top Offenders API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    seedEvents();
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("Root queries rate limit events", async () => {
    const res = await apiGet(rootPage, `${RL}/events`, { hours: "24", limit: "50" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.events)).toBe(true);
    expect(body.events.length).toBeGreaterThan(0);
  });

  test("Events filterable by status", async () => {
    const res = await apiGet(rootPage, `${RL}/events`, { hours: "24", limit: "50", status: "rejected" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    for (const evt of body.events) {
      expect(evt.status).toBe("rejected");
    }
  });

  test("Top offenders returns ranked list", async () => {
    const res = await apiGet(rootPage, `${RL}/top-offenders`, { hours: "24", limit: "20" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.top_ips)).toBe(true);
    const counts = body.top_ips.map((x: any) => x.rejected_count);
    const sorted = [...counts].sort((a, b) => b - a);
    expect(counts).toEqual(sorted);
  });

  test("Event export returns CSV", async () => {
    const res = await apiGet(rootPage, `${RL}/events/export`, { hours: "24" });
    expect(res.status()).toBe(200);
    expect(res.headers()["content-type"]).toContain("text/csv");
    const text = await res.text();
    expect(text.split("\n")[0]).toContain("timestamp");
  });
});

// ─── 558. Live Summary API ──────────────────────────────────────────────────────

test.describe("558. Live Summary API", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    seedEvents();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("Root retrieves live summary", async () => {
    const res = await apiGet(rootPage, `${RL}/live-summary`, { hours: "1" });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.total_hits).toBeGreaterThanOrEqual(0);
    expect(typeof body.by_group).toBe("object");
    expect(Array.isArray(body.time_series)).toBe(true);
  });

  test("Live summary includes top sources", async () => {
    const res = await apiGet(rootPage, `${RL}/live-summary`, { hours: "1" });
    const body = await res.json();
    expect(Array.isArray(body.by_source)).toBe(true);
    if (body.by_source.length > 0) {
      expect(body.by_source[0]).toHaveProperty("source_ip");
      expect(body.by_source[0]).toHaveProperty("count");
    }
  });

  test("Non-root cannot access live summary", async () => {
    const res = await apiGet(alicePage, `${RL}/live-summary`, { hours: "1" });
    expect(res.status()).toBe(403);
  });
});

// ─── 559. Input Validation Edge Cases ──────────────────────────────────────────────

test.describe("559. Input Validation Edge Cases", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, "root", `${RL}/config/messaging`);
    } catch {
      /* ignore */
    }
    await rootPage?.close();
  });

  test("Empty IP rejected for blocklist", async () => {
    const res = await apiPost(rootPage, "root", `${RL}/blocklist`, { ip: "" });
    expect(res.status()).toBe(422);
  });

  test("Empty CIDR rejected for allowlist", async () => {
    const res = await apiPost(rootPage, "root", `${RL}/allowlist`, { cidr: "" });
    expect(res.status()).toBe(422);
  });

  test("Config update with zero max_requests_per_user rejected", async () => {
    const res = await apiPut(rootPage, "root", `${RL}/config`, {
      group: "messaging",
      max_requests_per_user: 0,
    });
    expect(res.status()).toBe(422);
  });

  test("Config update for unknown group rejected", async () => {
    const res = await apiPut(rootPage, "root", `${RL}/config`, {
      group: "totally_unknown_group",
      max_requests_per_user: 10,
    });
    expect(res.status()).toBe(400);
  });
});

// ─── 560. Concurrent Operations ──────────────────────────────────────────────────

test.describe("560. Concurrent Operations", () => {
  let rootPage: Page;
  const dupIp = `192.168.${Math.floor(Date.now() % 254) + 1}.222`;

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, "root", `${RL}/blocklist/${dupIp}`);
    } catch {
      /* ignore */
    }
    await rootPage?.close();
  });

  test("Duplicate blocklist add is idempotent", async () => {
    const r1 = await apiPost(rootPage, "root", `${RL}/blocklist`, { ip: dupIp, reason: "a" });
    const r2 = await apiPost(rootPage, "root", `${RL}/blocklist`, { ip: dupIp, reason: "b" });
    expect(r1.status()).toBe(201);
    expect(r2.status()).toBe(201);
    const reget = await apiGet(rootPage, `${RL}/blocklist`);
    const body = await reget.json();
    const matches = body.entries.filter((e: any) => e.sk === dupIp);
    expect(matches.length).toBe(1);
  });

  test("Config update during event query both succeed", async () => {
    const [putRes, getRes] = await Promise.all([
      apiPut(rootPage, "root", `${RL}/config`, { group: "search", max_requests_per_user: 321 }),
      apiGet(rootPage, `${RL}/events`, { hours: "1", limit: "10" }),
    ]);
    expect(putRes.status()).toBe(200);
    expect(getRes.status()).toBe(200);
    await apiDelete(rootPage, "root", `${RL}/config/search`);
  });

  test("Blocklist remove of non-existent entry succeeds idempotently", async () => {
    const res = await apiDelete(rootPage, "root", `${RL}/blocklist/10.255.255.254`);
    expect(res.status()).toBe(200);
  });
});

// ─── 561. Authorization Boundary Tests ──────────────────────────────────────────────

test.describe("561. Authorization Boundary Tests", () => {
  let alicePage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await charliePage?.close();
  });

  test("Regular user cannot add to blocklist", async () => {
    const res = await apiPost(alicePage, "alice", `${RL}/blocklist`, { ip: "1.2.3.4" });
    expect(res.status()).toBe(403);
  });

  test("Regular user cannot remove from allowlist", async () => {
    const res = await apiDelete(alicePage, "alice", `${RL}/allowlist/10.0.0.0%2F8`);
    expect(res.status()).toBe(403);
  });

  test("Regular user cannot export events", async () => {
    const res = await apiGet(alicePage, `${RL}/events/export`, { hours: "1" });
    expect(res.status()).toBe(403);
  });

  test("Admin (non-root) cannot update config", async () => {
    const res = await apiPut(charliePage, "charlie_admin", `${RL}/config`, {
      group: "messaging",
      max_requests_per_user: 10,
    });
    expect(res.status()).toBe(403);
  });
});

// ─── 562. Rate Limit Dashboard UI ──────────────────────────────────────────────────

test.describe("562. Rate Limit Dashboard UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    seedEvents();
    rootPage = await newIdentityPage(browser, "root");
    // seed a blocklist entry so the Blocklist tab shows a row
    await apiPost(rootPage, "root", `${RL}/blocklist`, { ip: "192.168.1.50", reason: "seed-ui" });
  });

  test.afterAll(async () => {
    try {
      await apiDelete(rootPage, "root", `${RL}/blocklist/192.168.1.50`);
    } catch {
      /* ignore */
    }
    await rootPage?.close();
  });

  test("Dashboard loads with Rules tab", async () => {
    await rootPage.goto("/admin/rate-limits");
    await expect(rootPage.getByRole("heading", { name: "Rate Limit Dashboard" })).toBeVisible();
    await expect(rootPage.getByRole("tab", { name: /rules/i })).toBeVisible();
    // Rules tab content (config panel) is the default
    await expect(rootPage.getByText("Endpoint Group Configuration")).toBeVisible();
  });

  test("Blocklist tab shows entries", async () => {
    await rootPage.goto("/admin/rate-limits");
    await rootPage.getByRole("tab", { name: /blocklist/i }).click();
    await expect(rootPage.getByRole("button", { name: /block ip/i })).toBeVisible();
    await expect(rootPage.locator("td").filter({ hasText: "192.168.1.50" }).first()).toBeVisible();
  });

  test("Live dashboard shows summary", async () => {
    await rootPage.goto("/admin/rate-limits");
    await rootPage.getByRole("tab", { name: /live/i }).click();
    await expect(rootPage.getByText(/total hits/i).first()).toBeVisible();
  });

  test("Event log tab with search and export", async () => {
    await rootPage.goto("/admin/rate-limits");
    await rootPage.getByRole("tab", { name: /event log/i }).click();
    await expect(rootPage.getByRole("button", { name: /export csv/i })).toBeVisible();
    await expect(rootPage.getByPlaceholder(/search group/i)).toBeVisible();
  });
});

// Silence unused-helper lints in retry-spawned workers.
void resetMessagingConfig;
