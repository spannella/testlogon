/**
 * E2E tests for FIN-014 Payment Provider Health.
 *
 * Sections:
 *   527: Provider Status API
 *   528: Timeline, Error Drilldown, Uptime & Incidents API
 *   529: Provider Configuration API (root-only updates)
 *   530: Provider Toggle API (root-only)
 *   531: Edge cases
 *
 * Auth: role-bearing JWT cookies from e2e_admin_session_setup.py.
 *   root          – role=root
 *   charlie_admin – role=admin
 *   alice         – role=user (403 assertions)
 *
 * Health datapoints are seeded directly into the payment_provider_health
 * DDB table for deterministic status (stripe healthy, paypal degraded),
 * plus 3 stripe incidents (2 resolved "down", 1 ongoing).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppSeedPaymentHealth } from "./helpers/cpp-seed-payment-health";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const PREFIX = "ui/admin/payment-health";

// ─── Session bootstrap ─────────────────────────────────────────────────────

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
  return page;
}

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

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

// ─── DDB seed helper ───────────────────────────────────────────────────────

function seedHealthData(): void {
  if (usingCpp()) {
    cppSeedPaymentHealth();
    return;
  }
  execSync(
    `python3 -c "
import boto3, os, time, uuid
from pathlib import Path
env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('PAYMENT_PROVIDER_HEALTH_TABLE_NAME','payment_provider_health'))
now = int(time.time())
def dp(provider, success, latency, etype, ts):
    return {'pk':f'PROVIDER#{provider}','sk':f'DP#{ts}#{uuid.uuid4().hex}','GSI1PK':f'PROVIDER#{provider}','GSI1SK':ts,'ts':ts,'success':success,'latency_ms':latency,'error_type':etype,'op':'webhook'}
# stripe: healthy (100 success, 0 failure)
for i in range(100):
    tbl.put_item(Item=dp('stripe', True, 120 + (i%20), '', now - i*60))
# paypal: degraded (~10% failure -> 1000 bps)
for i in range(90):
    tbl.put_item(Item=dp('paypal', True, 400, '', now - i*60))
for i in range(10):
    tbl.put_item(Item=dp('paypal', False, 900, 'gateway_timeout', now - i*70))
# stripe incidents: 2 resolved down + 1 ongoing degraded
incs = [
    {'started': now - 86400, 'ended': now - 82800, 'status':'down', 'peak':3000, 'aff':50},
    {'started': now - 43200, 'ended': now - 41400, 'status':'down', 'peak':2800, 'aff':30},
    {'started': now - 3600, 'ended': None, 'status':'degraded', 'peak':700, 'aff':5},
]
for inc in incs:
    iid = uuid.uuid4().hex
    item = {'pk':'PROVIDER#stripe','sk':f'INCIDENT#{iid}','GSI1PK':'INCIDENTS#ALL','GSI1SK':inc['started'],'incident_id':iid,'provider':'stripe','started_at':inc['started'],'status':inc['status'],'peak_error_rate':inc['peak'],'affected_webhooks':inc['aff']}
    if inc['ended'] is not None:
        item['ended_at'] = inc['ended']
    tbl.put_item(Item=item)
print('seeded')
"`,
    { cwd: REPO_ROOT, timeout: 30_000 },
  );
}

// ─── 527. Provider Status API ────────────────────────────────────────────────

test.describe("527. Payment provider status API", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedHealthData();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("admin retrieves all provider statuses", async () => {
    const r = await apiGet(rootPage, PREFIX);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<Record<string, unknown>>;
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBe(3);
    for (const p of data) {
      expect(typeof p.provider).toBe("string");
      expect(typeof p.status).toBe("string");
      expect(typeof p.enabled).toBe("boolean");
      expect(typeof p.success_rate).toBe("number");
      expect(typeof p.avg_latency_ms).toBe("number");
    }
    const stripe = data.find((p) => p.provider === "stripe")!;
    expect(stripe.status).toBe("healthy");
    const paypal = data.find((p) => p.provider === "paypal")!;
    expect(paypal.status).toBe("degraded");
  });

  test("single provider status returns details", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/stripe`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.provider).toBe("stripe");
    expect(typeof data.total_success).toBe("number");
    expect(typeof data.total_failure).toBe("number");
    expect(typeof data.last_check_at).toBe("number");
    expect((data.total_success as number)).toBeGreaterThan(0);
  });

  test("unknown provider returns 404", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/unknown`);
    expect(r.status()).toBe(404);
  });

  test("non-admin cannot access provider health", async () => {
    const r = await apiGet(alicePage, PREFIX);
    expect(r.status()).toBe(403);
  });
});

// ─── 528. Timeline, errors, uptime & incidents API ────────────────────────────

test.describe("528. Timeline & error drilldown API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedHealthData();
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("timeline returns hourly health data", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/stripe/timeline`, { hours: "24" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { data: Array<Record<string, unknown>> };
    expect(Array.isArray(data.data)).toBe(true);
    expect(data.data.length).toBeGreaterThan(0);
    const b = data.data[0];
    expect(typeof b.hour).toBe("string");
    expect(typeof b.success).toBe("number");
    expect(typeof b.failure).toBe("number");
  });

  test("error drilldown shows error types", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/paypal/errors`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      error_types: Record<string, number>;
      recent_failures: unknown[];
    };
    expect(typeof data.error_types).toBe("object");
    expect(Array.isArray(data.recent_failures)).toBe(true);
    expect(data.error_types["gateway_timeout"]).toBeGreaterThan(0);
  });

  test("uptime report returns percentage", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/stripe/uptime`, { days: "30" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(data.uptime_pct).toBeGreaterThanOrEqual(0);
    expect(data.uptime_pct).toBeLessThanOrEqual(100);
    expect(data.total_incidents).toBeGreaterThanOrEqual(0);
  });

  test("incident list returns provider incidents", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/incidents`, { provider: "stripe" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Array<Record<string, unknown>>;
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(3);
    expect(data.every((i) => i.provider === "stripe")).toBe(true);
  });
});

// ─── 529. Provider Configuration API ──────────────────────────────────────────

test.describe("529. Provider configuration API", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await charliePage?.close();
  });

  test("admin retrieves provider config", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/stripe/config`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(typeof data.alert_error_rate_threshold).toBe("number");
    expect(typeof data.alert_latency_threshold_ms).toBe("number");
  });

  test("root updates alert thresholds", async () => {
    const r = await apiPatch(rootPage, "root", `${PREFIX}/stripe/config`, {
      alert_error_rate_threshold: 1000,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.alert_error_rate_threshold).toBe(1000);

    const r2 = await apiGet(rootPage, `${PREFIX}/stripe/config`);
    const data2 = (await r2.json()) as Record<string, unknown>;
    expect(data2.alert_error_rate_threshold).toBe(1000);
  });

  test("non-root cannot update config", async () => {
    const r = await apiPatch(charliePage, "charlie_admin", `${PREFIX}/stripe/config`, {
      alert_error_rate_threshold: 800,
    });
    expect(r.status()).toBe(403);
  });
});

// ─── 530. Provider Toggle API ─────────────────────────────────────────────────

test.describe("530. Provider toggle API", () => {
  let rootPage: Page;
  let charliePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
  });

  test.afterAll(async () => {
    // restore enabled
    try {
      await apiPost(rootPage, "root", `${PREFIX}/paypal/toggle`, { enabled: true });
    } catch { /* ignore */ }
    await rootPage?.close();
    await charliePage?.close();
  });

  test("root disables a provider", async () => {
    const r = await apiPost(rootPage, "root", `${PREFIX}/paypal/toggle`, {
      enabled: false,
      reason: "maintenance",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.enabled).toBe(false);
    expect(data.reason).toBe("maintenance");
  });

  test("root re-enables a provider", async () => {
    const r = await apiPost(rootPage, "root", `${PREFIX}/paypal/toggle`, { enabled: true });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.enabled).toBe(true);
  });

  test("non-root cannot toggle provider", async () => {
    const r = await apiPost(charliePage, "charlie_admin", `${PREFIX}/stripe/toggle`, {
      enabled: false,
    });
    expect(r.status()).toBe(403);
  });
});

// ─── 531. Edge cases ──────────────────────────────────────────────────────────

test.describe("531. Payment provider health edge cases", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    rootPage = await newIdentityPage(browser, "root");
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("timeline with very short window may return empty data array", async () => {
    // 1-hour window far narrower; ccbill has no seeded data.
    const r = await apiGet(rootPage, `${PREFIX}/ccbill/timeline`, { hours: "1" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { data: unknown[] };
    expect(Array.isArray(data.data)).toBe(true);
  });

  test("uptime for provider with no down incidents is 100%", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/ccbill/uptime`, { days: "30" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(data.uptime_pct).toBe(100.0);
  });

  test("error drilldown empty when no errors", async () => {
    const r = await apiGet(rootPage, `${PREFIX}/ccbill/errors`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as {
      error_types: Record<string, number>;
      recent_failures: unknown[];
    };
    expect(Object.keys(data.error_types).length).toBe(0);
    expect(data.recent_failures.length).toBe(0);
  });

  test("disabling an already-disabled provider is idempotent", async () => {
    const r1 = await apiPost(rootPage, "root", `${PREFIX}/ccbill/toggle`, {
      enabled: false,
      reason: "test",
    });
    expect(r1.status()).toBe(200);
    const r2 = await apiPost(rootPage, "root", `${PREFIX}/ccbill/toggle`, {
      enabled: false,
      reason: "test again",
    });
    expect(r2.status()).toBe(200);
    const data2 = (await r2.json()) as Record<string, unknown>;
    expect(data2.enabled).toBe(false);
    // restore
    await apiPost(rootPage, "root", `${PREFIX}/ccbill/toggle`, { enabled: true });
  });

  test("incident create and resolve sets ended_at", async () => {
    const create = await apiPost(rootPage, "root", `${PREFIX}/paypal/incidents`, {
      status: "down",
      peak_error_rate: 3000,
      affected_webhooks: 12,
    });
    expect(create.status()).toBe(200);
    const inc = (await create.json()) as Record<string, unknown>;
    expect(inc.ended_at).toBeNull();
    const incidentId = inc.incident_id as string;

    const resolve = await apiPost(
      rootPage,
      "root",
      `${PREFIX}/paypal/incidents/${incidentId}/resolve`,
    );
    expect(resolve.status()).toBe(200);
    const resolved = (await resolve.json()) as Record<string, unknown>;
    expect(typeof resolved.ended_at).toBe("number");
    expect((resolved.ended_at as number)).toBeGreaterThan(0);
  });
});
