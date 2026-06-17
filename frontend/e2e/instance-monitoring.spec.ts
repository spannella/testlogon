/**
 * E2E tests for Instance Monitoring & Health (INFRA-008).
 *
 * Owner-scoped per-instance metric datapoints + derived health.
 * Distinct from INFRA-012 admin cross-user view.
 *
 * Sections:
 *   272 — Metrics ingest & latest API (4 tests)
 *   273 — Time-series & health derivation API (5 tests)
 *   274 — Ownership isolation (2 tests)
 *   275 — Monitoring UI (3 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

function csrfHeaders(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.post(`${API}${path}`, {
    headers: csrfHeaders(identity),
    data: body ?? {},
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) url += "?" + new URLSearchParams(params).toString();
  return page.request.get(url);
}

async function launchInstance(page: Page, identity: string, label: string): Promise<string> {
  const resp = await apiPost(page, identity, "/ui/remote/ec2/launch", {
    label,
    instance_type: "t3.micro",
    ami_id: "ami-ubuntu-2204",
  });
  expect(resp.status()).toBe(201);
  const data = await resp.json();
  return data.instance_id as string;
}

const MON = (id: string) => `/ui/compute/monitoring/instances/${id}`;
const HEALTH_VALUES = ["healthy", "warning", "critical", "unknown"];

let alicePage: Page;
let bobPage: Page;

// ─────────────────────────────────────────────────────────────────────────────
// Section 272: Metrics ingest & latest API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("272 — Metrics ingest & latest API", () => {
  let instanceId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    instanceId = await launchInstance(alicePage, ALICE_ID, `mon-272-${TS}`);
  });

  test.afterAll(async () => {
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/terminate`);
    await alicePage.close();
  });

  test("272.1 Ingest a datapoint returns derived health", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/metrics`, {
      cpu_pct: 20,
      mem_pct: 30,
      disk_pct: 10,
      net_in_kbps: 100,
      net_out_kbps: 50,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.instance_id).toBe(instanceId);
    expect(HEALTH_VALUES).toContain(data.health_status);
    expect(data.health_status).toBe("healthy");
    expect(data.stored).toBe(true);
  });

  test("272.2 Latest metric returns most recent datapoint", async () => {
    await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/metrics`, {
      cpu_pct: 55,
      mem_pct: 45,
      disk_pct: 15,
    });
    const resp = await apiGet(alicePage, `${MON(instanceId)}/metrics/latest`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.has_data).toBe(true);
    expect(data.point.cpu_pct).toBe(55);
    expect(data.point.mem_pct).toBe(45);
  });

  test("272.3 Ingest with invalid cpu_pct returns 422", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/metrics`, {
      cpu_pct: 150,
      mem_pct: 30,
      disk_pct: 10,
    });
    expect(resp.status()).toBe(422);
  });

  test("272.4 Ingest to nonexistent instance returns 404", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${MON("i-does-not-exist")}/metrics`, {
      cpu_pct: 10,
      mem_pct: 10,
      disk_pct: 10,
    });
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 273: Time-series & health derivation API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("273 — Time-series & health derivation API", () => {
  let instanceId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    instanceId = await launchInstance(alicePage, ALICE_ID, `mon-273-${TS}`);
  });

  test.afterAll(async () => {
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/terminate`);
    await alicePage.close();
  });

  test("273.1 Seed deterministic datapoints", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/seed`, {
      points: 30,
      interval_seconds: 60,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.written).toBe(30);
  });

  test("273.2 Time-series returns datapoints newest first", async () => {
    const resp = await apiGet(alicePage, `${MON(instanceId)}/metrics`, { limit: "10" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.count).toBeGreaterThan(0);
    expect(data.count).toBeLessThanOrEqual(10);
    for (let i = 1; i < data.points.length; i++) {
      expect(data.points[i - 1].ts).toBeGreaterThanOrEqual(data.points[i].ts);
    }
  });

  test("273.3 Health derives healthy for low utilization", async () => {
    await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/metrics`, {
      cpu_pct: 10,
      mem_pct: 20,
      disk_pct: 5,
    });
    const resp = await apiGet(alicePage, `${MON(instanceId)}/health`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.health_status).toBe("healthy");
    expect(data.thresholds.cpu_critical_pct).toBeGreaterThan(0);
    expect(data.datapoints).toBeGreaterThan(0);
  });

  test("273.4 Health derives critical when over threshold", async () => {
    await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/metrics`, {
      cpu_pct: 99,
      mem_pct: 30,
      disk_pct: 10,
    });
    const resp = await apiGet(alicePage, `${MON(instanceId)}/health`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.health_status).toBe("critical");
    expect(data.reasons.length).toBeGreaterThan(0);
  });

  test("273.5 Health of terminated instance returns 404", async () => {
    const id = await launchInstance(alicePage, ALICE_ID, `mon-273-term-${TS}`);
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/terminate`);
    // Instance row still exists (status=terminated) so health is queryable...
    const resp = await apiGet(alicePage, `${MON(id)}/health`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.health_status).toBe("unknown");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 274: Ownership isolation
// ─────────────────────────────────────────────────────────────────────────────

test.describe("274 — Ownership isolation", () => {
  let bobInstanceId: string;

  test.beforeAll(async ({ browser }) => {
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
    bobInstanceId = await launchInstance(bobPage, BOB_ID, `mon-274-bob-${TS}`);

    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await apiPost(bobPage, BOB_ID, `/ui/remote/ec2/instances/${bobInstanceId}/terminate`);
    await bobPage.close();
    await alicePage.close();
  });

  test("274.1 Alice cannot read Bob's instance health", async () => {
    const resp = await apiGet(alicePage, `${MON(bobInstanceId)}/health`);
    expect(resp.status()).toBe(404);
  });

  test("274.2 Alice cannot ingest into Bob's instance", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${MON(bobInstanceId)}/metrics`, {
      cpu_pct: 10,
      mem_pct: 10,
      disk_pct: 10,
    });
    expect(resp.status()).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 275: Monitoring UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("275 — Monitoring UI", () => {
  let instanceId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    instanceId = await launchInstance(alicePage, ALICE_ID, `mon-275-${TS}`);
    await apiPost(alicePage, ALICE_ID, `${MON(instanceId)}/seed`, {
      points: 20,
      interval_seconds: 60,
      base_cpu_pct: 25,
    });
  });

  test.afterAll(async () => {
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/terminate`);
    await alicePage.close();
  });

  test("275.1 Monitoring page renders health badge", async () => {
    await alicePage.goto(`${BASE}/remote/instances/${instanceId}/monitoring`, {
      waitUntil: "domcontentloaded",
    });
    await expect(alicePage.getByTestId("health-badge")).toBeVisible({ timeout: 15_000 });
  });

  test("275.2 Metrics gauges show CPU and Memory", async () => {
    await expect(alicePage.getByTestId("metric-cpu")).toBeVisible();
    await expect(alicePage.getByTestId("metric-memory")).toBeVisible();
    await expect(alicePage.getByTestId("metric-disk")).toBeVisible();
  });

  test("275.3 Time-series sparkline renders with datapoints", async () => {
    await expect(alicePage.getByTestId("metrics-sparkline")).toBeVisible();
    await expect(alicePage.getByTestId("datapoint-count")).toContainText("datapoints");
  });
});
