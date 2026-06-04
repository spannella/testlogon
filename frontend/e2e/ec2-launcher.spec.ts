/**
 * E2E tests for EC2 Instance Launcher (INFRA-003).
 *
 * Sections:
 *   248 — Instance Type & AMI API (3 tests)
 *   249 — Launch & Lifecycle API (6 tests)
 *   250 — Instance Limits & Validation (4 tests)
 *   251 — Instance List & Filter (4 tests)
 *   252 — EC2 Launcher UI (3 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();

// ─── Session bootstrap ───────────────────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

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

// ─── API helpers ──────────────────────────────────────────────────────────────

function csrfHeaders(identity: string) {
  return { "x-csrf-token": getSessions()[identity].csrf_token };
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.post(`${API}${path}`, {
    headers: csrfHeaders(identity),
    data: body,
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) {
    url += "?" + new URLSearchParams(params).toString();
  }
  return page.request.get(url);
}

// ─── Test state ──────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;

// Track launched instance IDs for cleanup
const launchedIds: string[] = [];

// ─────────────────────────────────────────────────────────────────────────────
// Section 248: Instance Type & AMI API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("248 — Instance Type & AMI API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("248.1 List instance types returns allowlist", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/ec2/instance-types");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.types).toBeDefined();
    expect(data.types.length).toBe(4);
    for (const t of data.types) {
      expect(t.instance_type).toBeTruthy();
      expect(t.vcpu).toBeGreaterThan(0);
      expect(t.memory_gb).toBeGreaterThan(0);
      expect(t.cost_cents_per_min).toBeGreaterThan(0);
    }
  });

  test("248.2 List AMIs returns curated list", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/ec2/amis");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.amis).toBeDefined();
    expect(data.amis.length).toBeGreaterThanOrEqual(3);
    for (const a of data.amis) {
      expect(a.ami_id).toBeTruthy();
      expect(a.name).toBeTruthy();
      expect(a.os_type).toBeTruthy();
      expect(a.username).toBeTruthy();
    }
  });

  test("248.3 Unknown instance type on launch returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: "bad-type-test",
      instance_type: "m5.24xlarge",
      ami_id: "ami-ubuntu-2204",
    });
    expect(resp.status()).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 249: Launch & Lifecycle API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("249 — Launch & Lifecycle API", () => {
  let instanceId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    // Terminate all instances we launched
    for (const id of launchedIds) {
      try {
        await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/terminate`);
      } catch (_) { /* ignore */ }
    }
    await alicePage.close();
  });

  test("249.1 Alice launches a t3.micro Ubuntu instance", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: `e2e-test-${TS}`,
      instance_type: "t3.micro",
      ami_id: "ami-ubuntu-2204",
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.status).toBe("running");
    expect(data.instance_id).toBeTruthy();
    expect(data.ec2_instance_id).toBeTruthy();
    expect(data.public_ip).toBeTruthy();
    expect(data.ami_name).toBe("Ubuntu 22.04 LTS");
    expect(data.instance_type).toBe("t3.micro");
    instanceId = data.instance_id;
    launchedIds.push(instanceId);
  });

  test("249.2 Get instance returns the launched instance", async () => {
    const resp = await apiGet(alicePage, `/ui/remote/ec2/instances/${instanceId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.instance_id).toBe(instanceId);
    expect(data.status).toBe("running");
    expect(data.label).toBe(`e2e-test-${TS}`);
  });

  test("249.3 Alice stops a running instance", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/stop`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("stopped");
    expect(data.stopped_at).toBeGreaterThan(0);
  });

  test("249.4 Alice starts a stopped instance", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/start`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("running");
  });

  test("249.5 Alice reboots a running instance", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/reboot`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("running");
    expect(data.last_activity_at).toBeGreaterThan(0);
  });

  test("249.6 Alice terminates an instance", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${instanceId}/terminate`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("terminated");
    expect(data.terminated_at).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 250: Instance Limits & Validation
// ─────────────────────────────────────────────────────────────────────────────

test.describe("250 — Instance Limits & Validation", () => {
  const limitIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Clean slate: terminate any active instances left over from earlier
    // sections or prior runs. The launch limit only counts active states
    // (running/stopped/launching/stopping), so leftover active instances from
    // a previously-failed run would push 250.1 over the limit on the very
    // first launch. Terminate them so 250.1 can launch up to the limit.
    const listResp = await apiGet(alicePage, "/ui/remote/ec2/instances");
    if (listResp.ok()) {
      const body = await listResp.json();
      for (const inst of body.instances || []) {
        if (["running", "stopped", "launching", "stopping"].includes(inst.status)) {
          try {
            await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${inst.instance_id}/terminate`);
          } catch (_) { /* ignore */ }
        }
      }
    }
  });

  test.afterAll(async () => {
    for (const id of limitIds) {
      try {
        await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/terminate`);
      } catch (_) { /* ignore */ }
    }
    await alicePage.close();
  });

  test("250.1 Alice cannot exceed max instances", async () => {
    // Launch up to the limit (5 by default)
    for (let i = 0; i < 5; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
        label: `limit-test-${TS}-${i}`,
        instance_type: "t3.micro",
        ami_id: "ami-ubuntu-2204",
      });
      expect(resp.status()).toBe(201);
      const data = await resp.json();
      limitIds.push(data.instance_id);
    }

    // 6th should fail
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: `limit-test-${TS}-overflow`,
      instance_type: "t3.micro",
      ami_id: "ami-ubuntu-2204",
    });
    expect(resp.status()).toBe(409);
    const data = await resp.json();
    expect(data.detail).toContain("active instances allowed");
  });

  test("250.2 Cannot stop a terminated instance", async () => {
    // Terminate one
    const id = limitIds[0];
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/terminate`);

    // Try to stop it
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/stop`);
    expect(resp.status()).toBe(409);
  });

  test("250.3 Cannot start a running instance", async () => {
    const id = limitIds[1]; // still running
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/start`);
    expect(resp.status()).toBe(409);
  });

  test("250.4 Unknown AMI on launch returns 400", async () => {
    // Need to free a slot first (terminate one)
    const tId = limitIds[2];
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${tId}/terminate`);

    const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: "bad-ami-test",
      instance_type: "t3.micro",
      ami_id: "ami-nonexistent-99",
    });
    expect(resp.status()).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 251: Instance List & Filter
// ─────────────────────────────────────────────────────────────────────────────

test.describe("251 — Instance List & Filter", () => {
  const filterIds: string[] = [];

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);

    // Launch 2 instances for Alice
    for (let i = 0; i < 2; i++) {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
        label: `filter-test-${TS}-${i}`,
        instance_type: "t3.small",
        ami_id: "ami-ubuntu-2404",
      });
      const data = await resp.json();
      filterIds.push(data.instance_id);
    }
  });

  test.afterAll(async () => {
    for (const id of filterIds) {
      try {
        await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${id}/terminate`);
      } catch (_) { /* ignore */ }
    }
    await alicePage.close();
    await bobPage.close();
  });

  test("251.1 List instances returns user instances", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/ec2/instances");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.instances.length).toBeGreaterThanOrEqual(2);
    // Our filter-test instances should be present
    const ids = data.instances.map((i: any) => i.instance_id);
    for (const id of filterIds) {
      expect(ids).toContain(id);
    }
  });

  test("251.2 Filter by status", async () => {
    // Terminate one
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${filterIds[0]}/terminate`);

    const resp = await apiGet(alicePage, "/ui/remote/ec2/instances", { status: "running" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    // filterIds[0] should NOT be in running list
    const ids = data.instances.map((i: any) => i.instance_id);
    expect(ids).not.toContain(filterIds[0]);
    // filterIds[1] should be running
    expect(ids).toContain(filterIds[1]);
  });

  test("251.3 List sorted by created_at descending", async () => {
    const resp = await apiGet(alicePage, "/ui/remote/ec2/instances");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const timestamps = data.instances.map((i: any) => Number(i.created_at));
    for (let i = 0; i < timestamps.length - 1; i++) {
      expect(timestamps[i]).toBeGreaterThanOrEqual(timestamps[i + 1]);
    }
  });

  test("251.4 Alice cannot see Bob's instances", async () => {
    // Bob launches an instance
    const resp = await apiPost(bobPage, BOB_ID, "/ui/remote/ec2/launch", {
      label: `bob-instance-${TS}`,
      instance_type: "t3.micro",
      ami_id: "ami-ubuntu-2204",
    });
    expect(resp.status()).toBe(201);
    const bobData = await resp.json();
    const bobInstanceId = bobData.instance_id;

    // Alice should NOT see Bob's instance
    const aliceResp = await apiGet(alicePage, "/ui/remote/ec2/instances");
    const aliceData = await aliceResp.json();
    const aliceIds = aliceData.instances.map((i: any) => i.instance_id);
    expect(aliceIds).not.toContain(bobInstanceId);

    // Cleanup Bob's instance
    await apiPost(bobPage, BOB_ID, `/ui/remote/ec2/instances/${bobInstanceId}/terminate`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 252: EC2 Launcher UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("252 — EC2 Launcher UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("252.1 Ec2LauncherPage renders with heading and launch button", async () => {
    await alicePage.goto(`${BASE}/remote/ec2`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("EC2 Instances")).toBeVisible();
    await expect(alicePage.getByTestId("launch-btn")).toBeVisible();
  });

  test("252.2 Launch dialog shows instance types and AMIs", async () => {
    await alicePage.goto(`${BASE}/remote/ec2`, { waitUntil: "domcontentloaded" });
    await alicePage.getByTestId("launch-btn").click();
    await expect(alicePage.getByText("Launch EC2 Instance")).toBeVisible();
    await expect(alicePage.getByTestId("launch-label")).toBeVisible();
    await expect(alicePage.getByTestId("launch-type")).toBeVisible();
    await expect(alicePage.getByTestId("launch-ami")).toBeVisible();
    await expect(alicePage.getByTestId("launch-submit")).toBeVisible();
  });

  test("252.3 Launch from dialog creates instance", async () => {
    await alicePage.goto(`${BASE}/remote/ec2`, { waitUntil: "domcontentloaded" });
    await alicePage.getByTestId("launch-btn").click();
    await expect(alicePage.getByText("Launch EC2 Instance")).toBeVisible();

    // Fill label
    await alicePage.getByTestId("launch-label").fill(`ui-test-${TS}`);

    // Select instance type
    await alicePage.getByTestId("launch-type").click();
    await alicePage.getByRole("option", { name: /t3\.micro/ }).click();

    // Select AMI
    await alicePage.getByTestId("launch-ami").click();
    await alicePage.getByRole("option", { name: /Ubuntu 22\.04/ }).click();

    // Submit
    await alicePage.getByTestId("launch-submit").click();

    // Wait for toast or table update
    await expect(alicePage.getByText(`ui-test-${TS}`)).toBeVisible({ timeout: 10_000 });
  });
});
