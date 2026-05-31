/**
 * E2E tests for Security Groups & Network Rules (INFRA-009).
 *
 * Sections:
 *   270 — Security Group CRUD API (5 tests)
 *   271 — Rule Management API (5 tests)
 *   272 — Security Groups UI (5 tests)
 *   273 — Rule Validation Edge Cases (7 tests)
 *   274 — SG Launch Integration & Multi-User Isolation (6 tests)
 *
 * Auth: Alice & Bob session cookies (from e2e_admin_session_setup.py).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const API = BASE;
const ALICE_ID = "alice";
const BOB_ID = "bob";
const TS = Date.now();
const SG_BASE = "/ui/compute/security-groups";

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
  return page.request.post(`${API}${path}`, { headers: csrfHeaders(identity), data: body });
}
async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  return page.request.patch(`${API}${path}`, { headers: csrfHeaders(identity), data: body });
}
async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${API}${path}`, { headers: csrfHeaders(identity) });
}
async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  let url = `${API}${path}`;
  if (params) url += "?" + new URLSearchParams(params).toString();
  return page.request.get(url);
}

async function getDefaultSgId(page: Page): Promise<string> {
  const resp = await apiGet(page, SG_BASE);
  const data = await resp.json();
  const def = data.security_groups.find((s: any) => s.is_default);
  return def.sg_id;
}

let alicePage: Page;
let bobPage: Page;

// ─────────────────────────────────────────────────────────────────────────────
// Section 270: Security Group CRUD API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("270 — Security Group CRUD API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("270.1 Default SG auto-created on first list", async () => {
    const resp = await apiGet(alicePage, SG_BASE);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const def = data.security_groups.find((s: any) => s.is_default);
    expect(def).toBeTruthy();
    expect(def.rules.length).toBeGreaterThanOrEqual(3);
    const ssh = def.rules.find((r: any) => r.port_from === 22);
    expect(ssh.source).toBe("platform_only");
  });

  test("270.2 Create custom SG", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, SG_BASE, {
      name: `web-${TS}`,
      description: "web rules",
      rules: [
        { protocol: "tcp", port_from: 80, port_to: 80, source: "0.0.0.0/0", direction: "inbound", description: "HTTP" },
        { protocol: "tcp", port_from: 443, port_to: 443, source: "0.0.0.0/0", direction: "inbound", description: "HTTPS" },
      ],
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.is_default).toBe(false);
    expect(data.rules.length).toBe(2);
    expect(data.sg_id).toBeTruthy();
  });

  test("270.3 Update SG name", async () => {
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `upd-${TS}`, rules: [] });
    const sg = await create.json();
    const resp = await apiPatch(alicePage, ALICE_ID, `${SG_BASE}/${sg.sg_id}`, { name: `renamed-${TS}` });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.name).toBe(`renamed-${TS}`);
  });

  test("270.4 Delete custom SG", async () => {
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `del-${TS}`, rules: [] });
    const sg = await create.json();
    const del = await apiDelete(alicePage, ALICE_ID, `${SG_BASE}/${sg.sg_id}`);
    expect(del.status()).toBe(200);
    const get = await apiGet(alicePage, `${SG_BASE}/${sg.sg_id}`);
    expect(get.status()).toBe(404);
  });

  test("270.5 Cannot delete default SG", async () => {
    const defId = await getDefaultSgId(alicePage);
    const resp = await apiDelete(alicePage, ALICE_ID, `${SG_BASE}/${defId}`);
    expect(resp.status()).toBe(409);
    const data = await resp.json();
    expect(String(data.detail).toLowerCase()).toContain("default");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 271: Rule Management API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("271 — Rule Management API", () => {
  let sgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `rules-${TS}`, rules: [] });
    sgId = (await create.json()).sg_id;
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("271.6 Add inbound TCP rule", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 8080, port_to: 8080, source: "10.0.0.0/8", direction: "inbound", description: "dev",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const r = data.rules.find((x: any) => x.port_from === 8080);
    expect(r).toBeTruthy();
    expect(r.rule_id).toBeTruthy();
  });

  test("271.7 Add platform_only rule", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 3000, port_to: 3000, source: "platform_only", direction: "inbound",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.rules.some((r: any) => r.source === "platform_only" && r.port_from === 3000)).toBe(true);
  });

  test("271.8 Remove rule", async () => {
    const add = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "udp", port_from: 5353, port_to: 5353, source: "10.0.0.0/8", direction: "inbound",
    });
    const sg = await add.json();
    const ruleId = sg.rules.find((r: any) => r.port_from === 5353).rule_id;
    const del = await apiDelete(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules/${ruleId}`);
    expect(del.status()).toBe(200);
    const data = await del.json();
    expect(data.rules.some((r: any) => r.rule_id === ruleId)).toBe(false);
  });

  test("271.9 Reject invalid CIDR", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 9090, port_to: 9090, source: "not-a-cidr", direction: "inbound",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(String(data.detail).toLowerCase()).toContain("cidr");
  });

  test("271.10 Warn on 0.0.0.0/0 SSH", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 22, port_to: 22, source: "0.0.0.0/0", direction: "inbound",
    });
    expect(resp.status()).toBe(400);
    const data = await resp.json();
    expect(String(data.detail).toLowerCase()).toContain("ssh");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 272: Security Groups UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("272 — Security Groups UI", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("272.11 SecurityGroupsPage shows default SG", async () => {
    await alicePage.goto(`${BASE}/remote/security-groups`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId("security-groups-page")).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.getByTestId("sg-default-badge").first()).toBeVisible();
  });

  test("272.12 Create SG via dialog", async () => {
    await alicePage.goto(`${BASE}/remote/security-groups`, { waitUntil: "domcontentloaded" });
    await alicePage.getByTestId("create-sg-button").click();
    await expect(alicePage.getByTestId("create-sg-dialog")).toBeVisible();
    await alicePage.getByTestId("sg-name-input").fill(`ui-sg-${TS}`);
    await alicePage.getByTestId("sg-create-submit").click();
    await expect(alicePage.getByText(`ui-sg-${TS}`)).toBeVisible({ timeout: 10_000 });
  });

  test("272.13 Add rule via dialog", async () => {
    await alicePage.goto(`${BASE}/remote/security-groups`, { waitUntil: "domcontentloaded" });
    // Add a rule to the default SG (always present, first card)
    const defId = await getDefaultSgId(alicePage);
    await alicePage.reload({ waitUntil: "domcontentloaded" });
    await alicePage.getByTestId(`add-rule-${defId}`).click();
    await expect(alicePage.getByTestId("add-rule-dialog")).toBeVisible();
    await alicePage.getByTestId("rule-port-from").fill("8081");
    await alicePage.getByTestId("rule-port-to").fill("8081");
    await alicePage.getByTestId("rule-source").fill("10.0.0.0/8");
    await alicePage.getByTestId("rule-submit").click();
    await expect(alicePage.getByText("8081").first()).toBeVisible({ timeout: 10_000 });
  });

  test("272.14 Platform Only shortcut button works", async () => {
    await alicePage.goto(`${BASE}/remote/security-groups`, { waitUntil: "domcontentloaded" });
    const defId = await getDefaultSgId(alicePage);
    await alicePage.reload({ waitUntil: "domcontentloaded" });
    await alicePage.getByTestId(`add-rule-${defId}`).click();
    await alicePage.getByTestId("source-platform-button").click();
    await expect(alicePage.getByTestId("rule-source")).toHaveValue("platform_only");
  });

  test("272.15 Delete rule removes from table", async () => {
    // Create a fresh SG with a single rule via API, then delete it in the UI
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, {
      name: `del-rule-${TS}`,
      rules: [{ protocol: "tcp", port_from: 7777, port_to: 7777, source: "10.0.0.0/8", direction: "inbound" }],
    });
    const sg = await create.json();
    const ruleId = sg.rules[0].rule_id;
    await alicePage.goto(`${BASE}/remote/security-groups`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByTestId(`rule-row-${ruleId}`)).toBeVisible({ timeout: 10_000 });
    await alicePage.getByTestId(`delete-rule-${ruleId}`).click();
    await expect(alicePage.getByTestId(`rule-row-${ruleId}`)).toHaveCount(0, { timeout: 10_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 273: Rule Validation Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

test.describe("273 — Rule Validation Edge Cases", () => {
  let sgId: string;
  let refSgId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `edge-${TS}`, rules: [] });
    sgId = (await create.json()).sg_id;
    const ref = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `ref-${TS}`, rules: [] });
    refSgId = (await ref.json()).sg_id;
  });
  test.afterAll(async () => {
    await alicePage.close();
  });

  test("273.16 ICMP rule ignores port range", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "icmp", port_from: 0, port_to: 0, source: "10.0.0.0/8", direction: "inbound",
    });
    expect(resp.status()).toBe(200);
  });

  test("273.17 Protocol all ignores port range", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "all", port_from: 0, port_to: 0, source: "192.168.0.0/16", direction: "outbound",
    });
    expect(resp.status()).toBe(200);
  });

  test("273.18 Port range 0-65535 accepted for TCP", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 0, port_to: 65535, source: "10.1.0.0/16", direction: "inbound",
    });
    expect(resp.status()).toBe(200);
  });

  test("273.19 Source sg:{id} accepted for SG reference", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 6379, port_to: 6379, source: `sg:${refSgId}`, direction: "inbound",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.rules.some((r: any) => r.source === `sg:${refSgId}`)).toBe(true);
  });

  test("273.20 Rule with empty description accepted", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${sgId}/rules`, {
      protocol: "tcp", port_from: 4040, port_to: 4040, source: "10.2.0.0/16", direction: "inbound", description: "",
    });
    expect(resp.status()).toBe(200);
  });

  test("273.21 51st rule rejected", async () => {
    test.setTimeout(120_000);
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `bulk-${TS}`, rules: [] });
    const bulkId = (await create.json()).sg_id;
    let lastStatus = 0;
    for (let i = 0; i < 50; i++) {
      const r = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${bulkId}/rules`, {
        protocol: "tcp", port_from: 10000 + i, port_to: 10000 + i, source: "10.0.0.0/8", direction: "inbound",
      });
      lastStatus = r.status();
      expect(lastStatus).toBe(200);
    }
    const over = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${bulkId}/rules`, {
      protocol: "tcp", port_from: 20000, port_to: 20000, source: "10.0.0.0/8", direction: "inbound",
    });
    expect(over.status()).toBe(409);
  });

  test("273.22 platform_only resolves to non-empty CIDR list", async () => {
    const defId = await getDefaultSgId(alicePage);
    const resp = await apiGet(alicePage, `${SG_BASE}/${defId}/effective-rules`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const platRule = data.rules.find((r: any) => r.source === "platform_only");
    expect(platRule).toBeTruthy();
    expect(platRule.resolved_sources.length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 274: SG Launch Integration & Multi-User Isolation
// ─────────────────────────────────────────────────────────────────────────────

test.describe("274 — SG Launch Integration & Multi-User Isolation", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
  });
  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("274.23 Launch with custom SG associates instance", async () => {
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `launch-${TS}`, rules: [] });
    const sgId = (await create.json()).sg_id;
    const launch = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: `sg-launch-${TS}`, instance_type: "t3.micro", ami_id: "ami-ubuntu-2204", security_group_id: sgId,
    });
    expect(launch.status()).toBe(201);
    const inst = await launch.json();
    const sgResp = await apiGet(alicePage, `${SG_BASE}/${sgId}`);
    const sg = await sgResp.json();
    expect(sg.associated_instances).toContain(inst.instance_id);
    // cleanup
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${inst.instance_id}/terminate`);
  });

  test("274.24 Launch without SG auto-creates default", async () => {
    const launch = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: `no-sg-${TS}`, instance_type: "t3.micro", ami_id: "ami-ubuntu-2204",
    });
    expect(launch.status()).toBe(201);
    const inst = await launch.json();
    const defId = await getDefaultSgId(alicePage);
    expect(defId).toBeTruthy();
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${inst.instance_id}/terminate`);
  });

  test("274.25 Alice cannot view Bob's SGs", async () => {
    const bobCreate = await apiPost(bobPage, BOB_ID, SG_BASE, { name: `bob-secret-${TS}`, rules: [] });
    const bobSg = await bobCreate.json();
    const aliceList = await apiGet(alicePage, SG_BASE);
    const aliceData = await aliceList.json();
    expect(aliceData.security_groups.some((s: any) => s.sg_id === bobSg.sg_id)).toBe(false);
  });

  test("274.26 Alice cannot add rule to Bob's SG", async () => {
    const bobCreate = await apiPost(bobPage, BOB_ID, SG_BASE, { name: `bob-iso-${TS}`, rules: [] });
    const bobSg = await bobCreate.json();
    const resp = await apiPost(alicePage, ALICE_ID, `${SG_BASE}/${bobSg.sg_id}/rules`, {
      protocol: "tcp", port_from: 80, port_to: 80, source: "10.0.0.0/8", direction: "inbound",
    });
    // Alice's user_sub cannot see Bob's SG → treated as not found
    expect(resp.status()).toBe(404);
  });

  test("274.27 Delete SG with associated instance fails", async () => {
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `inuse-${TS}`, rules: [] });
    const sgId = (await create.json()).sg_id;
    const launch = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: `inuse-launch-${TS}`, instance_type: "t3.micro", ami_id: "ami-ubuntu-2204", security_group_id: sgId,
    });
    const inst = await launch.json();
    const del = await apiDelete(alicePage, ALICE_ID, `${SG_BASE}/${sgId}`);
    expect(del.status()).toBe(409);
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${inst.instance_id}/terminate`);
  });

  test("274.28 Delete SG succeeds after terminating instance", async () => {
    const create = await apiPost(alicePage, ALICE_ID, SG_BASE, { name: `free-${TS}`, rules: [] });
    const sgId = (await create.json()).sg_id;
    const launch = await apiPost(alicePage, ALICE_ID, "/ui/remote/ec2/launch", {
      label: `free-launch-${TS}`, instance_type: "t3.micro", ami_id: "ami-ubuntu-2204", security_group_id: sgId,
    });
    const inst = await launch.json();
    await apiPost(alicePage, ALICE_ID, `/ui/remote/ec2/instances/${inst.instance_id}/terminate`);
    const del = await apiDelete(alicePage, ALICE_ID, `${SG_BASE}/${sgId}`);
    expect(del.status()).toBe(200);
  });
});
