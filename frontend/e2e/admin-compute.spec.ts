/**
 * E2E tests for the Admin Compute Dashboard (INFRA-012).
 *
 * Section 280: Admin instance/pod visibility API
 * Section 281: Force-terminate & alerts API
 * Section 282: Quota management API
 * Section 283: Platform spending & stats API + dashboard render
 *
 * Auth: root (ROOT) + charlie_admin (ADMIN) for admin endpoints; alice (USER)
 * to assert 403. Quota set/delete is root-only (charlie_admin gets 403).
 *
 * Cookie auth: each identity gets a pre-cookie'd page. Non-GET requests carry
 * the x-csrf-token header.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

interface AdminSessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, AdminSessionData> | null = null;
function getSessions(): Record<string, AdminSessionData> {
  if (!_sessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.context().addCookies(sessions[identity].cookies as any);
  return page;
}

type Body = Record<string, unknown> | undefined;

async function apiPost(page: Page, identity: string, path: string, body?: Body) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPut(page: Page, identity: string, path: string, body?: Body) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

/** Launch an EC2 instance as the given identity. Returns the instance_id. */
async function launchInstance(page: Page, identity: string, instanceType = "t3.micro"): Promise<string> {
  const r = await apiPost(page, identity, "ui/remote/ec2/launch", {
    label: `e2e-admin-${Date.now()}`,
    instance_type: instanceType,
    ami_id: "ami-ubuntu-2204",
  });
  const data = (await r.json()) as Record<string, unknown>;
  return data.instance_id as string;
}

/** Launch a K8s pod as the given identity. Returns the pod_id. */
async function launchPod(page: Page, identity: string): Promise<string> {
  const r = await apiPost(page, identity, "ui/remote/k8s/launch", {
    label: `e2e-admin-pod-${Date.now()}`,
    image: "ubuntu-ssh",
    preset: "small",
  });
  const data = (await r.json()) as Record<string, unknown>;
  return data.pod_id as string;
}

/** Remove any custom quota for a user so launches aren't blocked. */
function clearQuota(userSub: string): void {
  execSync(
    `python3 -c "
import boto3, os
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('COMPUTE_QUOTAS_TABLE_NAME','compute_quotas'))
tbl.delete_item(Key={'user_sub':'${userSub}'})
print('cleared quota')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

/** Seed a compute_billing tick + monthly total for a user in the current month. */
function seedBilling(userSub: string, resourceType: string, amountCents: number): void {
  execSync(
    `python3 -c "
import boto3, os, uuid, time
from datetime import datetime, timezone
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table(os.environ.get('COMPUTE_BILLING_TABLE_NAME','compute_billing'))
ts = int(time.time())
mk = datetime.now(timezone.utc).strftime('%Y-%m')
eid = 'e_' + uuid.uuid4().hex[:8]
tbl.put_item(Item={'user_sub':'${userSub}','sk':f'TICK#{ts}#{eid}','entry_id':eid,'resource_type':'${resourceType}','resource_id':'r_'+uuid.uuid4().hex[:6],'amount_cents':${amountCents},'created_at':ts,'month_key':mk})
tbl.update_item(Key={'user_sub':'${userSub}','sk':f'MONTH#{mk}'}, UpdateExpression='SET current_month_total_cents = if_not_exists(current_month_total_cents,:z)+:a, month_key=:mk', ExpressionAttributeValues={':z':0,':a':${amountCents},':mk':mk})
print('seeded billing')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

// ─── 280. Admin instance/pod visibility API ──────────────────────────────────

test.describe("280. Admin compute visibility API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let instanceId: string;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    clearQuota(ALICE_ID);
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    instanceId = await launchInstance(alicePage, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("admin lists all instances across users", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/instances");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { instances: Array<Record<string, unknown>>; count: number };
    const mine = data.instances.find((i) => i.instance_id === instanceId);
    expect(mine).toBeTruthy();
    expect(mine!.user_sub).toBe(ALICE_ID);
  });

  test("admin filters instances by status=running", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/instances", { status: "running" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { instances: Array<Record<string, unknown>> };
    expect(data.instances.every((i) => i.status === "running")).toBe(true);
  });

  test("admin filters instances by user_sub", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/instances", { user_sub: ALICE_ID });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { instances: Array<Record<string, unknown>> };
    expect(data.instances.every((i) => i.user_sub === ALICE_ID)).toBe(true);
  });

  test("non-admin gets 403 on admin instances endpoint", async () => {
    const r = await apiGet(alicePage, "v1/admin/compute/instances");
    expect(r.status()).toBe(403);
  });

  test("admin lists all pods across users", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/pods");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { pods: unknown[]; count: number };
    expect(Array.isArray(data.pods)).toBe(true);
  });
});

// ─── 281. Force-terminate & alerts API ───────────────────────────────────────

test.describe("281. Force-terminate API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let instanceId: string;
  let podId: string;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    clearQuota(ALICE_ID);
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    instanceId = await launchInstance(alicePage, "alice");
    podId = await launchPod(alicePage, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("admin force-terminates a user instance", async () => {
    const r = await apiPost(
      rootPage,
      "root",
      `v1/admin/compute/instances/${encodeURIComponent(ALICE_ID)}/${instanceId}/terminate`,
      { reason: "resource abuse" },
    );
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("terminated");
  });

  test("user receives alert on admin termination", async () => {
    const r = await apiGet(alicePage, "ui/alerts", { limit: "50" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { alerts: Array<Record<string, unknown>> };
    const evt = data.alerts.find((a) => a.event === "compute.admin_terminated");
    expect(evt).toBeTruthy();
  });

  test("admin force-terminates a user pod", async () => {
    const r = await apiPost(
      rootPage,
      "root",
      `v1/admin/compute/pods/${encodeURIComponent(ALICE_ID)}/${podId}/terminate`,
      { reason: "cleanup" },
    );
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.status).toBe("terminated");
  });

  test("force-terminate non-existent instance returns 404", async () => {
    const r = await apiPost(
      rootPage,
      "root",
      `v1/admin/compute/instances/${encodeURIComponent(ALICE_ID)}/i_does_not_exist/terminate`,
      { reason: "x" },
    );
    expect(r.status()).toBe(404);
  });
});

// ─── 282. Quota management API ────────────────────────────────────────────────

test.describe("282. Quota management API", () => {
  let rootPage: Page;
  let charliePage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    clearQuota(ALICE_ID);
    rootPage = await newIdentityPage(browser, "root");
    charliePage = await newIdentityPage(browser, "charlie_admin");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    clearQuota(ALICE_ID);
    await rootPage?.close();
    await charliePage?.close();
    await alicePage?.close();
  });

  test("default quota for user without custom quota", async () => {
    const r = await apiGet(rootPage, `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.is_custom).toBe(false);
    expect(data.max_ec2_instances).toBe(3);
    expect(data.max_k8s_pods).toBe(5);
  });

  test("root sets a custom quota", async () => {
    const r = await apiPut(rootPage, "root", `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`, {
      max_ec2_instances: 1,
      max_k8s_pods: 2,
      max_monthly_spend_cents: 10000,
      allowed_instance_types: ["t3.micro"],
      allowed_k8s_presets: [],
      notes: "e2e custom quota",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(data.is_custom).toBe(true);
    expect(data.max_ec2_instances).toBe(1);
    expect(data.notes).toBe("e2e custom quota");
  });

  test("quota with max_ec2_instances=0 blocks launch", async () => {
    const setR = await apiPut(rootPage, "root", `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`, {
      max_ec2_instances: 0,
      max_k8s_pods: 5,
      max_monthly_spend_cents: 5000,
      allowed_instance_types: [],
      allowed_k8s_presets: [],
    });
    expect(setR.status()).toBe(200);
    const launchR = await apiPost(alicePage, "alice", "ui/remote/ec2/launch", {
      label: "should-be-blocked",
      instance_type: "t3.micro",
      ami_id: "ami-ubuntu-2204",
    });
    expect(launchR.status()).toBe(409);
  });

  test("invalid instance type in quota returns 422", async () => {
    const r = await apiPut(rootPage, "root", `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`, {
      max_ec2_instances: 3,
      max_k8s_pods: 5,
      max_monthly_spend_cents: 5000,
      allowed_instance_types: ["m5.bogus"],
      allowed_k8s_presets: [],
    });
    expect(r.status()).toBe(422);
  });

  test("delete custom quota reverts to defaults", async () => {
    const delR = await apiDelete(rootPage, "root", `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`);
    expect(delR.status()).toBe(200);
    const getR = await apiGet(rootPage, `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`);
    const data = (await getR.json()) as Record<string, unknown>;
    expect(data.is_custom).toBe(false);
    expect(data.max_ec2_instances).toBe(3);
  });

  test("admin (non-root) cannot set quotas", async () => {
    const r = await apiPut(charliePage, "charlie_admin", `v1/admin/compute/quotas/${encodeURIComponent(ALICE_ID)}`, {
      max_ec2_instances: 9,
      max_k8s_pods: 9,
      max_monthly_spend_cents: 99999,
      allowed_instance_types: [],
      allowed_k8s_presets: [],
    });
    expect(r.status()).toBe(403);
  });
});

// ─── 283. Platform spending & stats API ───────────────────────────────────────

test.describe("283. Platform spending & stats API", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    seedBilling(ALICE_ID, "ec2", 1234);
    seedBilling(BOB_ID, "k8s", 567);
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("platform spending summary", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/spending");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, number>;
    expect(data.total_cents).toBeGreaterThan(0);
    expect(data.active_user_count).toBeGreaterThanOrEqual(1);
  });

  test("per-user spending breakdown", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/spending/users");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { users: Array<Record<string, unknown>> };
    const alice = data.users.find((u) => u.user_sub === ALICE_ID);
    expect(alice).toBeTruthy();
    expect(Number(alice!.total_cents)).toBeGreaterThan(0);
  });

  test("instance type stats", async () => {
    const r = await apiGet(rootPage, "v1/admin/compute/stats/instance-types");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { stats: Array<Record<string, unknown>> };
    expect(Array.isArray(data.stats)).toBe(true);
    expect(data.stats.length).toBeGreaterThan(0);
  });

  test("admin compute dashboard renders", async () => {
    await rootPage.goto("http://localhost:3000/admin/compute");
    await expect(
      rootPage.getByRole("heading", { name: "Compute Dashboard" }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.getByText("Total Spending")).toBeVisible();
  });
});
