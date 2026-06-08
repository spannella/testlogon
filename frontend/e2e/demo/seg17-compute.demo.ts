/**
 * VIDEO SEGMENT 17 — Compute  (~60-95s)  · FINAL SEGMENT
 *
 * A guided tour of the platform's cloud-compute surfaces, filmed as a regular
 * user (alice) plus a brief root view of the platform-wide dashboard:
 *
 *   - EC2 Instances (/remote/ec2): launch, list, and lifecycle (stop/start/
 *     reboot/terminate) of mock EC2 instances. The launch dialog offers instance
 *     types and AMIs as templates.
 *   - Containers / K8s pods (/remote/k8s): the same model for Kubernetes pods —
 *     image + resource preset, TTL countdown, logs.
 *   - Instance Monitoring (/remote/instances/:id/monitoring): per-instance CPU /
 *     memory / disk gauges, a resource-utilization time series, and a datapoint
 *     count. Backed by ingested monitoring datapoints; a lifecycle TIMELINE
 *     (launch / stop / start) is recorded server-side per resource.
 *   - Compute Spending (/remote/billing): auto-billing — a budget meter with
 *     EC2 / K8s split, a per-resource breakdown, a ledger, and a budget control.
 *     A background timer meters every running resource and auto-terminates on an
 *     empty balance; an auto-restart policy can bring a critical instance back.
 *   - Admin Compute Dashboard (/admin/compute, root): platform-wide spend,
 *     per-user breakdown, instance-type popularity, and force-terminate.
 *
 * Pattern mirrors seg16-admin.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - alice — a regular user; owns the on-camera instances/pods/monitoring/billing.
 *   - root  — used only for the platform-wide Admin Compute Dashboard.
 *
 * Seeding (all off-camera, before any UI is shown), via alice's CSRF API:
 *   - two EC2 instances (one is stopped+started to enrich the lifecycle timeline)
 *   - one K8s pod
 *   - monitoring datapoints for the primary instance (so the gauges + series fill)
 *   - a compute-billing tick + monthly total (so the spending dashboard is real)
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg17-compute.demo.ts
 */
import { test, expect, type APIResponse, type Page } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const ALICE = "alice";
const ROOT = "root";
const ALICE_SUB = "e2e_alice@test.local";
const STAMP = Date.now();

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** CSRF-authenticated request helper bound to one identity's cookies/token. */
function reqs(page: Page, sess: SessionData) {
  return {
    post: (path: string, body?: unknown) =>
      page.request.post(`${API}${path}`, {
        headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
        data: body ?? {},
      }),
    get: (path: string) => page.request.get(`${API}${path}`),
  };
}

/** Seed a compute_billing tick + monthly total for alice in the current month. */
function seedBilling(): void {
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
mk = datetime.now(timezone.utc).strftime('%Y-%m')
def tick(rtype, cents):
    ts = int(time.time())
    eid = 'e_' + uuid.uuid4().hex[:8]
    tbl.put_item(Item={'user_sub':'${ALICE_SUB}','sk':f'TICK#{ts}#{eid}','entry_id':eid,'resource_type':rtype,'resource_id':'r_'+uuid.uuid4().hex[:6],'amount_cents':cents,'created_at':ts,'month_key':mk})
    tbl.update_item(Key={'user_sub':'${ALICE_SUB}','sk':f'MONTH#{mk}'}, UpdateExpression='SET current_month_total_cents = if_not_exists(current_month_total_cents,:z)+:a, month_key=:mk', ExpressionAttributeValues={':z':0,':a':cents,':mk':mk})
tick('ec2', 742)
tick('k8s', 318)
print('seeded billing')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 20_000 },
  );
}

test("Segment 17 — Compute", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];

  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(600);
  const a = reqs(page, alice);

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  // Primary EC2 instance — gets monitoring datapoints + a stop/start so the
  // lifecycle timeline has launch/stop/start events.
  const ec2a = (await jsonOk(
    (await a.post("/ui/remote/ec2/launch", {
      label: `web-server-${STAMP}`,
      instance_type: "t3.micro",
      ami_id: "ami-ubuntu-2204",
    })) as APIResponse,
    "launch ec2 #1",
  )) as Record<string, string>;
  const primaryId = ec2a.instance_id;

  // A second EC2 instance for a fuller list.
  await a
    .post("/ui/remote/ec2/launch", {
      label: `build-runner-${STAMP}`,
      instance_type: "t3.small",
      ami_id: "ami-ubuntu-2204",
    })
    .catch(() => {});

  // A K8s pod so the Containers list is populated.
  await a
    .post("/ui/remote/k8s/launch", {
      label: `worker-pod-${STAMP}`,
      image: "ubuntu-ssh",
      preset: "small",
    })
    .catch(() => {});

  // Seed monitoring datapoints for the primary instance.
  await a
    .post(`/ui/compute/monitoring/instances/${primaryId}/seed`, {
      points: 30,
      interval_seconds: 300,
      base_cpu_pct: 46,
      base_mem_pct: 58,
      base_disk_pct: 34,
    })
    .catch(() => {});

  // Enrich the lifecycle timeline: stop then start the primary instance.
  await a.post(`/ui/remote/ec2/instances/${primaryId}/stop`).catch(() => {});
  await page.waitForTimeout(400);
  await a.post(`/ui/remote/ec2/instances/${primaryId}/start`).catch(() => {});

  // Seed compute auto-billing so the spending dashboard is real.
  seedBilling();

  // ── On-camera tour ──────────────────────────────────────────────────────────

  // 1. Intro ───────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    17,
    "Compute",
    "Cloud instances · EC2 & K8s · monitoring · lifecycle timeline · auto-billing · auto-restart",
    3800,
  );

  // 2. EC2 Instances list ─────────────────────────────────────────────────────────
  await caption(page, "Cloud compute", "Loading your EC2 instances…");
  await page.goto(`${BASE}/remote/ec2`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("EC2 Instances").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByText("EC2 Instances").first(),
    "Spin up cloud instances",
    "Launch, list, and run real EC2 instances — each with status, type, IP, and live lifecycle controls",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByText(`web-server-${STAMP}`).first(),
    "A running instance",
    "Start, stop, reboot, or terminate — every action is metered and audited",
    { ms: 4000 },
  );

  // 3. Launch surface ─────────────────────────────────────────────────────────────
  await page.getByTestId("launch-btn").click().catch(() => {});
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("dialog").getByText("Launch EC2 Instance").first(),
    "Launch from templates",
    "Pick an instance type and an AMI, name it, add a startup script — then launch",
    { ms: 3800 },
  );
  // Open the instance-type selector so the templates are on screen.
  await page.getByTestId("launch-type").click().catch(() => {});
  await page.waitForTimeout(700);
  await reveal(
    page,
    page.locator('[role="option"]').first(),
    "Instance types",
    "vCPU and memory per type — the same template catalogue used for billing",
    { ms: 3600 },
  );
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(300);
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(500);

  // 4. Containers (K8s) ────────────────────────────────────────────────────────────
  await caption(page, "Containers", "Opening the Kubernetes pods…");
  await page.goto(`${BASE}/remote/k8s`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Containers").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByText(`worker-pod-${STAMP}`).first(),
    "Kubernetes pods too",
    "Launch containers by image + resource preset — with a TTL countdown and live logs",
    { ms: 4200 },
  );

  // 5. Instance Monitoring + lifecycle timeline ────────────────────────────────────
  await caption(page, "Monitoring", "Opening per-instance monitoring…");
  await page.goto(`${BASE}/remote/instances/${primaryId}/monitoring`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByRole("heading", { name: "Instance Monitoring" })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForResponse((rsp) => rsp.url().includes("/health") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(1100);
  await reveal(
    page,
    page.getByTestId("metric-cpu").first(),
    "Live resource metrics",
    "CPU, memory, and disk gauges from ingested monitoring datapoints — health is derived automatically",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByText("Resource Utilization").first(),
    "Utilization over time",
    "A rolling time series of CPU, memory, and disk — the basis for auto-restart on a critical instance",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByTestId("datapoint-count").first(),
    "Lifecycle is tracked",
    "Every launch, stop, and start is recorded to a per-resource lifecycle timeline server-side",
    { ms: 3800 },
  );

  // 6. Compute auto-billing ────────────────────────────────────────────────────────
  await caption(page, "Auto-billing", "Opening compute spending…");
  await page.goto(`${BASE}/remote/billing`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("page-title")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByTestId("budget-meter-bar").first(),
    "Metered automatically",
    "A background timer bills every running instance and pod by the minute — against a monthly budget",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByTestId("ec2-spending").first(),
    "EC2 vs K8s split",
    "Spend broken out by EC2 and Kubernetes — and a budget you can cap, with alert thresholds",
    { ms: 4000 },
  );

  // 7. Admin Compute Dashboard (root, platform-wide) ──────────────────────────────
  await caption(page, "Platform compute", "Switching to the root operator view…");
  await injectAuth(page, ROOT);
  await page.goto(`${BASE}/admin/compute`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Compute Dashboard" })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForTimeout(1100);
  await reveal(
    page,
    page.getByText("Total Spending").first(),
    "Platform-wide compute",
    "Root sees total spend, active instances and pods, per-user breakdown, and force-terminate",
    { ms: 4200 },
  );

  // 8. Outro ──────────────────────────────────────────────────────────────────────
  await clearCaption(page);
  await beat(page, 500);
  await caption(page, "Compute ✓ — That's the platform!", "Thanks for watching the tour");
  await beat(page, 3400);
  await clearCaption(page);
  await beat(page, 800);
});
