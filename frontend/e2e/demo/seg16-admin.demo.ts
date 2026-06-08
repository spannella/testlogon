/**
 * VIDEO SEGMENT 16 — Admin & Root  (~110-145s)
 *
 * A guided tour of the platform's privileged-operator surfaces, filmed as the
 * ROOT account (the only identity that sees every control):
 *
 *   - Root Role Management (/root/roles): grant a general/scoped admin role,
 *     update an admin's capability profile, revoke a role — every action lands in
 *     an immutable role-assignment audit timeline.
 *   - Impersonation (AppShell banner): root/general-admin can "act as" a user for
 *     support, gated behind a reason; a persistent banner shows who you're acting
 *     as, and Stop ends it. Every start/stop is audited.
 *   - Moderation Board (/admin/moderation): content-moderation queues with ticket
 *     detail, offender history, and a decision panel (resolution + enforcement).
 *   - Audit Log Export (/admin/audit-exports): export audit events by category in
 *     NDJSON / CSV / PDF (audit-grade), with an export-history table. Recurring
 *     scheduled reports are driven by the same pipeline server-side.
 *   - Payment Provider Health (/admin/payment-health): live Stripe/PayPal/CCBill
 *     status, success rate, latency, incidents — plus a root-only provider
 *     kill-switch (disable a provider to stop new payment initiation).
 *   - Platform Financials (/admin/financials): revenue trends + provider split.
 *
 * Pattern mirrors seg15-remote.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - root  — the privileged operator; sees role mgmt, kill-switches, audit.
 *   - bob   — a regular user used as the target of a grant / impersonation.
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - bob reset to a plain user (so the grant on camera is real).
 *   - a moderation ticket in the default "newsfeed" queue (so the board has work).
 *   - an audit-export job (so the export-history table has a row).
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg16-admin.demo.ts
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

const ROOT = "root";
const BOB_SUB = "e2e_bob@test.local";
const STAMP = Date.now();
const TICKET_ID = `modtk_demo_${STAMP}`;
const CONTENT_ID = `post_demo_${STAMP}`;

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

/** Reset Bob to a plain user so the on-camera grant is a real state transition. */
function resetBobToUser(): void {
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
tbl = ddb.Table(os.environ.get('USERS_TABLE_NAME','users'))
tbl.update_item(Key={'user_sub':'${BOB_SUB}'}, UpdateExpression='SET #r=:r REMOVE admin_profile', ExpressionAttributeNames={'#r':'role'}, ExpressionAttributeValues={':r':'user'})
print('reset bob to user')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

/** Seed a moderation ticket (in the default newsfeed queue) + a fake post snapshot. */
function seedTicket(): void {
  const now = Math.floor(Date.now() / 1000);
  execSync(
    `.venv/bin/python3 -c "
import boto3, os
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
from app.core.settings import S
ddb.Table(S.moderation_tickets_table_name).put_item(Item={
    'ticket_id':'${TICKET_ID}','entity_type':'moderation_ticket','content_type':'feed_post',
    'content_id':'${CONTENT_ID}','status':'open','priority':'high','queue':'newsfeed',
    'report_count':3,'aggregated_topics':['spam'],'latest_report_at':'${now}',
    'latest_report_scope':'ALL','updated_at':'${now}','created_at':'${now}',
    'offender_user_id':'${BOB_SUB}'})
app_table = os.environ.get('APP_TABLE','app_single_table')
try:
    ddb.Table(app_table).put_item(Item={'pk':'POST#${CONTENT_ID}','sk':'META','user_sub':'${BOB_SUB}','text':'Spam post under review','created_at':${now}})
except Exception as e:
    print('post snapshot skipped:', e)
print('seeded ticket ${TICKET_ID}')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

test("Segment 16 — Admin & Root", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const root: SessionData = sessions[ROOT];

  await injectAuth(page, ROOT);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(600);
  const r = reqs(page, root);

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  resetBobToUser();
  seedTicket();

  // An audit-export job so the export-history table has a real completed row.
  try {
    await jsonOk(
      (await r.post("/ui/admin/audit-exports", {
        categories: ["auth", "admin"],
        format: "ndjson",
        from_date: Math.floor(Date.now() / 1000) - 30 * 86400,
        to_date: Math.floor(Date.now() / 1000),
      })) as APIResponse,
      "create audit export",
    );
  } catch {
    // Non-fatal: the formats/selector are still shown even with an empty history.
  }

  // ── On-camera tour ──────────────────────────────────────────────────────────

  // 1. Intro ───────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    16,
    "Admin & Root",
    "Roles · impersonation · moderation · audit exports · payment health · kill-switches",
    3800,
  );

  // 2. Root Role Management ──────────────────────────────────────────────────────
  await caption(page, "Root role management", "Loading the privileged operator console…");
  await page.goto(`${BASE}/root/roles`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Root Role Management" })).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("heading", { name: "Root Role Management" }).first(),
    "Root-only operator console",
    "Assign admins, tune capability profiles, and review an immutable audit history — root account only",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByText("Grant admin role").first(),
    "Grant an admin role",
    "Promote a user to a general admin, or a scoped admin limited to selected domains — reason required",
    { ms: 4000 },
  );
  // Fill the grant form on camera so it's a concrete action (Bob → admin).
  await page.locator("#grant-target").fill(BOB_SUB).catch(() => {});
  await page.locator("#grant-reason").fill("Onboarding Bob to the support rota").catch(() => {});
  await page.waitForTimeout(500);
  await reveal(
    page,
    page.locator("#grant-profile-type"),
    "General or scoped",
    "Scoped admins are confined to auth, billing, or content-moderation domains only",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.getByText("Update admin profile").first(),
    "Re-scope or revoke",
    "Convert an admin between general and scoped — or revoke the role entirely",
    { ms: 3600 },
  );
  // Reveal the immutable role-assignment audit timeline.
  await reveal(
    page,
    page.getByText("Role assignment audit timeline").first(),
    "Immutable audit timeline",
    "Every grant, revoke, and profile change is recorded with actor, target, and reason",
    { ms: 4200 },
  );

  // 3. Impersonation ─────────────────────────────────────────────────────────────
  await caption(page, "Impersonation", "Acting as another user for support…");
  // The ImpersonationBanner lives at the top of the AppShell — go to the dashboard.
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("General admin/root impersonation controls available.").first(),
    "Built-in impersonation",
    "A persistent banner lets root and general admins act as a user — fully audited",
    { ms: 3600 },
  );
  // Open the start-impersonation dialog.
  await page.getByRole("button", { name: "Start impersonation" }).click().catch(() => {});
  await page.waitForTimeout(900);
  await page.locator("#imp-target").fill(BOB_SUB).catch(() => {});
  await page.locator("#imp-reason").fill("Reproducing a billing issue from ticket #4821").catch(() => {});
  await page.waitForTimeout(500);
  await reveal(
    page,
    page.locator('[role="dialog"]').getByText("Enter target user and reason").first(),
    "Reason-gated, time-limited",
    "Every session requires a target and a reason — and expires automatically",
    { ms: 3800 },
  );
  // Begin the impersonation. We drive the start via the CSRF API helper (the exact
  // call the dialog makes, but pointed straight at the backend) and seed the
  // persisted impersonation store — the same store the live button writes — so the
  // on-camera "Acting as" banner is reliable and matches the real flow.
  const impData = (await jsonOk(
    (await r.post("/admin/impersonation/start", {
      target_user_sub: BOB_SUB,
      reason: "Reproducing a billing issue from ticket #4821",
    })) as APIResponse,
    "start impersonation",
  )) as Record<string, unknown>;
  await page.evaluate((d: Record<string, unknown>) => {
    const state = {
      token: d.token,
      impersonationId: d.impersonation_id,
      actorSub: d.actor_sub,
      effectiveSub: d.effective_sub,
      expiresAt: d.expires_at,
    };
    localStorage.setItem("impersonation-store", JSON.stringify({ state, version: 0 }));
  }, impData);
  // Re-render the AppShell so the banner reads the freshly-seeded active store.
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1300);
  await reveal(
    page,
    page.locator("span").filter({ hasText: /^Acting as/ }).first(),
    "You're acting as the user",
    "The banner stays visible the whole time, with a one-click Stop to end it",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: "Stop impersonation" }).first(),
    "End it in one click",
    "Stop returns you to your own account — the session and its audit trail are sealed",
    { ms: 2600 },
  );
  // Tear down the impersonation (backend + local store) to leave the demo clean.
  await r
    .post("/admin/impersonation/stop", { impersonation_id: impData.impersonation_id })
    .catch(() => {});
  await page.evaluate(() => localStorage.removeItem("impersonation-store")).catch(() => {});
  await page.waitForTimeout(600);

  // 4. Moderation Board ───────────────────────────────────────────────────────────
  await caption(page, "Moderation board", "Opening the content-moderation queues…");
  await page.goto(`${BASE}/admin/moderation`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Moderation Board" })).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/admin/moderation/tickets") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByRole("heading", { name: "Moderation Board" }).first(),
    "Content moderation queues",
    "Newsfeed, messages, and profile queues — filter by status, topic, and assignee",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByText(TICKET_ID).first(),
    "A reported item",
    "Each ticket shows its queue, content type, and report count",
    { ms: 3600 },
  );
  // Open the ticket detail by clicking the row, then show the decision panel.
  await page.getByText(TICKET_ID).first().click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("Decision panel").first(),
    "Decide & enforce",
    "Resolve as no-violation or content-removed, with an optional warn or ban enforcement action",
    { ms: 4200 },
  );

  // 5. Audit Log Export ────────────────────────────────────────────────────────────
  await caption(page, "Audit log export", "Opening the audit export console…");
  await page.goto(`${BASE}/admin/audit-exports`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Audit Log Export" })).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/admin/audit-exports") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByRole("heading", { name: "Audit Log Export" }).first(),
    "Export the audit trail",
    "Pull audit events by category — auth, moderation, broadcast, admin, billing",
    { ms: 3800 },
  );
  // Open the format selector so NDJSON / CSV / PDF are on screen.
  await page.getByRole("combobox").first().click().catch(() => {});
  await page.waitForTimeout(700);
  await reveal(
    page,
    page.getByText("PDF (audit-grade)").first(),
    "NDJSON · CSV · PDF",
    "Tamper-evident, audit-grade PDF alongside machine-readable NDJSON and CSV",
    { ms: 4000 },
  );
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(400);
  await reveal(
    page,
    page.getByText("Export History").first(),
    "Export history",
    "Past exports — with status, event count, and download. Recurring reports run on a schedule",
    { ms: 4000 },
  );

  // 6. Payment Provider Health ──────────────────────────────────────────────────────
  await caption(page, "Payment health", "Loading provider health + kill-switches…");
  await page.goto(`${BASE}/admin/payment-health`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Payment Provider Health" })).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/payment-health") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByRole("heading", { name: "Payment Provider Health" }).first(),
    "Live provider health",
    "Stripe, PayPal, and CCBill — success rate, latency, and incident history at a glance",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByTestId("provider-card-stripe").first(),
    "Per-provider vitals",
    "Success rate, p95 latency, success/failure counts, and last health check",
    { ms: 3800 },
  );
  await reveal(
    page,
    page.getByTestId("toggle-stripe").first(),
    "Root-only kill-switch",
    "Disable a provider to stop new payment initiation instantly — in-flight charges are unaffected",
    { ms: 4000 },
  );
  // Open the toggle confirmation dialog (do NOT confirm — just show it).
  await page.getByTestId("toggle-stripe").first().click().catch(() => {});
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByRole("dialog").getByText("Disabling prevents new payment").first(),
    "Reason-gated kill-switch",
    "Disabling is a deliberate, reason-logged action — confirm to flip the switch",
    { ms: 3800 },
  );
  await page.getByRole("button", { name: "Cancel" }).click().catch(() => {});
  await page.waitForTimeout(500);

  // 7. Platform Financials (bonus dashboard) ─────────────────────────────────────────
  await caption(page, "Platform financials", "Opening the revenue dashboard…");
  await page.goto(`${BASE}/admin/financials`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Platform Financials" })).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByRole("heading", { name: "Platform Financials" }).first(),
    "Platform-wide financials",
    "Revenue trends and a provider split across Stripe, PayPal, and CCBill",
    { ms: 3600 },
  );

  // 8. Outro ──────────────────────────────────────────────────────────────────────
  await clearCaption(page);
  await beat(page, 500);
  await caption(page, "Admin & Root ✓", "Next: Compute");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 800);
});
