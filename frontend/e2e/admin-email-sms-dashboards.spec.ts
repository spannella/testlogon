/**
 * E2E tests for ADMIN-002: Admin Email/SMS Dashboards.
 *
 * Section 551: Email Stats & Deliveries API (4 tests)
 * Section 552: Email & SMS Suppression API (4 tests)
 * Section 553: SMS Stats & Failures API (4 tests)
 * Section 554: Template Management API (4 tests)
 * Section 555: Input Validation & Edge Cases (4 tests)
 * Section 556: Concurrent Operations (3 tests)
 * Section 557: Authorization Boundary Tests (3 tests)
 * Section 558: Communications Dashboard UI (4 tests)
 *
 * Auth: role-bearing cookies from e2e_admin_session_setup.py (root / alice).
 * Non-GET cookie requests carry an x-csrf-token header. Endpoints use the
 * existing /ui/admin/email and /ui/admin/sms routers (extended) plus the new
 * /ui/admin/notifications template router.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ROOT_SUB = "root.admin@testdev.local";

interface AdminSessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    const raw = execSync("python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py", {
      cwd: "/home/ubuntu/testlogon",
      timeout: 30_000,
    }).toString();
    _adminSessions = JSON.parse(raw);
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await page.context().addCookies(sessions[identity].cookies as any);
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

async function apiDelete(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  return page.request.delete(`${API}/${path}`, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

// ─── DDB seeding ─────────────────────────────────────────────────────────────

/** Seed email + SMS delivery records and notification templates directly into DDB. */
function seedDeliveryData(): void {
  execSync(
    `python3 -c "
import boto3, os, time
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k,v = line.split('=',1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
now = int(time.time())
edt = ddb.Table('email_delivery')
for i in range(5):
    edt.put_item(Item={'pk':f'EMAIL#seed{i}@test.local','sk':f'SENT#{now}#seed{i}','to_email':f'seed{i}@test.local','subject':'Seed','status':'sent','created_at':now,'ttl_epoch':now+86400})
edt.put_item(Item={'pk':'EMAIL#bounce@typo.com','sk':f'BOUNCE#{now}#sb1','to_email':'bounce@typo.com','bounce_type':'Permanent','status':'bounced','created_at':now,'ttl_epoch':now+86400})
edt.put_item(Item={'pk':'EMAIL#complain@test.local','sk':f'COMPLAINT#{now}#sc1','to_email':'complain@test.local','complaint_feedback_type':'abuse','status':'complained','created_at':now,'ttl_epoch':now+86400})
sdt = ddb.Table('sms_delivery')
for i in range(3):
    sdt.put_item(Item={'pk':f'SMS#+1555000{i}','sk':f'SENT#{now}#s{i}','phone':f'+1555000{i}','body_preview':'seed','segments':1,'status':'sent','created_at':now,'ttl_epoch':now+86400})
sdt.put_item(Item={'pk':'SMS#+15559999','sk':f'FAILED#{now}','phone':'+15559999','error':'invalid_number','status':'failed','created_at':now,'ttl_epoch':now+86400})
tt = ddb.Table('admin_messaging_templates')
tt.put_item(Item={'pk':'TEMPLATE#email_welcome','sk':'META','template_id':'email_welcome','channel':'email','name':'Welcome Email','subject':'Welcome {{user_name}}','body':'<h1>Hi {{user_name}}</h1>','variables':['user_name'],'active':True,'updated_at':now})
tt.put_item(Item={'pk':'TEMPLATE#sms_verification','sk':'META','template_id':'sms_verification','channel':'sms','subject':None,'name':'SMS Verification','body':'Code {{code}}','variables':['code'],'active':True,'updated_at':now})
print('seeded')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
  );
}

test.describe("ADMIN-002: Email/SMS Dashboards", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getAdminSessions();
    seedDeliveryData();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  // ── 551: Email Stats & Deliveries API ──────────────────────────────────────
  test.describe("551. Email Stats & Deliveries API", () => {
    test("Admin retrieves email delivery stats", async () => {
      const r = await apiGet(rootPage, "ui/admin/email/dashboard/stats", { days: "7" });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.sent).toBeGreaterThanOrEqual(5);
      expect(d.delivery_rate).toBeGreaterThanOrEqual(0);
      expect(d.delivery_rate).toBeLessThanOrEqual(100);
      expect(d.bounce_rate).toBeGreaterThanOrEqual(0);
    });

    test("Admin lists email deliveries", async () => {
      const r = await apiGet(rootPage, "ui/admin/email/deliveries", { limit: "10" });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d.items)).toBe(true);
    });

    test("Admin lists email bounces", async () => {
      const r = await apiGet(rootPage, "ui/admin/email/bounces", {});
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d.items)).toBe(true);
      expect(d.items.length).toBeGreaterThanOrEqual(1);
    });

    test("Non-admin cannot access email stats", async () => {
      const r = await apiGet(alicePage, "ui/admin/email/dashboard/stats", { days: "7" });
      expect(r.status()).toBe(403);
    });
  });

  // ── 552: Email & SMS Suppression API ───────────────────────────────────────
  test.describe("552. Suppression API", () => {
    const supAddr = `spam_${Date.now()}@test.local`;

    test("Admin views email suppression list", async () => {
      const r = await apiGet(rootPage, "ui/admin/email/suppressed", {});
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d.items)).toBe(true);
    });

    test("Admin adds email to suppression list", async () => {
      const r = await apiPost(rootPage, "root", "ui/admin/email/suppressed", {
        address: supAddr,
        reason: "spam",
      });
      expect([200, 201]).toContain(r.status());
      const list = await (await apiGet(rootPage, "ui/admin/email/suppressed", { limit: "200" })).json();
      const found = list.items.some((it: Record<string, unknown>) => it.email === supAddr);
      expect(found).toBe(true);
    });

    test("Admin removes email from suppression", async () => {
      const r = await apiDelete(rootPage, "root", `ui/admin/email/suppressed/${encodeURIComponent(supAddr)}`);
      expect(r.status()).toBe(200);
      const list = await (await apiGet(rootPage, "ui/admin/email/suppressed", { limit: "200" })).json();
      const found = list.items.some((it: Record<string, unknown>) => it.email === supAddr);
      expect(found).toBe(false);
    });

    test("Admin views SMS suppression list", async () => {
      const r = await apiGet(rootPage, "ui/admin/sms/suppressed", {});
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d.items)).toBe(true);
    });
  });

  // ── 553: SMS Stats & Failures API ──────────────────────────────────────────
  test.describe("553. SMS Stats & Failures API", () => {
    test("Admin retrieves SMS delivery stats", async () => {
      const r = await apiGet(rootPage, "ui/admin/sms/dashboard/stats", { days: "7" });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.sent).toBeGreaterThanOrEqual(3);
      expect(d.delivery_rate).toBeGreaterThanOrEqual(0);
    });

    test("Admin lists SMS deliveries", async () => {
      const r = await apiGet(rootPage, "ui/admin/sms/deliveries", { limit: "10" });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d.items)).toBe(true);
    });

    test("Admin lists SMS failures", async () => {
      const r = await apiGet(rootPage, "ui/admin/sms/failures", {});
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d.items)).toBe(true);
      expect(d.items.length).toBeGreaterThanOrEqual(1);
    });

    test("Admin adds phone to SMS suppression", async () => {
      const phone = `+1555${Date.now() % 10000000}`;
      const r = await apiPost(rootPage, "root", "ui/admin/sms/suppressed", {
        address: phone,
        reason: "opt-out",
      });
      expect([200, 201]).toContain(r.status());
    });
  });

  // ── 554: Template Management API ───────────────────────────────────────────
  test.describe("554. Template Management API", () => {
    test("Admin lists notification templates", async () => {
      const r = await apiGet(rootPage, "ui/admin/notifications/templates", {});
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(Array.isArray(d)).toBe(true);
      expect(d.length).toBeGreaterThanOrEqual(2);
    });

    test("Admin updates template body", async () => {
      // Keep the {{user_name}} variable so the preview test below still renders it.
      const newBody = `<h1>Updated ${Date.now()} {{user_name}}</h1>`;
      const r = await apiPatch(rootPage, "root", "ui/admin/notifications/templates/email_welcome", {
        body: newBody,
      });
      expect(r.status()).toBe(200);
      const got = await (await apiGet(rootPage, "ui/admin/notifications/templates/email_welcome", {})).json();
      expect(got.body).toBe(newBody);
    });

    test("Admin previews template", async () => {
      const r = await apiPost(rootPage, "root", "ui/admin/notifications/templates/email_welcome/preview", {
        sample_vars: { user_name: "Alice" },
      });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.rendered_body).toContain("Alice");
    });

    test("Admin sends test notification", async () => {
      const r = await apiPost(rootPage, "root", "ui/admin/notifications/templates/email_welcome/test-send", {
        recipient: "admin@test.local",
        sample_vars: { user_name: "Admin" },
      });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.ok).toBe(true);
      expect(d.channel).toBe("email");
    });
  });

  // ── 555: Input Validation & Edge Cases ─────────────────────────────────────
  test.describe("555. Input Validation", () => {
    test("Empty suppression address rejected", async () => {
      const r = await apiPost(rootPage, "root", "ui/admin/email/suppressed", { address: "", reason: "test" });
      expect(r.status()).toBe(422);
    });

    test("Template body with script tags stripped", async () => {
      const r = await apiPatch(rootPage, "root", "ui/admin/notifications/templates/email_welcome", {
        body: "<p>ok</p><script>alert(1)</script>",
      });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.body).not.toContain("<script>");
    });

    test("Invalid days parameter rejected", async () => {
      const r = await apiGet(rootPage, "ui/admin/email/dashboard/stats", { days: "0" });
      expect(r.status()).toBe(422);
    });

    test("Template update with empty subject allowed", async () => {
      const r = await apiPatch(rootPage, "root", "ui/admin/notifications/templates/email_welcome", {
        subject: "",
      });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.subject === "" || d.subject === null).toBe(true);
    });
  });

  // ── 556: Concurrent Operations ─────────────────────────────────────────────
  test.describe("556. Concurrent Operations", () => {
    test("Concurrent suppression add is idempotent", async () => {
      const addr = `dup_${Date.now()}@test.local`;
      const [r1, r2] = await Promise.all([
        apiPost(rootPage, "root", "ui/admin/email/suppressed", { address: addr, reason: "a" }),
        apiPost(rootPage, "root", "ui/admin/email/suppressed", { address: addr, reason: "b" }),
      ]);
      expect(r1.status()).toBe(200);
      expect(r2.status()).toBe(200);
      const list = await (await apiGet(rootPage, "ui/admin/email/suppressed", { limit: "200" })).json();
      const count = list.items.filter((it: Record<string, unknown>) => it.email === addr).length;
      expect(count).toBe(1);
      await apiDelete(rootPage, "root", `ui/admin/email/suppressed/${encodeURIComponent(addr)}`);
    });

    test("Concurrent template updates last-write-wins", async () => {
      const b1 = `<p>one ${Date.now()}</p>`;
      const b2 = `<p>two ${Date.now()}</p>`;
      await Promise.all([
        apiPatch(rootPage, "root", "ui/admin/notifications/templates/email_welcome", { body: b1 }),
        apiPatch(rootPage, "root", "ui/admin/notifications/templates/email_welcome", { body: b2 }),
      ]);
      const got = await (await apiGet(rootPage, "ui/admin/notifications/templates/email_welcome", {})).json();
      expect([b1, b2]).toContain(got.body);
    });

    test("Stats query reflects newly seeded records", async () => {
      seedDeliveryData();
      const r = await apiGet(rootPage, "ui/admin/email/dashboard/stats", { days: "7" });
      expect(r.status()).toBe(200);
      const d = await r.json();
      expect(d.sent).toBeGreaterThanOrEqual(5);
    });
  });

  // ── 557: Authorization Boundary Tests ──────────────────────────────────────
  test.describe("557. Authorization Boundaries", () => {
    test("Regular user cannot access SMS stats", async () => {
      const r = await apiGet(alicePage, "ui/admin/sms/dashboard/stats", {});
      expect(r.status()).toBe(403);
    });

    test("Regular user cannot add suppression", async () => {
      const r = await apiPost(alicePage, "alice", "ui/admin/email/suppressed", {
        address: "x@test.local",
        reason: "nope",
      });
      expect(r.status()).toBe(403);
    });

    test("Regular user cannot update template", async () => {
      const r = await apiPatch(alicePage, "alice", "ui/admin/notifications/templates/email_welcome", {
        body: "hacked",
      });
      expect(r.status()).toBe(403);
    });
  });

  // ── 558: Communications Dashboard UI ───────────────────────────────────────
  test.describe("558. Communications Dashboard UI", () => {
    test("Dashboard loads with Email tab active", async () => {
      await rootPage.goto("/admin/communications");
      await expect(rootPage.getByRole("tab", { name: /email/i })).toBeVisible();
      await expect(rootPage.getByTestId("kpi-email-sent")).toBeVisible();
    });

    test("SMS tab shows SMS-specific stats", async () => {
      await rootPage.goto("/admin/communications");
      await rootPage.getByRole("tab", { name: /^sms$/i }).click();
      await expect(rootPage.getByTestId("kpi-sms-segments")).toBeVisible();
    });

    test("Templates tab lists templates", async () => {
      await rootPage.goto("/admin/communications");
      await rootPage.getByRole("tab", { name: /templates/i }).click();
      await expect(rootPage.getByText("Welcome Email")).toBeVisible();
    });

    test("Suppression add dialog works", async () => {
      const addr = `ui_${Date.now()}@test.local`;
      await rootPage.goto("/admin/communications");
      await rootPage.getByTestId("email-add-suppression").click();
      await rootPage.locator("#email-supp-addr").fill(addr);
      await rootPage.locator("#email-supp-reason").fill("ui-test");
      await rootPage.getByTestId("email-suppression-submit").click();
      await expect(rootPage.getByText(addr)).toBeVisible({ timeout: 10_000 });
      await apiDelete(rootPage, "root", `ui/admin/email/suppressed/${encodeURIComponent(addr)}`);
    });
  });
});
