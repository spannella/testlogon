/**
 * E2E tests for KYC-017 — Document Signing Template Library.
 *
 * Sections 780–784:
 *   780: Template CRUD API (create / slug / tier / placeholders, duplicate slug, auth)
 *   781: Version management (upload, activate-deactivates-siblings, list)
 *   782: Tier lookup (list active required-for-tier, inactive excluded)
 *   783: Render-for-case (auto-populate placeholders, no-templates)
 *   784: Admin-only / auth (403 for non-admin, 401 for anonymous)
 *
 * Auth: cookie-based role-bearing sessions seeded by e2e_admin_session_setup.py
 * (root=root, charlie_admin=admin, alice=user). Admin endpoints use
 * require_admin_or_root; case endpoints use require_ui_session (CSRF on POST).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const TPL_BASE = "v1/kyc/document-templates";

// Minimal valid base64 PDF carrying merge placeholders.
const PDF_WITH_PLACEHOLDERS = Buffer.from(
  "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" +
    "Name: {{full_name}} City: {{city}} DOB: {{date_of_birth}} Date: {{current_date}}\n%%EOF",
).toString("base64");

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
  await page.context().addCookies(sessions[identity].cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, sessions[identity].user_sub);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
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

// Seed Alice's profile + a KYC case with a target tier directly into DDB.
function seedProfileAndCase(caseId: string, targetTier: string): void {
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
prof = ddb.Table(os.environ.get('PROFILE_TABLE_NAME','profiles'))
prof.put_item(Item={'user_sub':'${ALICE_ID}','profile':{'display_name':'Alice Tester','first_name':'Alice','last_name':'Tester','displayed_email':'alice@example.com','birthday':'1991-02-03','mailing_address':{'line1':'42 Test Lane','city':'Testville','state':'NY','postal_code':'10001','country':'US'}}})
cases = ddb.Table(os.environ.get('KYC_CASES_TABLE_NAME','kyc_cases'))
cases.put_item(Item={'pk':'KYC#${caseId}','sk':'META','kyc_case_id':'${caseId}','user_sub':'${ALICE_ID}','status':'draft','target_tier':'${targetTier}','version':1})
print('seeded')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

// ─── 780. Template CRUD API ──────────────────────────────────────────────
test.describe("780. KYC document template CRUD API", () => {
  let rootPage: Page;
  let alicePage: Page;
  const ts = Date.now();
  const slug = `e2e_tos_${ts}`;
  let templateId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("780.1 admin creates a template with slug, tier and placeholders", async () => {
    const r = await apiPost(rootPage, "root", TPL_BASE, {
      slug,
      display_name: "Terms of Service Acknowledgment",
      description: "E2E template",
      required_tier: "tier_1",
      placeholder_fields: ["full_name", "city", "date_of_birth", "current_date"],
    });
    expect(r.status()).toBe(201);
    const data = (await r.json()) as Record<string, any>;
    expect(data.slug).toBe(slug);
    expect(data.required_tier).toBe("tier_1");
    expect(data.status).toBe("active");
    expect(data.placeholder_fields).toContain("full_name");
    templateId = data.template_id;
    expect(templateId).toMatch(/^kdt_/);
  });

  test("780.2 duplicate slug is rejected with 409", async () => {
    const r = await apiPost(rootPage, "root", TPL_BASE, {
      slug,
      display_name: "Dup",
      required_tier: "tier_1",
      placeholder_fields: [],
    });
    expect(r.status()).toBe(409);
    const data = (await r.json()) as Record<string, any>;
    expect(JSON.stringify(data)).toContain("kyc_template_slug_exists");
  });

  test("780.3 slug validation rejects spaces/uppercase (422)", async () => {
    const r = await apiPost(rootPage, "root", TPL_BASE, {
      slug: "Bad Slug",
      display_name: "Bad",
      required_tier: "tier_1",
      placeholder_fields: [],
    });
    expect(r.status()).toBe(422);
  });

  test("780.4 list returns the created template", async () => {
    const r = await apiGet(rootPage, TPL_BASE);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { items: Array<Record<string, any>>; total: number };
    expect(data.items.some((t) => t.slug === slug)).toBe(true);
  });

  test("780.5 get template returns metadata + versions", async () => {
    const r = await apiGet(rootPage, `${TPL_BASE}/${templateId}`);
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, any>;
    expect(data.template_id).toBe(templateId);
    expect(Array.isArray(data.versions)).toBe(true);
  });
});

// ─── 781. Version management ─────────────────────────────────────────────
test.describe("781. KYC template version management API", () => {
  let rootPage: Page;
  const ts = Date.now();
  const slug = `e2e_aml_${ts}`;
  let templateId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    const r = await apiPost(rootPage, "root", TPL_BASE, {
      slug,
      display_name: "AML Declaration",
      required_tier: "tier_2",
      placeholder_fields: ["full_name"],
    });
    templateId = ((await r.json()) as Record<string, any>).template_id;
  });

  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("781.1 upload PDF version increments to v1 and v2", async () => {
    const r1 = await apiPost(rootPage, "root", `${TPL_BASE}/${templateId}/versions`, {
      pdf_base64: PDF_WITH_PLACEHOLDERS,
    });
    expect(r1.status()).toBe(201);
    expect(((await r1.json()) as Record<string, any>).version).toBe(1);

    const r2 = await apiPost(rootPage, "root", `${TPL_BASE}/${templateId}/versions`, {
      pdf_base64: PDF_WITH_PLACEHOLDERS,
    });
    expect(r2.status()).toBe(201);
    const v2 = (await r2.json()) as Record<string, any>;
    expect(v2.version).toBe(2);
    expect(v2.s3_key).toContain(slug);
  });

  test("781.2 non-PDF upload rejected with 422", async () => {
    const r = await apiPost(rootPage, "root", `${TPL_BASE}/${templateId}/versions`, {
      pdf_base64: Buffer.from("not a pdf").toString("base64"),
    });
    expect(r.status()).toBe(422);
  });

  test("781.3 activate v2 deactivates v1", async () => {
    const r = await apiPatch(rootPage, "root", `${TPL_BASE}/${templateId}/versions/2/activate`);
    expect(r.status()).toBe(200);
    expect(((await r.json()) as Record<string, any>).status).toBe("active");

    const detail = await apiGet(rootPage, `${TPL_BASE}/${templateId}`);
    const versions = ((await detail.json()) as Record<string, any>).versions as Array<Record<string, any>>;
    const v1 = versions.find((v) => v.version === 1);
    const v2 = versions.find((v) => v.version === 2);
    expect(v2!.status).toBe("active");
    expect(v1!.status).toBe("inactive");
  });

  test("781.4 deactivate a version", async () => {
    const r = await apiPatch(rootPage, "root", `${TPL_BASE}/${templateId}/versions/2/deactivate`);
    expect(r.status()).toBe(200);
    expect(((await r.json()) as Record<string, any>).status).toBe("inactive");
  });

  test("781.5 preview renders a PDF with mock data", async () => {
    // Reactivate v2 so it has an uploaded PDF to preview.
    await apiPatch(rootPage, "root", `${TPL_BASE}/${templateId}/versions/2/activate`);
    const r = await apiGet(rootPage, `${TPL_BASE}/${templateId}/versions/2/preview`);
    expect(r.status()).toBe(200);
    expect(r.headers()["content-type"]).toContain("application/pdf");
    const body = await r.body();
    expect(body.slice(0, 5).toString()).toBe("%PDF-");
    // Mock full_name merged into placeholder.
    expect(body.toString()).toContain("Jane Sample Doe");
  });

  test("781.6 archive sets template status to archived", async () => {
    const r = await apiDelete(rootPage, "root", `${TPL_BASE}/${templateId}`);
    expect(r.status()).toBe(200);
    expect(((await r.json()) as Record<string, any>).status).toBe("archived");

    const detail = await apiGet(rootPage, `${TPL_BASE}/${templateId}`);
    expect(((await detail.json()) as Record<string, any>).status).toBe("archived");
  });
});

// ─── 782. Tier lookup ────────────────────────────────────────────────────
test.describe("782. KYC required-templates-by-tier API", () => {
  let rootPage: Page;
  let alicePage: Page;
  const ts = Date.now();
  const slugT1 = `e2e_t1_${ts}`;
  const slugT2 = `e2e_t2_${ts}`;
  let idT1 = "";
  let idT2 = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    const a = await apiPost(rootPage, "root", TPL_BASE, {
      slug: slugT1,
      display_name: "Tier1 Doc",
      required_tier: "tier_1",
      placeholder_fields: ["full_name"],
    });
    idT1 = ((await a.json()) as Record<string, any>).template_id;
    await apiPost(rootPage, "root", `${TPL_BASE}/${idT1}/versions`, { pdf_base64: PDF_WITH_PLACEHOLDERS });

    const b = await apiPost(rootPage, "root", TPL_BASE, {
      slug: slugT2,
      display_name: "Tier2 Doc",
      required_tier: "tier_2",
      placeholder_fields: ["full_name"],
    });
    idT2 = ((await b.json()) as Record<string, any>).template_id;
    await apiPost(rootPage, "root", `${TPL_BASE}/${idT2}/versions`, { pdf_base64: PDF_WITH_PLACEHOLDERS });
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("782.1 required for tier_2 includes both tier_1 and tier_2 docs", async () => {
    const r = await apiGet(alicePage, `${TPL_BASE}/required/list`, { tier: "tier_2" });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { tier: string; items: Array<Record<string, any>> };
    const slugs = data.items.map((i) => i.slug);
    expect(slugs).toContain(slugT1);
    expect(slugs).toContain(slugT2);
  });

  test("782.2 required for tier_1 excludes the tier_2 doc", async () => {
    const r = await apiGet(alicePage, `${TPL_BASE}/required/list`, { tier: "tier_1" });
    const data = (await r.json()) as { items: Array<Record<string, any>> };
    const slugs = data.items.map((i) => i.slug);
    expect(slugs).toContain(slugT1);
    expect(slugs).not.toContain(slugT2);
  });

  test("782.3 deactivated template is excluded from required list", async () => {
    await apiPatch(rootPage, "root", `${TPL_BASE}/${idT2}/versions/1/deactivate`);
    const r = await apiGet(alicePage, `${TPL_BASE}/required/list`, { tier: "tier_2" });
    const data = (await r.json()) as { items: Array<Record<string, any>> };
    expect(data.items.map((i) => i.slug)).not.toContain(slugT2);
  });
});

// ─── 783. Render for case ────────────────────────────────────────────────
test.describe("783. KYC render-for-case auto-population API", () => {
  let rootPage: Page;
  let alicePage: Page;
  const ts = Date.now();
  const slug = `e2e_render_${ts}`;
  const caseId = `kyc_e2e${ts}`;
  let templateId = "";

  test.beforeAll(async ({ browser }) => {
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    seedProfileAndCase(caseId, "tier_1");
    const r = await apiPost(rootPage, "root", TPL_BASE, {
      slug,
      display_name: "Render Doc",
      required_tier: "tier_1",
      placeholder_fields: ["full_name", "city", "date_of_birth", "current_date"],
    });
    templateId = ((await r.json()) as Record<string, any>).template_id;
    await apiPost(rootPage, "root", `${TPL_BASE}/${templateId}/versions`, {
      pdf_base64: PDF_WITH_PLACEHOLDERS,
    });
  });

  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("783.1 render-for-case auto-populates placeholders and creates a packet", async () => {
    const r = await apiPost(alicePage, "alice", `${TPL_BASE}/render-for-case`, {
      case_id: caseId,
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { case_id: string; rendered: Array<Record<string, any>> };
    expect(data.case_id).toBe(caseId);
    const entry = data.rendered.find((e) => e.slug === slug);
    expect(entry).toBeDefined();
    // Profile has full_name + city + dob → these placeholders populate.
    expect(entry!.fields_populated).toBeGreaterThanOrEqual(3);
    expect(entry!.rendered_s3_key).toContain(caseId);
    // Reused EXISTING signature packet creation → packet_id present.
    expect(typeof entry!.packet_id).toBe("string");
  });

  test("783.2 render-for-case with no active templates returns 400", async () => {
    // Required templates are cumulative (required_tier <= the case's target
    // tier), so sibling describe-blocks (e.g. 782) leave active tier_1 templates
    // in the shared DynamoDB. Deactivate EVERY active version currently required
    // for this case's tier so the render genuinely has zero templates.
    const list = await apiGet(alicePage, `${TPL_BASE}/required/list`, { tier: "tier_1" });
    const items = ((await list.json()) as { items: Array<{ template_id: string; version: number }> }).items;
    for (const it of items) {
      await apiPatch(rootPage, "root", `${TPL_BASE}/${it.template_id}/versions/${it.version}/deactivate`);
    }
    const r = await apiPost(alicePage, "alice", `${TPL_BASE}/render-for-case`, {
      case_id: caseId,
    });
    expect(r.status()).toBe(400);
    expect(JSON.stringify(await r.json())).toContain("kyc_no_templates_available");
  });
});

// ─── 784. Admin-only / auth ──────────────────────────────────────────────
test.describe("784. KYC document templates admin-only / auth", () => {
  let alicePage: Page;
  const ts = Date.now();

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("784.1 non-admin cannot create a template (403)", async () => {
    const r = await apiPost(alicePage, "alice", TPL_BASE, {
      slug: `e2e_forbidden_${ts}`,
      display_name: "Nope",
      required_tier: "tier_1",
      placeholder_fields: [],
    });
    expect(r.status()).toBe(403);
  });

  test("784.2 non-admin cannot list templates (403)", async () => {
    const r = await apiGet(alicePage, TPL_BASE);
    expect(r.status()).toBe(403);
  });

  test("784.3 anonymous request is unauthorized (401)", async ({ request }) => {
    const r = await request.get(`${API}/${TPL_BASE}`);
    expect(r.status()).toBe(401);
  });
});
