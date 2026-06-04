/**
 * E2E tests for KYC-020 — Multi-Language Support.
 *
 * Sections 793–799:
 *   793: Supported locales + bundle API (user)
 *   794: Translation CRUD API (admin upsert / list / delete)
 *   795: English fallback + localized questionnaire / legal notice
 *   796: Coverage report + bulk import / export
 *   797: Locale resolution (profile precedence, Accept-Language, RTL)
 *   798: Auth enforcement (403 non-admin, 401 anonymous)
 *   799: Admin translation management UI
 *
 * Auth: cookie-based role-bearing sessions seeded by e2e_admin_session_setup.py
 * (root=root, charlie_admin=admin, alice=user). Admin endpoints use
 * require_admin_or_root; user endpoints use require_ui_session (CSRF on POST).
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BASE = "v1/kyc/i18n";
const TS = Date.now();

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

async function apiPut(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.put(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
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

/** Set Alice's profile locale directly in DDB (or clear it with null). */
function setAliceLocale(locale: string | null): void {
  const literal = locale === null ? "None" : `'${locale}'`;
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
item = prof.get_item(Key={'user_sub':'${ALICE_ID}'}).get('Item') or {'user_sub':'${ALICE_ID}'}
p = dict(item.get('profile') or {})
p['locale'] = ${literal}
item['profile'] = p
item['user_sub'] = '${ALICE_ID}'
prof.put_item(Item=item)
print('ok')
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
  );
}

// ─── 793. Supported locales + bundle API ─────────────────────────────────
test.describe("793. KYC i18n supported locales + bundle", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("793.1 user lists supported locales", async () => {
    const r = await apiGet(alicePage, `${BASE}/locales`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.default).toBe("en");
    const codes = body.locales.map((l: { code: string }) => l.code);
    expect(codes).toContain("es");
    expect(codes).toContain("ar");
  });

  test("793.2 Arabic locale is flagged RTL", async () => {
    const r = await apiGet(alicePage, `${BASE}/locales`);
    const body = await r.json();
    const ar = body.locales.find((l: { code: string }) => l.code === "ar");
    expect(ar.rtl).toBe(true);
  });

  test("793.3 get translation bundle for a locale", async () => {
    const r = await apiGet(alicePage, `${BASE}/translations/es`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.language).toBe("es");
    expect(typeof body.translations).toBe("object");
  });
});

// ─── 794. Translation CRUD API ───────────────────────────────────────────
test.describe("794. KYC translation CRUD API", () => {
  let rootPage: Page;
  let alicePage: Page;
  const key = `kyc.status.e2e_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("794.1 admin creates a Spanish translation", async () => {
    const r = await apiPut(rootPage, "root", `${BASE}/admin/translations/es/${key}`, {
      value: "Aprobado",
      context: "KYC case status",
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.value).toBe("Aprobado");
    expect(body.language_code).toBe("es");
    expect(body.updated_by).toBeTruthy();
  });

  test("794.2 admin lists translations with prefix filter", async () => {
    const r = await apiGet(rootPage, `${BASE}/admin/translations/es`, { prefix: `kyc.status.e2e_${TS}` });
    expect(r.status()).toBe(200);
    const body = await r.json();
    const found = body.items.find((it: { key: string }) => it.key === key);
    expect(found).toBeTruthy();
    expect(found.value).toBe("Aprobado");
  });

  test("794.3 created translation appears in the published bundle", async () => {
    const r = await apiGet(alicePage, `${BASE}/translations/es`, { prefix: `kyc.status.e2e_${TS}` });
    const body = await r.json();
    expect(body.translations[key]).toBe("Aprobado");
  });

  test("794.4 admin deletes a translation", async () => {
    const r = await apiDelete(rootPage, "root", `${BASE}/admin/translations/es/${key}`);
    expect(r.status()).toBe(200);
    const list = await apiGet(rootPage, `${BASE}/admin/translations/es`, { prefix: `kyc.status.e2e_${TS}` });
    const body = await list.json();
    expect(body.items.find((it: { key: string }) => it.key === key)).toBeFalsy();
  });

  test("794.5 unsupported locale rejected with 400", async () => {
    const r = await apiPut(rootPage, "root", `${BASE}/admin/translations/zz/kyc.status.x`, {
      value: "x",
    });
    expect(r.status()).toBe(400);
  });

  test("794.6 key not starting with kyc. rejected (422)", async () => {
    const r = await apiPut(rootPage, "root", `${BASE}/admin/translations/es/bad.key.${TS}`, {
      value: "x",
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 795. Fallback + questionnaire / legal notice localization ───────────
test.describe("795. KYC fallback + localized content", () => {
  let rootPage: Page;
  let alicePage: Page;
  const fbKey = `kyc.requirement.e2e_fb_${TS}`;
  const qSlug = `idv_${TS}`;
  const qId = `q_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    alicePage = await newIdentityPage(browser, "alice");
    // English-only key for fallback test
    await apiPut(rootPage, "root", `${BASE}/admin/translations/en/${fbKey}`, {
      value: "Please upload a document",
    });
    // Questionnaire Spanish translations
    await apiPut(rootPage, "root", `${BASE}/admin/translations/es/kyc.questionnaire.title.${qSlug}`, {
      value: "Verificación de Identidad",
    });
    await apiPut(rootPage, "root", `${BASE}/admin/translations/es/kyc.question.label.${qId}`, {
      value: "Nombre completo",
    });
    // French legal notice
    await apiPut(rootPage, "root", `${BASE}/admin/translations/fr/kyc.legal_notice.v_${TS}`, {
      value: "En signant ce document, vous attestez que les informations sont exactes.",
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
    await alicePage?.close();
  });

  test("795.1 missing Spanish key falls back to English in bundle", async () => {
    const r = await apiGet(alicePage, `${BASE}/translations/es`, { prefix: `kyc.requirement.e2e_fb_${TS}` });
    const body = await r.json();
    expect(body.translations[fbKey]).toBe("Please upload a document");
  });

  test("795.2 questionnaire localized to Spanish", async () => {
    const r = await apiPost(alicePage, "alice", `${BASE}/questionnaire/localized?lang=es`, {
      questionnaire: {
        slug: qSlug,
        title: "Identity Verification",
        description: "Verify your identity.",
        questions: [{ question_id: qId, label: "Full name", hint: "", type: "text" }],
      },
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.language).toBe("es");
    expect(body.questionnaire.title).toBe("Verificación de Identidad");
    expect(body.questionnaire.questions[0].label).toBe("Nombre completo");
  });

  test("795.3 legal notice returned in French", async () => {
    const r = await apiGet(alicePage, `${BASE}/legal-notice/v_${TS}`, { lang: "fr" });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.language).toBe("fr");
    expect(body.text).toContain("En signant");
    expect(body.is_fallback).toBe(false);
  });

  test("795.4 unsupported lang on questionnaire falls back to English", async () => {
    const r = await apiPost(alicePage, "alice", `${BASE}/questionnaire/localized?lang=zz`, {
      questionnaire: { slug: qSlug, title: "Identity Verification", questions: [] },
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.language).toBe("en");
    expect(body.questionnaire.title).toBe("Identity Verification");
  });
});

// ─── 796. Coverage + bulk import / export ────────────────────────────────
test.describe("796. KYC coverage + bulk import/export", () => {
  let rootPage: Page;
  const k1 = `kyc.ui.label.e2e_${TS}.one`;
  const k2 = `kyc.ui.label.e2e_${TS}.two`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("796.1 admin bulk imports translations", async () => {
    const r = await apiPost(rootPage, "root", `${BASE}/admin/translations/es/bulk-import`, {
      translations: { [k1]: "Uno", [k2]: "Dos", [`${k1}.empty`]: "" },
      status: "published",
    });
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.imported).toBe(2);
    expect(body.skipped).toBe(1);
  });

  test("796.2 bulk import updates existing keys (last-write-wins)", async () => {
    await apiPost(rootPage, "root", `${BASE}/admin/translations/es/bulk-import`, {
      translations: { [k1]: "Uno-actualizado" },
      status: "published",
    });
    const r = await apiGet(rootPage, `${BASE}/admin/translations/es`, { prefix: k1 });
    const body = await r.json();
    const found = body.items.find((it: { key: string }) => it.key === k1);
    expect(found.value).toBe("Uno-actualizado");
  });

  test("796.3 export returns full JSON map for a language", async () => {
    const r = await apiGet(rootPage, `${BASE}/admin/translations/es/export`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.language).toBe("es");
    expect(body.translations[k2]).toBe("Dos");
  });

  test("796.4 coverage report shows pct per language", async () => {
    const r = await apiGet(rootPage, `${BASE}/admin/coverage`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.languages.es).toBeTruthy();
    expect(body.languages.en.coverage_pct).toBe(1.0);
    expect(typeof body.languages.es.coverage_pct).toBe("number");
  });

  test("796.5 value exceeding 10000 chars rejected (422)", async () => {
    const big = "x".repeat(10001);
    const r = await apiPut(rootPage, "root", `${BASE}/admin/translations/es/kyc.error.toolong_${TS}`, {
      value: big,
    });
    expect(r.status()).toBe(422);
  });
});

// ─── 797. Locale resolution + RTL ────────────────────────────────────────
test.describe("797. KYC locale resolution", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    setAliceLocale(null);
    await alicePage?.close();
  });

  test("797.1 profile locale respected for /me/locale", async () => {
    setAliceLocale("es");
    const r = await apiGet(alicePage, `${BASE}/me/locale`);
    expect(r.status()).toBe(200);
    const body = await r.json();
    expect(body.language).toBe("es");
  });

  test("797.2 Accept-Language used when profile locale unset", async () => {
    setAliceLocale(null);
    const r = await alicePage.request.get(`${API}/${BASE}/me/locale`, {
      headers: { "Accept-Language": "fr-FR,fr;q=0.9" },
    });
    const body = await r.json();
    expect(body.language).toBe("fr");
  });

  test("797.3 unsupported Accept-Language falls back to default", async () => {
    setAliceLocale(null);
    const r = await alicePage.request.get(`${API}/${BASE}/me/locale`, {
      headers: { "Accept-Language": "zz" },
    });
    const body = await r.json();
    expect(body.language).toBe("en");
  });

  test("797.4 Arabic bundle reports rtl=true", async () => {
    const r = await apiGet(alicePage, `${BASE}/translations/ar`);
    const body = await r.json();
    expect(body.rtl).toBe(true);
  });
});

// ─── 798. Auth enforcement ───────────────────────────────────────────────
test.describe("798. KYC i18n auth enforcement", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });
  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("798.1 non-admin cannot upsert a translation (403)", async () => {
    const r = await apiPut(alicePage, "alice", `${BASE}/admin/translations/es/kyc.status.hack_${TS}`, {
      value: "hack",
    });
    expect(r.status()).toBe(403);
  });

  test("798.2 non-admin cannot view coverage (403)", async () => {
    const r = await apiGet(alicePage, `${BASE}/admin/coverage`);
    expect(r.status()).toBe(403);
  });

  test("798.3 anonymous request to bundle is rejected (401)", async ({ request }) => {
    const r = await request.get(`${API}/${BASE}/translations/es`);
    expect(r.status()).toBe(401);
  });
});

// ─── 799. Admin translation management UI ────────────────────────────────
test.describe("799. KYC translation management UI", () => {
  let rootPage: Page;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    rootPage = await newIdentityPage(browser, "root");
    // seed a published Spanish key so the table shows a row
    await apiPut(rootPage, "root", `${BASE}/admin/translations/es/kyc.status.ui_${TS}`, {
      value: "En Revisión",
      context: "ui test",
    });
  });
  test.afterAll(async () => {
    await rootPage?.close();
  });

  test("799.1 admin sees translation editor with language selector", async () => {
    await rootPage.goto("/admin/kyc/translations");
    await expect(rootPage.getByTestId("kyc-lang-select")).toBeVisible({ timeout: 15_000 });
    await expect(rootPage.getByTestId("kyc-coverage-bar")).toBeVisible();
  });

  test("799.2 admin adds a translation inline", async () => {
    await rootPage.goto("/admin/kyc/translations");
    const newKey = `kyc.ui.label.uiadd_${TS}`;
    await rootPage.getByTestId("kyc-new-key").fill(newKey);
    await rootPage.getByTestId("kyc-new-value").fill("Etiqueta de prueba");
    await rootPage.getByTestId("kyc-add-btn").click();
    // verify via API that the value landed
    await expect(async () => {
      const r = await apiGet(rootPage, `${BASE}/admin/translations/es`, { prefix: newKey });
      const body = await r.json();
      expect(body.items.find((it: { key: string }) => it.key === newKey)?.value).toBe(
        "Etiqueta de prueba",
      );
    }).toPass({ timeout: 10_000 });
  });
});
