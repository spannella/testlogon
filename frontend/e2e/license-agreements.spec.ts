/**
 * E2E tests for LICENSE-001 — License Agreement Upload & Management.
 *
 * Section 463: Agreement Upload API (4 tests)
 * Section 464: Agreement Metadata & Download API (4 tests)
 * Section 465: Content Linking API (4 tests)
 * Section 466: Admin Review API (4 tests)
 *
 * Auth: role-bearing cookies from e2e_admin_session_setup.py. Multipart upload
 * + JSON POSTs carry the x-csrf-token header (required by require_ui_session
 * when the ui_session cookie is present). Admin endpoints require admin/root.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// Minimal valid one-page PDF.
const PDF_BYTES = Buffer.from(
  "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
    "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
    "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>endobj\n" +
    "trailer<</Root 1 0 R>>\n%%EOF\n",
  "utf-8",
);

async function uploadAgreement(
  page: Page,
  identity: string,
  fields: Record<string, string>,
  fileName = "agreement.pdf",
  fileBytes = PDF_BYTES,
  mimeType = "application/pdf",
) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/ui/licenses/agreements`, {
    headers: { "x-csrf-token": sess.csrf_token },
    multipart: {
      ...fields,
      file: { name: fileName, mimeType, buffer: fileBytes },
    },
  });
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
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

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}/${path}`);
}

// ─── 463. Agreement Upload API ──────────────────────────────────────────────

test.describe("463. License Agreement Upload API", () => {
  let alicePage: Page;
  const TS = Date.now();
  let licenseId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("463.1 Alice uploads a PDF license agreement", async () => {
    const r = await uploadAgreement(alicePage, "alice", {
      title: `Epidemic Pack ${TS}`,
      licensor_name: "Epidemic Sound AB",
      license_type: "royalty_free",
      territory: "worldwide",
      notes: "Covers all tracks",
    });
    expect(r.status()).toBe(200);
    const data = (await r.json()) as Record<string, unknown>;
    expect(typeof data.license_id).toBe("string");
    expect(data.status).toBe("pending_review");
    expect(data.file_name).toBe("agreement.pdf");
    licenseId = data.license_id as string;
  });

  test("463.2 Agreement appears in creator's list", async () => {
    const r = await apiGet(alicePage, "ui/licenses/agreements");
    expect(r.status()).toBe(200);
    const data = (await r.json()) as { items: Array<Record<string, unknown>> };
    const found = data.items.find((i) => i.license_id === licenseId);
    expect(found).toBeTruthy();
    expect(found?.title).toBe(`Epidemic Pack ${TS}`);
  });

  test("463.3 Agreement detail returns all fields", async () => {
    const r = await apiGet(alicePage, `ui/licenses/agreements/${licenseId}`);
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.title).toBe(`Epidemic Pack ${TS}`);
    expect(d.licensor_name).toBe("Epidemic Sound AB");
    expect(d.license_type).toBe("royalty_free");
    expect(d.territory).toBe("worldwide");
    expect(Number(d.file_size)).toBeGreaterThan(0);
  });

  test("463.4 Invalid file type is rejected", async () => {
    const r = await uploadAgreement(
      alicePage,
      "alice",
      {
        title: `Bad File ${TS}`,
        licensor_name: "x",
        license_type: "custom",
      },
      "malware.exe",
      Buffer.from("MZ\x90\x00bad", "binary"),
      "application/octet-stream",
    );
    expect(r.status()).toBe(400);
    const d = (await r.json()) as Record<string, unknown>;
    expect(JSON.stringify(d).toLowerCase()).toContain("mime");
  });
});

// ─── 464. Agreement Metadata & Download API ─────────────────────────────────

test.describe("464. Agreement Metadata & Download API", () => {
  let alicePage: Page;
  let bobPage: Page;
  const TS = Date.now();
  let licenseId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    const r = await uploadAgreement(alicePage, "alice", {
      title: `Meta Test ${TS}`,
      licensor_name: "Licensor Inc",
      license_type: "commercial",
      territory: "US",
    });
    const data = (await r.json()) as Record<string, unknown>;
    licenseId = data.license_id as string;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("464.1 Creator updates agreement metadata", async () => {
    const r = await apiPatch(
      alicePage,
      "alice",
      `ui/licenses/agreements/${licenseId}`,
      { title: `Meta Updated ${TS}`, territory: "worldwide" },
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.title).toBe(`Meta Updated ${TS}`);
    expect(d.territory).toBe("worldwide");
    expect(Number(d.version)).toBeGreaterThanOrEqual(2);
  });

  test("464.2 Agreement download returns a URL", async () => {
    const r = await apiGet(
      alicePage,
      `ui/licenses/agreements/${licenseId}/download`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(typeof d.download_url).toBe("string");
    expect((d.download_url as string).length).toBeGreaterThan(0);
  });

  test("464.3 Non-owner cannot access agreement", async () => {
    const r = await apiGet(
      bobPage,
      `ui/licenses/agreements/${licenseId}`,
    );
    expect(r.status()).toBe(404);
  });

  test("464.4 Soft-delete removes agreement from list", async () => {
    const del = await apiDelete(
      alicePage,
      "alice",
      `ui/licenses/agreements/${licenseId}`,
    );
    expect(del.status()).toBe(200);
    const r = await apiGet(alicePage, "ui/licenses/agreements");
    const data = (await r.json()) as { items: Array<Record<string, unknown>> };
    expect(data.items.find((i) => i.license_id === licenseId)).toBeFalsy();
  });
});

// ─── 465. Content Linking API ───────────────────────────────────────────────

test.describe("465. Content Linking API", () => {
  let alicePage: Page;
  const TS = Date.now();
  let licenseId = "";
  const contentId = `vid_${TS}`;

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    const r = await uploadAgreement(alicePage, "alice", {
      title: `Link Test ${TS}`,
      licensor_name: "Licensor Inc",
      license_type: "creative_commons",
    });
    const data = (await r.json()) as Record<string, unknown>;
    licenseId = data.license_id as string;
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("465.1 Link content to agreement", async () => {
    const r = await apiPost(
      alicePage,
      "alice",
      `ui/licenses/agreements/${licenseId}/link`,
      { content_id: contentId, content_type: "video" },
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.content_id).toBe(contentId);
    expect(d.content_type).toBe("video");
    expect(d.license_id).toBe(licenseId);
  });

  test("465.2 List content for agreement", async () => {
    const r = await apiGet(
      alicePage,
      `ui/licenses/agreements/${licenseId}/content`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { items: Array<Record<string, unknown>> };
    expect(d.items.find((i) => i.content_id === contentId)).toBeTruthy();
  });

  test("465.3 List licenses for content item", async () => {
    const r = await apiGet(
      alicePage,
      `ui/licenses/agreements/content/${contentId}/licenses`,
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { items: Array<Record<string, unknown>> };
    expect(d.items.find((i) => i.license_id === licenseId)).toBeTruthy();
  });

  test("465.4 Unlink content from agreement", async () => {
    const del = await apiDelete(
      alicePage,
      "alice",
      `ui/licenses/agreements/${licenseId}/link/${contentId}`,
    );
    expect(del.status()).toBe(200);
    const r = await apiGet(
      alicePage,
      `ui/licenses/agreements/${licenseId}/content`,
    );
    const d = (await r.json()) as { items: Array<Record<string, unknown>> };
    expect(d.items.find((i) => i.content_id === contentId)).toBeFalsy();
  });
});

// ─── 466. Admin Review API ──────────────────────────────────────────────────

test.describe("466. Admin Review API", () => {
  let alicePage: Page;
  let charliePage: Page;
  const TS = Date.now();
  let verifyId = "";
  let rejectId = "";

  test.beforeAll(async ({ browser }) => {
    getSessions();
    alicePage = await newIdentityPage(browser, "alice");
    charliePage = await newIdentityPage(browser, "charlie_admin");
    const r1 = await uploadAgreement(alicePage, "alice", {
      title: `Review Verify ${TS}`,
      licensor_name: "Licensor Inc",
      license_type: "editorial",
    });
    verifyId = ((await r1.json()) as Record<string, unknown>).license_id as string;
    const r2 = await uploadAgreement(alicePage, "alice", {
      title: `Review Reject ${TS}`,
      licensor_name: "Licensor Inc",
      license_type: "editorial",
    });
    rejectId = ((await r2.json()) as Record<string, unknown>).license_id as string;
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await charliePage?.close();
  });

  test("466.1 Admin sees pending agreement in review queue", async () => {
    const r = await apiGet(charliePage, "ui/admin/licenses/review?limit=100");
    expect(r.status()).toBe(200);
    const d = (await r.json()) as { items: Array<Record<string, unknown>> };
    expect(d.items.find((i) => i.license_id === verifyId)).toBeTruthy();
  });

  test("466.2 Admin verifies agreement", async () => {
    const r = await apiPost(
      charliePage,
      "charlie_admin",
      `ui/admin/licenses/review/${verifyId}`,
      { verified: true },
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.status).toBe("active");
  });

  test("466.3 Admin rejects agreement with reason", async () => {
    const r = await apiPost(
      charliePage,
      "charlie_admin",
      `ui/admin/licenses/review/${rejectId}`,
      { verified: false, rejection_reason: "Illegible" },
    );
    expect(r.status()).toBe(200);
    const d = (await r.json()) as Record<string, unknown>;
    expect(d.status).toBe("rejected");
    expect(d.rejection_reason).toBe("Illegible");
  });

  test("466.4 Non-admin cannot access review queue", async () => {
    const r = await apiGet(alicePage, "ui/admin/licenses/review");
    expect(r.status()).toBe(403);
  });
});
