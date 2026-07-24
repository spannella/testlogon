/**
 * E2E tests for the SuiteCRM Document Library cluster (EVT-011..013).
 *
 * Backend: additive endpoints on the file-manager router (`/v1/fs`), gated by
 * the `crm_document_library_enabled` flag (default OFF → both new endpoints
 * return 404). See app/routers/filemanager.py + docs/suitecrm/specs/EVT-011.md.
 *
 * Sections:
 *   1 — CRM metadata PATCH + crm-search API (flag-aware)
 *   2 — Cross-user isolation (flag-aware)
 *   3 — CrmDocuments UI (list / upload / detail)
 *
 * Auth: uses e2e_admin_session_setup.py (all identities).
 *
 * DO NOT RUN as part of authoring — these are authored to mirror tickets.spec.ts.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID    = "e2e_bob@test.local";
const TS       = Date.now();

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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

async function injectAuth(page: Page, identity: string): Promise<void> {
  const session = getAdminSessions()[identity];
  if (!session) throw new Error(`No session for identity: ${identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate(
    ([userId, accessToken]: [string, string]) => {
      const state = { userId, accessToken, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    [session.user_sub, session.access_token],
  );
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getAdminSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

/** Upload a small text file as the given identity. */
async function ensureFolder(page: Page, identity: string, path: string) {
  const sess = getAdminSessions()[identity];
  // Idempotent: 200 on create, ~409/400 if it already exists — both fine.
  return page.request.post(`${API}/v1/fs/folder`, {
    headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
    data: { path },
  });
}

async function uploadFile(page: Page, identity: string, path: string, content: string) {
  const sess = getAdminSessions()[identity];
  // The upload endpoint requires the parent folder to already exist.
  const parent = path.substring(0, path.lastIndexOf("/")) || "/";
  if (parent !== "/") {
    await ensureFolder(page, identity, parent);
  }
  return page.request.post(`${API}/v1/fs/upload`, {
    params: { path, overwrite: "true" },
    headers: { "x-csrf-token": sess.csrf_token },
    multipart: {
      file: { name: path.split("/").pop()!, mimeType: "text/plain", buffer: Buffer.from(content) },
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 1 — CRM metadata PATCH + crm-search API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 1: CRM document metadata + search (API)", () => {
  let alicePage: Page;
  const docPath = `/crm-documents/contract_${TS}.txt`;
  const recordId = `contact_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    await uploadFile(alicePage, "alice", docPath, "hello crm");
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("PATCH crm-metadata sets all fields (or 404 when flag off)", async () => {
    const res = await apiPatch(alicePage, "alice", `v1/fs/crm-metadata?path=${encodeURIComponent(docPath)}`, {
      crm_category: "Contracts",
      crm_description: "An important contract",
      linked_record_type: "contact",
      linked_record_id: recordId,
    });
    if (res.status() === 404) {
      // Flag off — feature gated. Acceptable default state.
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.path).toBe(docPath);
    expect(body.crm_category).toBe("Contracts");
    expect(body.linked_record_type).toBe("contact");
    expect(body.linked_record_id).toBe(recordId);
    expect(body.crm_metadata_updated_at).toBeTruthy();
  });

  test("crm-search finds the linked document (or 404 when flag off)", async () => {
    const res = await apiGet(alicePage, "v1/fs/crm-search", {
      linked_record_type: "contact",
      linked_record_id: recordId,
    });
    if (res.status() === 404) {
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.items)).toBe(true);
    const match = body.items.find((d: { path: string }) => d.path === docPath);
    expect(match).toBeTruthy();
    expect(match.linked_record_id).toBe(recordId);
  });

  test("invalid linked_record_type is rejected (when flag on)", async () => {
    const res = await apiPatch(alicePage, "alice", `v1/fs/crm-metadata?path=${encodeURIComponent(docPath)}`, {
      linked_record_type: "invoice",
      linked_record_id: "x",
    });
    // 404 (flag off) or 400 (invalid type). Never 200.
    expect([400, 404]).toContain(res.status());
  });

  test("linked record pair must be atomic (when flag on)", async () => {
    const res = await apiPatch(alicePage, "alice", `v1/fs/crm-metadata?path=${encodeURIComponent(docPath)}`, {
      linked_record_type: "contact",
    });
    expect([400, 404]).toContain(res.status());
  });

  test("clearing fields removes the link (when flag on)", async () => {
    const res = await apiPatch(alicePage, "alice", `v1/fs/crm-metadata?path=${encodeURIComponent(docPath)}`, {
      crm_category: null,
      crm_description: null,
      linked_record_type: null,
      linked_record_id: null,
    });
    if (res.status() === 404) {
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.linked_record_type).toBeNull();
    expect(body.crm_category).toBeNull();
  });

  test("GET /info does not expose CRM fields (additive-only)", async () => {
    const res = await apiGet(alicePage, "v1/fs/info", { path: docPath });
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body).not.toHaveProperty("crm_category");
    expect(body).not.toHaveProperty("linked_record_type");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 2 — Cross-user isolation
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 2: cross-user isolation (API)", () => {
  let alicePage: Page;
  let bobPage: Page;
  const docPath = `/crm-documents/isolated_${TS}.txt`;
  const recordId = `account_${TS}`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    await uploadFile(alicePage, "alice", docPath, "alice only");
    await apiPatch(alicePage, "alice", `v1/fs/crm-metadata?path=${encodeURIComponent(docPath)}`, {
      linked_record_type: "account",
      linked_record_id: recordId,
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("Bob cannot see Alice's linked documents (when flag on)", async () => {
    const res = await apiGet(bobPage, "v1/fs/crm-search", {
      linked_record_type: "account",
      linked_record_id: recordId,
    });
    if (res.status() === 404) {
      expect(res.status()).toBe(404);
      return;
    }
    expect(res.status()).toBe(200);
    const body = await res.json();
    const match = body.items.find((d: { path: string }) => d.path === docPath);
    expect(match).toBeFalsy();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 3 — CrmDocuments UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 3: CrmDocuments UI", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("list page renders the search form", async () => {
    await page.goto(`${BASE}/crm/documents`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "CRM Documents" })).toBeVisible();
    // Either the search UI (flag on) or the not-enabled card (flag off).
    const hasSearch = await page.getByText("Find by linked record").isVisible().catch(() => false);
    const hasNotEnabled = await page
      .getByText(/Document Library is not enabled/i)
      .isVisible()
      .catch(() => false);
    expect(hasSearch || hasNotEnabled).toBe(true);
  });

  test("upload page renders source + metadata cards", async () => {
    await page.goto(`${BASE}/crm/documents/upload`, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: /Upload & link document/i })).toBeVisible();
    await expect(page.getByText("CRM metadata")).toBeVisible();
  });

  test("detail page renders for an encoded path", async () => {
    const enc = encodeURIComponent(`/crm-documents/contract_${TS}.txt`);
    await page.goto(`${BASE}/crm/documents/detail/${enc}`, { waitUntil: "domcontentloaded" });
    // Either file details (exists) or not-found / not-enabled state. Poll for a
    // terminal state — the info query may show a loading skeleton briefly first.
    await expect(
      page.getByText(/File details|Document not found|not enabled/i).first(),
    ).toBeVisible({ timeout: 15_000 });
  });
});
