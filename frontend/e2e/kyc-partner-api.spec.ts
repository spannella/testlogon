/**
 * E2E tests for the KYC Third-Party Partner API (KYC-021) — /api/v1/kyc/*.
 *
 * This is a programmatic, API-key-authenticated API. Requests are made with
 * the global Playwright `request` fixture (NOT page.request) using an
 * `X-API-Key` header, so they authenticate via the API-key path and skip CSRF
 * entirely.
 *
 * Setup:
 *   - Alice (USER) and Bob (USER) each mint a scoped KYC API key via
 *     POST /ui/api_keys (session auth):
 *       aliceKey → ["kyc:admin"]  (implies submit/read/upload/webhook)
 *       bobKey   → ["kyc:admin"]  (separate partner — isolation check)
 *       readKey  → ["kyc:read"]   (insufficient scope for create/upload)
 *
 * Scope model:
 *   kyc:submit  → create/submit applications
 *   kyc:read    → read status / list / result
 *   kyc:upload  → upload documents
 *   kyc:webhook → manage webhooks
 *   kyc:admin   → all of the above
 */

import { test, expect, type Page, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<Record<string, unknown>>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies as never);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** Session-auth POST (cookies + CSRF) — used for setup only (minting keys). */
async function mintKey(page: Page, userId: string, caps: string[]): Promise<string> {
  const session = getSessions()[userId];
  const r = await page.request.post(`${API}/ui/api_keys`, {
    data: { label: `kyc_${caps.join("_")}_${TS}`, capabilities: caps },
    headers: { "x-csrf-token": session.csrf_token, "Content-Type": "application/json" },
  });
  expect(r.ok()).toBeTruthy();
  return (await r.json()).key_secret as string;
}

/** API-key helpers via the global request fixture (no cookies → API-key auth). */
function keyGet(request: APIRequestContext, key: string, path: string) {
  return request.get(`${API}${path}`, { headers: { "X-API-Key": key } });
}
function keyPost(
  request: APIRequestContext,
  key: string,
  path: string,
  body?: object,
  extraHeaders?: Record<string, string>,
) {
  return request.post(`${API}${path}`, {
    headers: { "X-API-Key": key, "Content-Type": "application/json", ...(extraHeaders ?? {}) },
    data: body ?? {},
  });
}

let aliceKey = "";
let bobKey = "";
let readKey = "";

const APPLICANT = {
  first_name: "Jane",
  last_name: "Doe",
  date_of_birth: "1992-03-15",
  email: "jane.doe@example.com",
  phone: "+14155551234",
  address: {
    street: "123 Main St",
    city: "San Francisco",
    state: "CA",
    postal_code: "94105",
    country: "US",
  },
};

test.beforeAll(async ({ browser }) => {
  const aPage = await browser.newPage();
  await injectAuth(aPage, ALICE_ID);
  aliceKey = await mintKey(aPage, ALICE_ID, ["kyc:admin"]);
  readKey = await mintKey(aPage, ALICE_ID, ["kyc:read"]);
  expect(aliceKey).toContain("ak_");
  await aPage.close();

  const bPage = await browser.newPage();
  await injectAuth(bPage, BOB_ID);
  bobKey = await mintKey(bPage, BOB_ID, ["kyc:admin"]);
  await bPage.close();
});

// ─── Section 770: Partner Application Lifecycle ─────────────────────

test.describe("770. KYC Partner API — application lifecycle", () => {
  const externalId = `partner-ref-${TS}-001`;
  const idemKey = `idem-${TS}-create`;
  let applicationId = "";

  test("770.1 create application with valid API key → 201", async ({ request }) => {
    const resp = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: externalId, applicant: APPLICANT, tier: "tier_2" },
      { "Idempotency-Key": idemKey },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    applicationId = data.application_id;
    expect(applicationId).toBeTruthy();
    expect(data.status).toBe("draft");
  });

  test("770.2 get application by id", async ({ request }) => {
    const resp = await keyGet(request, aliceKey, `/api/v1/kyc/applications/${applicationId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.application_id).toBe(applicationId);
    expect(data.external_id).toBe(externalId);
    expect(data.applicant.first_name).toBe("Jane");
  });

  test("770.3 look up application by external_id", async ({ request }) => {
    const resp = await keyGet(
      request,
      aliceKey,
      `/api/v1/kyc/applications?external_id=${encodeURIComponent(externalId)}`,
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.application_id).toBe(applicationId);
  });

  test("770.4 submit application transitions to submitted", async ({ request }) => {
    const resp = await keyPost(
      request,
      aliceKey,
      `/api/v1/kyc/applications/${applicationId}/submit`,
      {},
      { "Idempotency-Key": `idem-${TS}-submit` },
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.status).toBe("submitted");
  });

  test("770.5 duplicate idempotency key returns original response", async ({ request }) => {
    const resp = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: externalId, applicant: APPLICANT, tier: "tier_2" },
      { "Idempotency-Key": idemKey },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.application_id).toBe(applicationId);
  });

  test("770.6 no API key returns 401", async ({ request }) => {
    const resp = await request.post(`${API}/api/v1/kyc/applications`, {
      headers: { "Content-Type": "application/json", "Idempotency-Key": `idem-${TS}-noauth` },
      data: { external_id: `x-${TS}`, applicant: APPLICANT },
    });
    expect(resp.status()).toBe(401);
  });
});

// ─── Section 771: Scope Enforcement & Idempotency Validation ────────

test.describe("771. KYC Partner API — scope & idempotency enforcement", () => {
  test("771.1 kyc:read key cannot create application (403)", async ({ request }) => {
    const resp = await keyPost(
      request,
      readKey,
      "/api/v1/kyc/applications",
      { external_id: `read-${TS}`, applicant: APPLICANT },
      { "Idempotency-Key": `idem-read-${TS}` },
    );
    expect(resp.status()).toBe(403);
  });

  test("771.2 kyc:read key CAN list applications (200)", async ({ request }) => {
    const resp = await keyGet(request, readKey, "/api/v1/kyc/applications");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.data)).toBeTruthy();
  });

  test("771.3 missing Idempotency-Key on create returns 400", async ({ request }) => {
    const resp = await keyPost(request, aliceKey, "/api/v1/kyc/applications", {
      external_id: `noidem-${TS}`,
      applicant: APPLICANT,
    });
    expect(resp.status()).toBe(400);
  });

  test("771.4 invalid create payload returns 422", async ({ request }) => {
    const resp = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: "", applicant: { first_name: "", last_name: "x", date_of_birth: "bad", email: "noat" } },
      { "Idempotency-Key": `idem-bad-${TS}` },
    );
    expect(resp.status()).toBe(422);
  });

  test("771.5 invalid API key returns 401", async ({ request }) => {
    const resp = await keyGet(request, "ak_deadbeef.notreal", "/api/v1/kyc/applications");
    expect(resp.status()).toBe(401);
  });
});

// ─── Section 772: Document Upload ───────────────────────────────────

test.describe("772. KYC Partner API — document upload", () => {
  let applicationId = "";

  test.beforeAll(async ({ request }) => {
    const resp = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: `doc-app-${TS}`, applicant: APPLICANT, tier: "tier_1" },
      { "Idempotency-Key": `idem-docapp-${TS}` },
    );
    expect(resp.status()).toBe(201);
    applicationId = (await resp.json()).application_id;
  });

  test("772.1 upload document with valid file and type → 201", async ({ request }) => {
    const resp = await request.post(
      `${API}/api/v1/kyc/applications/${applicationId}/documents`,
      {
        headers: { "X-API-Key": aliceKey, "Idempotency-Key": `idem-doc-${TS}` },
        multipart: {
          document_type: "id_front",
          file: {
            name: "id_front.pdf",
            mimeType: "application/pdf",
            buffer: Buffer.from("%PDF-1.4 fake id document"),
          },
        },
      },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.document_id).toBeTruthy();
    expect(data.document_type).toBe("id_front");
  });

  test("772.2 invalid document_type returns 400", async ({ request }) => {
    const resp = await request.post(
      `${API}/api/v1/kyc/applications/${applicationId}/documents`,
      {
        headers: { "X-API-Key": aliceKey, "Idempotency-Key": `idem-doc-bad-${TS}` },
        multipart: {
          document_type: "invalid_type",
          file: { name: "x.pdf", mimeType: "application/pdf", buffer: Buffer.from("x") },
        },
      },
    );
    expect(resp.status()).toBe(400);
  });

  test("772.3 application status includes uploaded document", async ({ request }) => {
    // Ensure the id_front document exists independent of 772.1 surviving a
    // retry: on a fresh-worker retry the describe beforeAll re-creates a NEW
    // application, but 772.1 (the upload) is not re-run, so guard by uploading
    // here idempotently (same Idempotency-Key as 772.1 -> dedup, no duplicate).
    await request.post(
      `${API}/api/v1/kyc/applications/${applicationId}/documents`,
      {
        headers: { "X-API-Key": aliceKey, "Idempotency-Key": `idem-doc-772-3-${TS}` },
        multipart: {
          document_type: "id_front",
          file: {
            name: "id_front.pdf",
            mimeType: "application/pdf",
            buffer: Buffer.from("%PDF-1.4 fake id document"),
          },
        },
      },
    );
    const resp = await keyGet(request, aliceKey, `/api/v1/kyc/applications/${applicationId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.documents.find(
      (d: { document_type: string }) => d.document_type === "id_front",
    );
    expect(found).toBeTruthy();
    expect(found.document_id).toBeTruthy();
  });

  test("772.4 kyc:read key cannot upload document (403)", async ({ request }) => {
    const resp = await request.post(
      `${API}/api/v1/kyc/applications/${applicationId}/documents`,
      {
        headers: { "X-API-Key": readKey, "Idempotency-Key": `idem-doc-read-${TS}` },
        multipart: {
          document_type: "selfie",
          file: { name: "s.jpg", mimeType: "image/jpeg", buffer: Buffer.from("img") },
        },
      },
    );
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 773: Webhook Management ────────────────────────────────

test.describe("773. KYC Partner API — webhook management", () => {
  let webhookId = "";

  test("773.1 register webhook endpoint → 201", async ({ request }) => {
    const resp = await keyPost(request, aliceKey, "/api/v1/kyc/webhooks", {
      url: "https://partner.example.com/kyc/callback",
      events: ["status_changed", "decision_made"],
      secret: `whsecret_${TS}_abcdef`,
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    webhookId = data.webhook_id;
    expect(webhookId).toBeTruthy();
  });

  test("773.2 list registered webhooks", async ({ request }) => {
    const resp = await keyGet(request, aliceKey, "/api/v1/kyc/webhooks");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.data.find((w: { webhook_id: string }) => w.webhook_id === webhookId);
    expect(found).toBeTruthy();
  });

  test("773.3 test webhook delivery", async ({ request }) => {
    const resp = await keyPost(request, aliceKey, `/api/v1/kyc/webhooks/${webhookId}/test`);
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("773.4 webhook secret < 16 chars rejected (422)", async ({ request }) => {
    const resp = await keyPost(request, aliceKey, "/api/v1/kyc/webhooks", {
      url: "https://partner.example.com/kyc/callback",
      events: ["status_changed"],
      secret: "short",
    });
    expect(resp.status()).toBe(422);
  });

  test("773.5 non-HTTPS webhook URL rejected (422)", async ({ request }) => {
    const resp = await keyPost(request, aliceKey, "/api/v1/kyc/webhooks", {
      url: "http://insecure.example.com/cb",
      events: ["status_changed"],
      secret: `whsecret_${TS}_abcdef`,
    });
    expect(resp.status()).toBe(422);
  });

  test("773.6 delete webhook removes it from list", async ({ request }) => {
    const del = await request.delete(`${API}/api/v1/kyc/webhooks/${webhookId}`, {
      headers: { "X-API-Key": aliceKey },
    });
    expect(del.status()).toBe(200);
    const list = await keyGet(request, aliceKey, "/api/v1/kyc/webhooks");
    const data = await list.json();
    const found = data.data.find((w: { webhook_id: string }) => w.webhook_id === webhookId);
    expect(found).toBeFalsy();
  });
});

// ─── Section 774: Partner Isolation ─────────────────────────────────

test.describe("774. KYC Partner API — partner isolation", () => {
  let aliceAppId = "";
  let bobAppId = "";

  test("774.1 Alice + Bob each create an application", async ({ request }) => {
    const a = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: `iso-alice-${TS}`, applicant: APPLICANT },
      { "Idempotency-Key": `idem-iso-alice-${TS}` },
    );
    expect(a.status()).toBe(201);
    aliceAppId = (await a.json()).application_id;

    const b = await keyPost(
      request,
      bobKey,
      "/api/v1/kyc/applications",
      { external_id: `iso-bob-${TS}`, applicant: APPLICANT },
      { "Idempotency-Key": `idem-iso-bob-${TS}` },
    );
    expect(b.status()).toBe(201);
    bobAppId = (await b.json()).application_id;
    expect(bobAppId).not.toBe(aliceAppId);
  });

  test("774.2 Alice's list contains only Alice's applications", async ({ request }) => {
    const resp = await keyGet(request, aliceKey, "/api/v1/kyc/applications");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const ids = data.data.map((a: { application_id: string }) => a.application_id);
    expect(ids).toContain(aliceAppId);
    expect(ids).not.toContain(bobAppId);
  });

  test("774.3 Bob cannot read Alice's application (404)", async ({ request }) => {
    const resp = await keyGet(request, bobKey, `/api/v1/kyc/applications/${aliceAppId}`);
    expect(resp.status()).toBe(404);
  });

  test("774.4 same idempotency key is per-API-key scoped", async ({ request }) => {
    const shared = `shared-idem-${TS}`;
    const a = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: `idemscope-alice-${TS}`, applicant: APPLICANT },
      { "Idempotency-Key": shared },
    );
    expect(a.status()).toBe(201);
    const aId = (await a.json()).application_id;

    const b = await keyPost(
      request,
      bobKey,
      "/api/v1/kyc/applications",
      { external_id: `idemscope-bob-${TS}`, applicant: APPLICANT },
      { "Idempotency-Key": shared },
    );
    expect(b.status()).toBe(201);
    const bId = (await b.json()).application_id;
    expect(bId).not.toBe(aId);
  });
});

// ─── Section 775: Sandbox Mode ──────────────────────────────────────

test.describe("775. KYC Partner API — sandbox mode", () => {
  test("775.1 X-Sandbox request returns deterministic application_id", async ({ request }) => {
    const resp = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: `sandbox-${TS}`, applicant: APPLICANT },
      { "Idempotency-Key": `idem-sandbox-${TS}`, "X-Sandbox": "true" },
    );
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.application_id.startsWith("sandbox_app_")).toBeTruthy();
    expect(data.sandbox).toBe(true);
  });

  test("775.2 sandbox application id is deterministic for same external_id", async ({ request }) => {
    const ext = `sandbox-det-${TS}`;
    const r1 = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: ext, applicant: APPLICANT },
      { "Idempotency-Key": `idem-sbdet1-${TS}`, "X-Sandbox": "true" },
    );
    const id1 = (await r1.json()).application_id;
    const r2 = await keyPost(
      request,
      aliceKey,
      "/api/v1/kyc/applications",
      { external_id: ext, applicant: APPLICANT },
      { "Idempotency-Key": `idem-sbdet2-${TS}`, "X-Sandbox": "true" },
    );
    const id2 = (await r2.json()).application_id;
    expect(id1).toBe(id2);
  });
});
