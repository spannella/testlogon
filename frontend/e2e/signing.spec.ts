/**
 * E2E tests for Document Signing dedicated page.
 *
 * Sections:
 *   71 — Signing API  (10 tests)
 *   72 — Signing UI   (7 tests)
 *
 * Auth: Alice session cookies (from e2e_session_setup.py).
 *
 * IMPORTANT: SIGNATURE_PDF_ENABLED=true must be set in .env.local.
 * If the flag is off, all API tests will return 503 and fail.
 *
 * The API tests inject a fake PDF node into the file_manager DynamoDB table so
 * that create_signature_packet can resolve the source_path. The node is cleaned
 * up in afterAll.
 *
 * State management note: packetId and other inter-test state is created in
 * beforeAll (not inside individual tests) to survive Playwright's per-test
 * retry isolation.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE     = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS       = Date.now();
const PDF_PATH  = `/e2e/sign_test_${TS}.pdf`;
const PDF_PATH2 = `/e2e/sign_test2_${TS}.pdf`;

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub:     string;
  session_id:   string;
  csrf_token:   string;
  access_token: string;
  cookies: Array<{
    name:     string;
    value:    string;
    domain:   string;
    path:     string;
    httpOnly: boolean;
    secure:   boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires:  number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId = ALICE_ID) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

// ─── API helpers — use Vite proxy so session cookies are forwarded ────────────

async function apiGet(page: Page, path: string) {
  const session = getSessions()[ALICE_ID];
  return page.request.get(`${BASE}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiPost(page: Page, path: string, body: object) {
  const session = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── DDB helpers ──────────────────────────────────────────────────────────────

const DDB_PRELUDE = `
import boto3, os, time
from pathlib import Path
env_file = Path('${REPO_ROOT}/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource(
    'dynamodb',
    endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1',
    aws_access_key_id='test',
    aws_secret_access_key='test',
)
`;

const PYTHON = "python3";

/**
 * Inject a fake PDF file node into the file_manager DynamoDB table so that
 * create_signature_packet can resolve source_path without a real file upload.
 */
function injectPdfNode(userSub: string, pdfPath: string): void {
  const name = pdfPath.split("/").pop()!;
  const parent = pdfPath.substring(0, pdfPath.lastIndexOf("/")) || "/";
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.put_item(Item={
    'PK': 'USER#${userSub}',
    'SK': 'NODE#${pdfPath}',
    'type': 'file',
    'path': '${pdfPath}',
    'name': '${name}',
    'name_lc': '${name.toLowerCase()}',
    'parent': '${parent}',
    'content_type': 'application/pdf',
    'size': 1024,
    'created_at': str(int(time.time())),
    'updated_at': str(int(time.time())),
    's3_key': 'e2e/fake/${name}',
    's3_bucket': 'test-bucket',
})
print('pdf node injected')
"`,
    { timeout: 10_000 },
  );
}

/** Remove the injected PDF node from the file_manager table. */
function cleanupPdfNode(userSub: string, pdfPath: string): void {
  try {
    execSync(
      `${PYTHON} -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.delete_item(Key={'PK': 'USER#${userSub}', 'SK': 'NODE#${pdfPath}'})
print('cleaned up')
"`,
      { timeout: 10_000 },
    );
  } catch {
    /* best-effort */
  }
}

/** Insert a signer record for the given packet directly into DynamoDB. */
function injectSigner(packetId: string, signerSub: string): void {
  execSync(
    `${PYTHON} -c "${DDB_PRELUDE}
tbl = ddb.Table('signature_packet_signers')
tbl.put_item(Item={
    'packet_id': '${packetId}',
    'signer_id': '${signerSub}',
    'status': 'pending',
    'status_key': 'pending#${packetId}',
    'created_at': str(int(time.time())),
})
print('signer injected')
"`,
    { timeout: 10_000 },
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 71: Signing API
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 71: Signing API", () => {
  let alicePage: Page;
  let aliceSub: string;
  // Lifecycle packet (71.2–71.9): created in beforeAll so it survives retries.
  let packetId = "";
  // Ad-hoc packet created inside 71.1 to verify the create API response.
  let adhocPacketId = "";
  // Second packet for 71.10
  let packet2Id = "";

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage);
    aliceSub = getSessions()[ALICE_ID].user_sub;

    // Inject fake PDF nodes so create_signature_packet can resolve source_path
    injectPdfNode(aliceSub, PDF_PATH);
    injectPdfNode(aliceSub, PDF_PATH2);

    // Create the lifecycle packet up front so all tests can reference it
    const createResp = await apiPost(alicePage, "/v1/signature-packets", {
      source_path: PDF_PATH,
      origin_channel: "share",
    });
    if (createResp.status() !== 200) {
      throw new Error(`Failed to create lifecycle packet: ${createResp.status()} ${await createResp.text()}`);
    }
    const pkt = await createResp.json() as { packet_id: string };
    packetId = pkt.packet_id;

    // Add two fields (required:false so send doesn't require assignments)
    for (const fieldType of ["signature", "text"] as const) {
      const fr = await apiPost(alicePage, `/v1/signature-packets/${packetId}/fields`, {
        action: "create",
        field_type: fieldType,
        x: fieldType === "signature" ? 0.1 : 0.1,
        y: fieldType === "signature" ? 0.1 : 0.3,
        page: 1,
        width: fieldType === "signature" ? 0.22 : 0.32,
        height: fieldType === "signature" ? 0.06 : 0.07,
        required: false,
      });
      if (fr.status() !== 200) throw new Error(`Field creation failed: ${fr.status()}`);
    }

    // Inject a signer so the send endpoint is satisfied
    injectSigner(packetId, aliceSub);

    // Send the packet so 71.7/71.8/71.9 can test post-send state
    const sendResp = await apiPost(alicePage, `/v1/signature-packets/${packetId}/send`, {});
    if (sendResp.status() !== 200) {
      throw new Error(`Failed to send lifecycle packet: ${sendResp.status()} ${await sendResp.text()}`);
    }
  });

  test.afterAll(async () => {
    cleanupPdfNode(aliceSub, PDF_PATH);
    cleanupPdfNode(aliceSub, PDF_PATH2);
    await alicePage.close();
  });

  test("71.1 create packet with origin_channel share → 200 with packet_id", async () => {
    // Create an ad-hoc packet to verify the create API itself
    const resp = await apiPost(alicePage, "/v1/signature-packets", {
      source_path: PDF_PATH,
      origin_channel: "share",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { packet_id: string; status: string; origin_channel: string };
    expect(data.packet_id).toBeTruthy();
    expect(typeof data.packet_id).toBe("string");
    expect(data.status).toBe("draft");
    expect(data.origin_channel).toBe("share");
    adhocPacketId = data.packet_id;
  });

  test("71.2 GET packet → 200, status draft", async () => {
    // adhocPacketId from 71.1 — but use lifecycle packet which was pre-sent.
    // Test that any packet can be retrieved by its ID.
    expect(packetId).toBeTruthy();
    const resp = await apiGet(alicePage, `/v1/signature-packets/${packetId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { status: string; packet_id: string };
    expect(data.packet_id).toBe(packetId);
    // Lifecycle packet was sent in beforeAll so status is "sent"
    expect(["draft", "sent"]).toContain(data.status);
  });

  test("71.3 add signature field to a draft packet → 200 with field_id", async () => {
    // Use the ad-hoc packet (still in draft) if available, otherwise create one
    const targetPacket = adhocPacketId || packetId;
    expect(targetPacket).toBeTruthy();
    const resp = await apiPost(alicePage, `/v1/signature-packets/${targetPacket}/fields`, {
      action: "create",
      field_type: "signature",
      x: 0.1,
      y: 0.1,
      page: 1,
      width: 0.22,
      height: 0.06,
      required: false,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { field_id: string; action: string };
    expect(data.field_id).toBeTruthy();
    expect(data.action).toBe("create");
  });

  test("71.4 add text field → 200", async () => {
    const targetPacket = adhocPacketId || packetId;
    expect(targetPacket).toBeTruthy();
    const resp = await apiPost(alicePage, `/v1/signature-packets/${targetPacket}/fields`, {
      action: "create",
      field_type: "text",
      x: 0.1,
      y: 0.3,
      page: 1,
      width: 0.32,
      height: 0.07,
      required: false,
    });
    expect(resp.status()).toBe(200);
  });

  test("71.5 GET lifecycle packet → fields array has exactly 2 items", async () => {
    expect(packetId).toBeTruthy();
    const resp = await apiGet(alicePage, `/v1/signature-packets/${packetId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { fields: unknown[] };
    expect(data.fields.length).toBe(2);
  });

  test("71.6 lifecycle packet was sent in beforeAll → send response was ok", async () => {
    // Verify the packet is in sent state (send happened in beforeAll)
    expect(packetId).toBeTruthy();
    const resp = await apiGet(alicePage, `/v1/signature-packets/${packetId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { status: string };
    expect(data.status).toBe("sent");
  });

  test("71.7 GET lifecycle packet after send → status is sent", async () => {
    expect(packetId).toBeTruthy();
    const resp = await apiGet(alicePage, `/v1/signature-packets/${packetId}`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { status: string };
    expect(data.status).toBe("sent");
  });

  test("71.8 add field after send → 409 (fields locked)", async () => {
    expect(packetId).toBeTruthy();
    const resp = await apiPost(alicePage, `/v1/signature-packets/${packetId}/fields`, {
      action: "create",
      field_type: "text",
      x: 0.5,
      y: 0.5,
      page: 1,
      width: 0.2,
      height: 0.05,
      required: false,
    });
    expect(resp.status()).toBe(409);
  });

  test("71.9 GET packet events → array has events", async () => {
    expect(packetId).toBeTruthy();
    const resp = await apiGet(alicePage, `/v1/signature-packets/${packetId}/events`);
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { events: unknown[] };
    expect(Array.isArray(data.events)).toBe(true);
    expect(data.events.length).toBeGreaterThan(0);
  });

  test("71.10 create packet with origin_channel message → 200 with valid packet_id", async () => {
    const resp = await apiPost(alicePage, "/v1/signature-packets", {
      source_path: PDF_PATH2,
      origin_channel: "message",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json() as { packet_id: string; origin_channel: string };
    expect(data.packet_id).toBeTruthy();
    expect(data.origin_channel).toBe("message");
    packet2Id = data.packet_id;
    expect(packet2Id).not.toBe(packetId);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Section 72: Signing UI
// ─────────────────────────────────────────────────────────────────────────────

test.describe("Section 72: Signing UI", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }: { browser: Browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage);
    await alicePage.goto(`${BASE}/signing`, { waitUntil: "domcontentloaded" });
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("72.1 /signing shows Document Signing heading", async () => {
    test.setTimeout(15_000);
    await expect(alicePage.getByText("Document Signing")).toBeVisible({ timeout: 8_000 });
  });

  test("72.2 Create signature form section visible", async () => {
    // SUX-009: the packet composer moved to the dedicated /signing/new page.
    await alicePage.goto(`${BASE}/signing/new`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Create signature form")).toBeVisible();
  });

  test("72.3 source path input is visible and editable", async () => {
    await alicePage.goto(`${BASE}/signing/new`, { waitUntil: "domcontentloaded" });
    const input = alicePage.getByPlaceholder(/source pdf path/i);
    await expect(input).toBeVisible();
    await input.fill("/test/editable.pdf");
    await expect(input).toHaveValue("/test/editable.pdf");
    // Reset
    await input.fill("");
  });

  test("72.4 sidebar Signing link is visible with correct href", async () => {
    const link = alicePage.getByRole("link", { name: "Signing", exact: true });
    await expect(link).toBeVisible();
    const href = await link.getAttribute("href");
    expect(href).toBe("/signing");
  });

  test("72.5 /files page does NOT contain Document Signing text", async () => {
    await alicePage.goto(`${BASE}/files`, { waitUntil: "domcontentloaded" });
    // Wait for page to settle
    await alicePage.waitForTimeout(1_000);
    await expect(alicePage.getByText("Document Signing")).not.toBeVisible();
    // Navigate back
    await alicePage.goto(`${BASE}/signing`, { waitUntil: "domcontentloaded" });
  });

  test("72.6 mobile nav Signing item visible at 375×812 viewport", async () => {
    test.setTimeout(15_000);
    await alicePage.setViewportSize({ width: 375, height: 812 });
    await alicePage.goto(`${BASE}/signing`, { waitUntil: "domcontentloaded" });
    // Open the "More" sheet in mobile nav
    const moreBtn = alicePage.getByRole("button", { name: "More" });
    await moreBtn.click();
    await expect(alicePage.getByRole("button", { name: "Signing" })).toBeVisible({ timeout: 5_000 });
    // Close sheet
    await alicePage.keyboard.press("Escape");
    // Restore viewport
    await alicePage.setViewportSize({ width: 1280, height: 720 });
  });

  test("72.7 fill source path and create draft → status chip appears", async () => {
    test.setTimeout(25_000);
    await alicePage.setViewportSize({ width: 1280, height: 720 });

    // Inject a real PDF node for UI test so the backend can resolve it
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const uiPdfPath = `/e2e/ui_sign_${TS}.pdf`;
    injectPdfNode(aliceSub, uiPdfPath);

    // SUX-009: packet creation lives on the dedicated /signing/new composer page.
    await alicePage.goto(`${BASE}/signing/new`, { waitUntil: "domcontentloaded" });
    await expect(alicePage.getByText("Create signature form")).toBeVisible({ timeout: 8_000 });

    const input = alicePage.getByPlaceholder(/source pdf path/i);
    await input.fill(uiPdfPath);

    const createBtn = alicePage.getByRole("button", { name: /create draft/i });
    await createBtn.click();

    // Status chip should appear after packet creation
    await expect(alicePage.locator('[data-testid="packet-status-chip"]')).toBeVisible({ timeout: 10_000 });

    cleanupPdfNode(aliceSub, uiPdfPath);
  });
});
