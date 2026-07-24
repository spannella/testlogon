/**
 * E2E for the Signing inbox document viewer (SUX-* + drafts).
 *
 * Covers the four buckets a user expects — Awaiting me / Sent by me / Completed /
 * Drafts — plus the new Drafts tab and "Resume" (reopens a draft in the composer).
 *
 * Auth: Alice session cookies (e2e_session_setup.py). Creates a real draft packet
 * via the API (after injecting a fake PDF node into DynamoDB so create resolves).
 * Requires SIGNATURE_PDF_ENABLED=true.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { loadSessions } from "./helpers/session";

const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  csrf_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

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

async function apiGet(page: Page, p: string) {
  const s = getSessions()[ALICE_ID];
  return page.request.get(`${BASE}${p}`, { headers: { "x-csrf-token": s.csrf_token } });
}
async function apiPost(page: Page, p: string, body: object) {
  const s = getSessions()[ALICE_ID];
  return page.request.post(`${BASE}${p}`, { data: body, headers: { "x-csrf-token": s.csrf_token } });
}

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
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL', 'http://localhost:8001'),
    region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;

function injectPdfNode(userSub: string, pdfPath: string): void {
  const name = pdfPath.split("/").pop()!;
  const parent = pdfPath.substring(0, pdfPath.lastIndexOf("/")) || "/";
  execSync(
    `python3 -c "${DDB_PRELUDE}
tbl = ddb.Table('file_manager')
tbl.put_item(Item={'PK':'USER#${userSub}','SK':'NODE#${pdfPath}','type':'file','path':'${pdfPath}',
 'name':'${name}','name_lc':'${name.toLowerCase()}','parent':'${parent}','content_type':'application/pdf',
 'size':1024,'created_at':str(int(time.time())),'updated_at':str(int(time.time())),
 's3_key':'e2e/fake/${name}','s3_bucket':'test-bucket'})
print('ok')
"`,
    { timeout: 10_000 },
  );
}

test.describe("Signing inbox document viewer", () => {
  let page: Page;
  let aliceSub: string;
  let draftId = "";
  const PDF_PATH = `/e2e/inbox_${TS}.pdf`;
  const SRC_NAME = `inbox_${TS}.pdf`;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page);
    aliceSub = getSessions()[ALICE_ID].user_sub;
    injectPdfNode(aliceSub, PDF_PATH);
    const resp = await apiPost(page, "/v1/signature-packets", {
      source_path: PDF_PATH,
      origin_channel: "share",
    });
    expect(resp.status()).toBe(200);
    draftId = ((await resp.json()) as { packet_id: string }).packet_id;
    expect(draftId).toBeTruthy();
  });

  test.afterAll(async () => {
    await page?.close();
  });

  test("inbox shows the four document buckets", async () => {
    await page.goto(`${BASE}/signing/inbox`, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("tab-awaiting")).toBeVisible();
    await expect(page.getByTestId("tab-sent")).toBeVisible();
    await expect(page.getByTestId("tab-completed")).toBeVisible();
    await expect(page.getByTestId("tab-drafts")).toBeVisible();
  });

  test("API: draft appears in /drafts and NOT in /sent", async () => {
    const drafts = await (await apiGet(page, "/v1/signature-packets/drafts")).json();
    const sent = await (await apiGet(page, "/v1/signature-packets/sent")).json();
    const draftIds = (drafts.items as Array<{ packet_id: string }>).map((i) => i.packet_id);
    const sentIds = (sent.items as Array<{ packet_id: string }>).map((i) => i.packet_id);
    expect(draftIds).toContain(draftId);
    expect(sentIds).not.toContain(draftId);
  });

  test("Drafts tab lists the draft with a Resume action", async () => {
    await page.goto(`${BASE}/signing/inbox`, { waitUntil: "domcontentloaded" });
    await page.getByTestId("tab-drafts").click();
    const panel = page.getByTestId("panel-drafts");
    await expect(panel.getByText(SRC_NAME)).toBeVisible({ timeout: 8000 });
    await expect(panel.getByRole("button", { name: "Resume" }).first()).toBeVisible();
  });

  test("Resume reopens the draft in the composer", async () => {
    await page.goto(`${BASE}/signing/inbox`, { waitUntil: "domcontentloaded" });
    await page.getByTestId("tab-drafts").click();
    const row = page
      .getByTestId("signing-inbox-row")
      .filter({ hasText: SRC_NAME })
      .first();
    await row.getByRole("button", { name: "Resume" }).click();
    await expect(page).toHaveURL(new RegExp(`/signing/new\\?packet=${draftId}`));
    // composer auto-loads the draft → status line reflects it, Step 2 appears
    await expect(page.getByTestId("signature-status")).toContainText(draftId, { timeout: 10_000 });
    await expect(page.getByText("Step 2 · Place signature fields")).toBeVisible();
  });
});
