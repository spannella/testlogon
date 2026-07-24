import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const TS = Date.now();

interface SessionData {
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

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    _sessions = loadSessions();
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for ${identity}`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

/* ------------------------------------------------------------------ */
/*  DDB helpers (run Python via execSync)                              */
/* ------------------------------------------------------------------ */

function runPython(code: string): string {
  return execSync(
    `python3 -c "${code.replace(/"/g, '\\"')}"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  ).toString().trim();
}

const PY_PREAMBLE = `
import sys, os, json
sys.path.insert(0, '${REPO_ROOT}')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
import boto3, time
from decimal import Decimal
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001')
`.trim();

function setSessionStatus(sessionId: string, status: string) {
  const code = `
${PY_PREAMBLE}
table = ddb.Table('BroadcastSessions')
table.update_item(
    Key={'session_id': '${sessionId}'},
    UpdateExpression='SET #s = :s',
    ExpressionAttributeNames={'#s': 'status'},
    ExpressionAttributeValues={':s': '${status}'},
)
print('ok')
`;
  runPython(code);
}

function seedPaymentMethod(userId: string, pmId: string) {
  const code = `
${PY_PREAMBLE}
table = ddb.Table('billing')
table.put_item(Item={
    'pk': 'USER#${userId}',
    'sk': 'PM#${pmId}',
    'payment_method_id': '${pmId}',
    'brand': 'visa',
    'last4': '4242',
    'type': 'card',
})
table.put_item(Item={
    'pk': 'USER#${userId}',
    'sk': 'BILLING',
    'default_payment_method_id': '${pmId}',
})
print('ok')
`;
  runPython(code);
}

function activatePrivateSession(sessionId: string, requestId: string) {
  const code = `
${PY_PREAMBLE}
table = ddb.Table('BroadcastPrivateSessions')
table.update_item(
    Key={'pk': 'BCAST#${sessionId}', 'sk': 'PRIVATE#${requestId}'},
    UpdateExpression='SET #s = :s, started_at = :sa',
    ExpressionAttributeNames={'#s': 'status'},
    ExpressionAttributeValues={':s': 'active', ':sa': int(time.time()) - 120},
)
print('ok')
`;
  runPython(code);
}

function queryBillingLedger(userId: string): { count: number } {
  const code = `
${PY_PREAMBLE}
from boto3.dynamodb.conditions import Key as K

class DE(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal): return int(o) if o == int(o) else float(o)
        return super().default(o)

table = ddb.Table('billing')
resp = table.query(
    KeyConditionExpression=K('pk').eq('USER#${userId}') & K('sk').begins_with('LEDGER#'),
)
entries = [i for i in resp.get('Items', []) if i.get('reason') == 'Private session']
print(json.dumps({'count': len(entries)}, cls=DE))
`;
  return JSON.parse(runPython(code));
}

/* ------------------------------------------------------------------ */
/*  Shared broadcast setup                                            */
/* ------------------------------------------------------------------ */

async function createLiveBroadcast(page: Page): Promise<{ profileId: string; sessionId: string }> {
  // Create profile
  const profileResp = await apiPost(page, "root", "/broadcast/profiles", {
    name: `priv-profile-${TS}-${Math.random().toString(36).slice(2, 8)}`,
    region: "us-east-1",
    rendition_preset: "720p30",
  });
  expect(profileResp.status()).toBe(201);
  const profileId = (await profileResp.json()).id;

  // Create session
  const sessionResp = await apiPost(page, "root", "/broadcast/sessions", {
    profile_id: profileId,
  });
  expect(sessionResp.status()).toBe(201);
  const sessionId = (await sessionResp.json()).id;

  // Set session to live via DDB (bypassing orchestrator)
  setSessionStatus(sessionId, "live");

  return { profileId, sessionId };
}

/* ------------------------------------------------------------------ */
/*  Section 123 -- Private Request Flow                                */
/* ------------------------------------------------------------------ */

test.describe("123 -- Broadcast Private Request Flow", () => {
  let rootPage: Page;
  let alicePage: Page;
  let sessionId: string;
  const ALICE_PM = `pm_priv_alice_${TS}`;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    // Seed Alice's payment method
    const aliceSub = getSessions()["alice"].user_sub;
    seedPaymentMethod(aliceSub, ALICE_PM);

    // Create a live broadcast
    const broadcast = await createLiveBroadcast(rootPage);
    sessionId = broadcast.sessionId;
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("123.1 Viewer submits private request with valid rate and PM", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private/request`, {
      rate_per_minute_cents: 500,
      payment_method_id: ALICE_PM,
      max_duration_minutes: 30,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.status).toBe("requested");
    expect(body.rate_per_minute_cents).toBe(500);
    expect(body.max_duration_minutes).toBe(30);
    expect(body.viewer_id).toBe(getSessions()["alice"].user_sub);
    expect(body.private_session_id).toBeTruthy();
    expect(body.session_id).toBe(sessionId);
  });

  test("123.2 Duplicate request while pending returns 409", async () => {
    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${sessionId}/private/request`, {
      rate_per_minute_cents: 500,
      payment_method_id: ALICE_PM,
    });
    expect(resp.status()).toBe(409);
  });

  test("123.3 Creator lists pending requests", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/private/requests`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.requests.length).toBeGreaterThanOrEqual(1);
    expect(body.requests[0].status).toBe("requested");
  });

  test("123.4 Get private status shows pending request", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${sessionId}/private/status`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("requested");
  });
});

/* ------------------------------------------------------------------ */
/*  Section 124 -- Accept / Decline / End / Resume                     */
/* ------------------------------------------------------------------ */

test.describe("124 -- Broadcast Private Accept/Decline/End", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, "root");

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("124.1 Creator accepts private request -> broadcast status = private", async () => {
    const aliceSub = getSessions()["alice"].user_sub;
    const pmId = `pm_accept_${TS}`;
    seedPaymentMethod(aliceSub, pmId);

    const broadcast = await createLiveBroadcast(rootPage);

    // Alice requests
    const reqResp = await apiPost(alicePage, "alice", `/broadcast/sessions/${broadcast.sessionId}/private/request`, {
      rate_per_minute_cents: 500,
      payment_method_id: pmId,
    });
    expect(reqResp.status()).toBe(201);
    const reqBody = await reqResp.json();
    const requestId = reqBody.private_session_id;

    // Root accepts
    const acceptResp = await apiPost(rootPage, "root", `/broadcast/sessions/${broadcast.sessionId}/private/${requestId}/accept`, {
      behavior: "pause",
    });
    expect(acceptResp.status()).toBe(200);
    const acceptBody = await acceptResp.json();
    expect(acceptBody.status).toBe("accepted");
    expect(acceptBody.behavior).toBe("pause");
    expect(acceptBody.call_id).toBeTruthy();
    expect(acceptBody.rate_per_minute_cents).toBe(500);

    // Verify broadcast session is now private
    const sessionResp = await apiGet(rootPage, `/broadcast/sessions/${broadcast.sessionId}`);
    const sessionBody = await sessionResp.json();
    expect(sessionBody.status).toBe("private");
  });

  test("124.2 Creator declines private request", async () => {
    const aliceSub = getSessions()["alice"].user_sub;
    const pmId = `pm_decline_${TS}`;
    seedPaymentMethod(aliceSub, pmId);

    const broadcast = await createLiveBroadcast(rootPage);

    // Alice requests
    const reqResp = await apiPost(alicePage, "alice", `/broadcast/sessions/${broadcast.sessionId}/private/request`, {
      rate_per_minute_cents: 500,
      payment_method_id: pmId,
    });
    expect(reqResp.status()).toBe(201);
    const reqBody = await reqResp.json();

    // Root declines
    const declineResp = await apiPost(rootPage, "root", `/broadcast/sessions/${broadcast.sessionId}/private/${reqBody.private_session_id}/decline`, {});
    expect(declineResp.status()).toBe(200);
    const declineBody = await declineResp.json();
    expect(declineBody.ok).toBe(true);

    // Verify broadcast is still live
    const sessionResp = await apiGet(rootPage, `/broadcast/sessions/${broadcast.sessionId}`);
    const sessionBody = await sessionResp.json();
    expect(sessionBody.status).toBe("live");
  });

  test("124.3 Non-operator accept returns 403", async () => {
    const aliceSub = getSessions()["alice"].user_sub;
    const pmId = `pm_noauth_${TS}`;
    seedPaymentMethod(aliceSub, pmId);

    const broadcast = await createLiveBroadcast(rootPage);

    const reqResp = await apiPost(alicePage, "alice", `/broadcast/sessions/${broadcast.sessionId}/private/request`, {
      rate_per_minute_cents: 500,
      payment_method_id: pmId,
    });
    expect(reqResp.status()).toBe(201);
    const reqBody = await reqResp.json();

    // Alice tries to accept (not the creator)
    const acceptResp = await apiPost(alicePage, "alice", `/broadcast/sessions/${broadcast.sessionId}/private/${reqBody.private_session_id}/accept`, {
      behavior: "pause",
    });
    expect(acceptResp.status()).toBe(403);
  });

  test("124.4 Request on non-live broadcast returns 403", async () => {
    const aliceSub = getSessions()["alice"].user_sub;
    const pmId = `pm_nonlive_${TS}`;
    seedPaymentMethod(aliceSub, pmId);

    // Create a draft session (not live)
    const profileResp = await apiPost(rootPage, "root", "/broadcast/profiles", {
      name: `priv-draft-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    const profId = (await profileResp.json()).id;
    const sessionResp = await apiPost(rootPage, "root", "/broadcast/sessions", {
      profile_id: profId,
    });
    const draftSessionId = (await sessionResp.json()).id;

    const resp = await apiPost(alicePage, "alice", `/broadcast/sessions/${draftSessionId}/private/request`, {
      rate_per_minute_cents: 500,
      payment_method_id: pmId,
    });
    expect(resp.status()).toBe(403);
  });

  test("124.5 End private -> back to live after resume", async () => {
    const aliceSub = getSessions()["alice"].user_sub;
    const pmId = `pm_resume_${TS}`;
    seedPaymentMethod(aliceSub, pmId);

    const broadcast = await createLiveBroadcast(rootPage);

    // Alice requests
    const reqResp = await apiPost(alicePage, "alice", `/broadcast/sessions/${broadcast.sessionId}/private/request`, {
      rate_per_minute_cents: 300,
      payment_method_id: pmId,
    });
    expect(reqResp.status()).toBe(201);
    const reqBody = await reqResp.json();
    const requestId = reqBody.private_session_id;

    // Root accepts
    const acceptResp = await apiPost(rootPage, "root", `/broadcast/sessions/${broadcast.sessionId}/private/${requestId}/accept`, {
      behavior: "pause",
    });
    expect(acceptResp.status()).toBe(200);

    // Activate the private session via DDB (simulating WebRTC connect)
    activatePrivateSession(broadcast.sessionId, requestId);

    // End private session
    const endResp = await apiPost(rootPage, "root", `/broadcast/sessions/${broadcast.sessionId}/private/${requestId}/end`, {});
    expect(endResp.status()).toBe(200);
    const endBody = await endResp.json();
    expect(endBody.status).toBe("ended");
    expect(endBody.total_billed_cents).toBeGreaterThanOrEqual(300); // At least 1 min at 300/min
    expect(endBody.ended_by).toBe("creator");

    // Resume broadcast
    const resumeResp = await apiPost(rootPage, "root", `/broadcast/sessions/${broadcast.sessionId}/resume`, {});
    expect(resumeResp.status()).toBe(200);
    const resumeBody = await resumeResp.json();
    expect(resumeBody.status).toBe("live");
  });

  test("124.6 Billing ledger entries written on end", async () => {
    // Check that billing entries from the previous test exist
    const aliceSub = getSessions()["alice"].user_sub;
    const rootSub = getSessions()["root"].user_sub;

    const aliceLedger = queryBillingLedger(aliceSub);
    const rootLedger = queryBillingLedger(rootSub);

    expect(aliceLedger.count).toBeGreaterThanOrEqual(1);
    expect(rootLedger.count).toBeGreaterThanOrEqual(1);
  });
});
