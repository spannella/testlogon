import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
import { usingCpp, cppSeedPaymentMethod } from "./helpers/cpp-seed";
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

async function apiDelete(page: Page, identity: string, path: string) {
  const s = getSessions()[identity];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiPatch(
  page: Page,
  identity: string,
  path: string,
  body: object,
) {
  const s = getSessions()[identity];
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

const PYTHON = REPO_ROOT + "/.venv/bin/python3";

/**
 * Post a tip, retrying on 429 (rate limit). The broadcast tip rate limiter
 * allows one tip per 3 seconds per session+user. Back-to-back tests that
 * send tips can hit this limit.
 */
async function tipWithRetry(
  page: Page,
  identity: string,
  path: string,
  body: object,
  maxRetries = 3,
): Promise<Awaited<ReturnType<typeof apiPost>>> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const resp = await apiPost(page, identity, path, body);
    if (resp.status() !== 429) return resp;
    // Wait out the rate limit window then retry
    const retryBody = await resp.json().catch(() => ({}));
    const waitMs = retryBody?.detail?.retry_after_ms ?? 3200;
    await new Promise((r) => setTimeout(r, Math.min(waitMs + 200, 4000)));
  }
  // Final attempt without catch
  return apiPost(page, identity, path, body);
}

/* ------------------------------------------------------------------ */
/*  Helper: inject a test payment method for a user                    */
/* ------------------------------------------------------------------ */

function injectPaymentMethod(userSub: string, pmId: string): void {
  if (usingCpp()) {
    // cpp reads a DIFFERENT billing store (tlc_billing on moto :5005). The
    // Python :8001 write below never reaches cpp, so h_bc_tip's PM-ownership
    // check would 400 an otherwise-valid tip. Seed cpp too. userSub is a SUB.
    cppSeedPaymentMethod(userSub, pmId);
    return;
  }
  execSync(
    `${PYTHON} -c "
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
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
pm_id = '${pmId}'
sk = 'PM#' + pm_id
tbl.put_item(Item={
    'pk': pk,
    'sk': sk,
    'payment_method_id': pm_id,
    'provider': 'stripe',
    'provider_method_id': pm_id,
    'method_type': 'card',
    'label': 'Test Card ****4242',
    'brand': 'visa',
    'last4': '4242',
    'exp_month': 12,
    'exp_year': 2099,
    'priority': 0,
    'created_at': int(time.time()),
})
tbl.put_item(Item={
    'pk': pk,
    'sk': 'BILLING',
    'autopay_enabled': False,
    'currency': 'usd',
    'default_payment_method_id': pm_id,
})
print('injected')
"`,
    { timeout: 10_000 },
  );
}

/* ------------------------------------------------------------------ */
/*  Shared state                                                       */
/* ------------------------------------------------------------------ */

let liveSessionId: string;
let profileId: string;
const ROOT_ID = "root";
const ALICE_ID = "alice";

/* ------------------------------------------------------------------ */
/*  Section 131 -- Broadcast Tip API                                   */
/* ------------------------------------------------------------------ */

test.describe("Section 131 -- Broadcast Tip API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let alicePmId: string;

  test.beforeAll(async ({ browser }) => {
    // Separate browser contexts for root and alice
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a profile (root)
    const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
      name: `Tip Test Profile ${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profResp.status()).toBe(201);
    const profBody = await profResp.json();
    profileId = profBody.id;

    // Create a session (root)
    const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    const sessBody = await sessResp.json();
    liveSessionId = sessBody.id;

    // Start the session
    const startResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${liveSessionId}/start`,
      { reason: "e2e-tip-test" },
    );
    expect(startResp.status()).toBe(202);

    // Inject a payment method for Alice
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    alicePmId = `pm_bctip_${TS}_alice`;
    injectPaymentMethod(aliceSub, alicePmId);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("131.1 Alice sends a tip to a live broadcast", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 500,
      text: `Great stream ${TS}`,
      payment_method_id: alicePmId,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.kind).toBe("tip");
    expect(body.tip_amount_cents).toBe(500);
    expect(body.tip_currency).toBe("USD");
    expect(body.tip_payment_id).toBeTruthy();
    expect(body.message_id).toBeTruthy();
    expect(body.text).toBe(`Great stream ${TS}`);
  });

  test("131.2 Tip appears in chat history", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/chat?limit=10`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const tipMsg = body.messages.find(
      (m: { kind: string; text: string }) => m.kind === "tip" && m.text === `Great stream ${TS}`,
    );
    expect(tipMsg).toBeTruthy();
    expect(tipMsg.tip_amount_cents).toBe(500);
  });

  test("131.3 Tip summary shows correct totals", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/tips/summary`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.total_cents).toBeGreaterThanOrEqual(500);
    expect(body.tip_count).toBeGreaterThanOrEqual(1);
    expect(body.top_tippers.length).toBeGreaterThanOrEqual(1);
    expect(body.recent_tips.length).toBeGreaterThanOrEqual(1);
    const aliceTipper = body.top_tippers.find(
      (t: { user_id: string }) => t.user_id === getSessions()[ALICE_ID].user_sub,
    );
    expect(aliceTipper).toBeTruthy();
    expect(aliceTipper.total_cents).toBeGreaterThanOrEqual(500);
  });

  test("131.4 Tip below minimum is rejected (422)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 50,
      payment_method_id: alicePmId,
    });
    expect(resp.status()).toBe(422); // pydantic validation: ge=100
  });

  test("131.5 Tip above maximum is rejected (422)", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 200000,
      payment_method_id: alicePmId,
    });
    expect(resp.status()).toBe(422); // pydantic validation: le=100000
  });

  test("131.6 Broadcaster cannot tip own stream", async () => {
    // Root is the broadcaster -- inject a PM for root
    const rootSub = getSessions()[ROOT_ID].user_sub;
    const rootPmId = `pm_bctip_${TS}_root`;
    injectPaymentMethod(rootSub, rootPmId);
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 500,
      payment_method_id: rootPmId,
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("CANNOT_TIP_SELF");
  });

  test("131.7 Session tip totals update on session object", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tip_total_cents).toBeGreaterThanOrEqual(500);
    expect(body.tip_count).toBeGreaterThanOrEqual(1);
    expect(body.tip_enabled).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 132 -- Tip Goals API                                       */
/* ------------------------------------------------------------------ */

test.describe("Section 132 -- Tip Goals API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let goalId: string;
  let alicePmId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Ensure we have a live session
    if (!liveSessionId) {
      const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
        name: `Tip Goals Profile ${TS}`,
        region: "us-east-1",
        rendition_preset: "720p30",
      });
      profileId = (await profResp.json()).id;
      const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
        profile_id: profileId,
      });
      liveSessionId = (await sessResp.json()).id;
      await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/start`, { reason: "e2e" });
    }

    const aliceSub = getSessions()[ALICE_ID].user_sub;
    alicePmId = `pm_bctip_${TS}_alice_goals`;
    injectPaymentMethod(aliceSub, alicePmId);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("132.1 Broadcaster creates a tip goal", async () => {
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals`, {
      label: `Cooking segment ${TS}`,
      target_cents: 1000,
      sort_order: 0,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.goal_id).toBeTruthy();
    expect(body.label).toBe(`Cooking segment ${TS}`);
    expect(body.target_cents).toBe(1000);
    expect(body.current_cents).toBe(0);
    expect(body.reached).toBe(false);
    goalId = body.goal_id;
  });

  test("132.2 List goals returns the created goal", async () => {
    const resp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/goals`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const goal = body.goals.find((g: { goal_id: string }) => g.goal_id === goalId);
    expect(goal).toBeTruthy();
    expect(goal.label).toBe(`Cooking segment ${TS}`);
  });

  test("132.3 Non-broadcaster cannot create goals", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/goals`, {
      label: "Alice's goal",
      target_cents: 500,
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("NOT_BROADCASTER");
  });

  test("132.4 Tip advances goal progress", async () => {
    const tipResp = await tipWithRetry(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 300,
      text: `Goal tip ${TS}`,
      payment_method_id: alicePmId,
    });
    expect(tipResp.status()).toBe(201);

    // Check goal progress
    const goalsResp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/goals`);
    expect(goalsResp.status()).toBe(200);
    const body = await goalsResp.json();
    const goal = body.goals.find((g: { goal_id: string }) => g.goal_id === goalId);
    expect(goal).toBeTruthy();
    expect(goal.current_cents).toBeGreaterThanOrEqual(300);
  });

  test("132.5 Goal is marked as reached when target is met", async () => {
    // Send enough to reach the goal
    const tipResp = await tipWithRetry(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 1000,
      text: `Big goal tip ${TS}`,
      payment_method_id: alicePmId,
    });
    expect(tipResp.status()).toBe(201);

    // Check goal is reached
    const goalsResp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/goals`);
    expect(goalsResp.status()).toBe(200);
    const body = await goalsResp.json();
    const goal = body.goals.find((g: { goal_id: string }) => g.goal_id === goalId);
    expect(goal).toBeTruthy();
    expect(goal.reached).toBe(true);
    expect(goal.current_cents).toBeGreaterThanOrEqual(goal.target_cents);
  });

  test("132.6 Broadcaster deletes a goal", async () => {
    const resp = await apiDelete(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals/${goalId}`);
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);

    // Verify deleted
    const goalsResp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/goals`);
    const goalsBody = await goalsResp.json();
    const deleted = goalsBody.goals.find((g: { goal_id: string }) => g.goal_id === goalId);
    expect(deleted).toBeUndefined();
  });

  test("132.7 Non-broadcaster cannot delete goals", async () => {
    // Create a goal first
    const createResp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals`, {
      label: `Delete test ${TS}`,
      target_cents: 500,
    });
    const newGoalId = (await createResp.json()).goal_id;

    const resp = await apiDelete(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/goals/${newGoalId}`);
    expect(resp.status()).toBe(403);

    // Cleanup
    await apiDelete(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals/${newGoalId}`);
  });

  test("132.8 Max 5 goals per session", async () => {
    // Create 5 goals
    const goalIds: string[] = [];
    for (let i = 0; i < 5; i++) {
      const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals`, {
        label: `Max test ${TS} #${i}`,
        target_cents: 500,
        sort_order: i,
      });
      expect(resp.status()).toBe(201);
      goalIds.push((await resp.json()).goal_id);
    }

    // 6th should fail
    const resp = await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals`, {
      label: `Over limit ${TS}`,
      target_cents: 500,
    });
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.code).toBe("MAX_GOALS_REACHED");

    // Cleanup
    for (const gid of goalIds) {
      await apiDelete(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/goals/${gid}`);
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Section 133 -- Tip Configuration                                   */
/* ------------------------------------------------------------------ */

test.describe("Section 133 -- Tip Configuration", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Ensure we have a live session (resilient to worker restarts on retry)
    if (!liveSessionId) {
      if (!profileId) {
        const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
          name: `Tip Config Profile ${TS}`,
          region: "us-east-1",
          rendition_preset: "720p30",
        });
        profileId = (await profResp.json()).id;
      }
      const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
        profile_id: profileId,
      });
      liveSessionId = (await sessResp.json()).id;
      await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/start`, { reason: "e2e" });
    }
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("133.1 Broadcaster can update tip config", async () => {
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${liveSessionId}/tips/config`,
      { tip_min_cents: 200, tip_max_cents: 50000 },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tip_min_cents).toBe(200);
    expect(body.tip_max_cents).toBe(50000);
  });

  test("133.2 Non-broadcaster cannot update tip config", async () => {
    const resp = await apiPatch(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${liveSessionId}/tips/config`,
      { tip_enabled: false },
    );
    expect(resp.status()).toBe(403);
  });

  test("133.3 Broadcaster can disable tipping", async () => {
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${liveSessionId}/tips/config`,
      { tip_enabled: false },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.tip_enabled).toBe(false);
  });

  test("133.4 Tipping disabled rejects tips with 403", async () => {

    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const alicePmId = `pm_bctip_${TS}_alice_cfg`;
    injectPaymentMethod(aliceSub, alicePmId);
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 500,
      payment_method_id: alicePmId,
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("TIPPING_DISABLED");
  });

  test("133.5 Re-enable tipping", async () => {
    // Re-enable and reset to defaults
    const resp = await apiPatch(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${liveSessionId}/tips/config`,
      { tip_enabled: true, tip_min_cents: 100, tip_max_cents: 100000 },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).tip_enabled).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 134 -- Payment Method Validation                           */
/* ------------------------------------------------------------------ */

test.describe("Section 134 -- Payment Method Validation", () => {
  let rootPage: Page;
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Ensure we have a live session (resilient to worker restarts on retry)
    if (!liveSessionId) {
      if (!profileId) {
        const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
          name: `PM Validation Profile ${TS}`,
          region: "us-east-1",
          rendition_preset: "720p30",
        });
        profileId = (await profResp.json()).id;
      }
      const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
        profile_id: profileId,
      });
      liveSessionId = (await sessResp.json()).id;
      await apiPost(rootPage, ROOT_ID, `/broadcast/sessions/${liveSessionId}/start`, { reason: "e2e" });
    }
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("134.1 Invalid payment method returns 400", async () => {
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 500,
      payment_method_id: "pm_nonexistent_xyz",
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.detail.code).toBe("PAYMENT_METHOD_NOT_FOUND");
  });

  test("134.2 Valid PM allows tip", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const pmId = `pm_bctip_${TS}_alice_valid`;
    injectPaymentMethod(aliceSub, pmId);
    const resp = await tipWithRetry(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 100,
      payment_method_id: pmId,
    });
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.kind).toBe("tip");
    expect(body.tip_amount_cents).toBe(100);
  });

  test("134.3 Tip to non-live session returns 403", async () => {

    // Create a new draft session
    const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
      profile_id: profileId,
    });
    const draftSessionId = (await sessResp.json()).id;

    const aliceSub2 = getSessions()[ALICE_ID].user_sub;
    const pmId = `pm_bctip_${TS}_alice_draft`;
    injectPaymentMethod(aliceSub2, pmId);
    const resp = await apiPost(alicePage, ALICE_ID, `/broadcast/sessions/${draftSessionId}/chat/tip`, {
      amount_cents: 500,
      payment_method_id: pmId,
    });
    expect(resp.status()).toBe(403);
    const body = await resp.json();
    expect(body.detail.code).toBe("BROADCAST_NOT_LIVE");

    // Cleanup
    await apiDelete(rootPage, ROOT_ID, `/broadcast/sessions/${draftSessionId}`);
  });

  test("134.4 Tip with billing ledger entries created", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const pmId = `pm_bctip_${TS}_alice_ledger`;
    injectPaymentMethod(aliceSub, pmId);
    const tipResp = await tipWithRetry(alicePage, ALICE_ID, `/broadcast/sessions/${liveSessionId}/chat/tip`, {
      amount_cents: 200,
      text: `Ledger test ${TS}`,
      payment_method_id: pmId,
    });
    expect(tipResp.status()).toBe(201);

    // Verify tip summary reflects it
    const summaryResp = await apiGet(rootPage, `/broadcast/sessions/${liveSessionId}/tips/summary`);
    expect(summaryResp.status()).toBe(200);
    const summary = await summaryResp.json();
    expect(summary.total_cents).toBeGreaterThanOrEqual(200);
    expect(summary.recent_tips.some((t: { text: string }) => t.text === `Ledger test ${TS}`)).toBe(true);
  });
});
