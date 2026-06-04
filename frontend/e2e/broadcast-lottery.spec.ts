import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

/* ------------------------------------------------------------------ */
/*  Constants & helpers                                                */
/* ------------------------------------------------------------------ */

const API = "http://localhost:8000";
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
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
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

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ */
/*  Helper: inject a test payment method for a user                    */
/* ------------------------------------------------------------------ */

function injectPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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
/*  Helper: query billing ledger entries for a user                    */
/* ------------------------------------------------------------------ */

function queryLedger(userSub: string): Array<Record<string, unknown>> {
  const raw = execSync(
    `${PYTHON} -c "
import boto3, os, json
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
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
from boto3.dynamodb.conditions import Key
resp = tbl.query(
    KeyConditionExpression=Key('pk').eq('USER#${userSub}') & Key('sk').begins_with('LEDGER#'),
    Limit=50,
    ScanIndexForward=False,
)
from decimal import Decimal
def default(o):
    if isinstance(o, Decimal):
        return int(o) if o == int(o) else float(o)
    raise TypeError(repr(o))
print(json.dumps(resp.get('Items', []), default=default))
"`,
    { timeout: 10_000 },
  ).toString();
  return JSON.parse(raw);
}

/* ------------------------------------------------------------------ */
/*  Shared state                                                       */
/* ------------------------------------------------------------------ */

const ROOT_ID = "root";
const ALICE_ID = "alice";
const BOB_ID = "bob";

/* ------------------------------------------------------------------ */
/*  Section 135 -- Broadcast Lottery API                               */
/* ------------------------------------------------------------------ */

test.describe.serial("135 -- Broadcast Lottery API", () => {
  let rootPage: Page;
  let alicePage: Page;
  let profileId: string;
  let sessionId: string;
  let lotteryId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create broadcast profile + session
    const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
      name: `lottery-test-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profResp.status()).toBe(201);
    profileId = (await profResp.json()).id;

    const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    sessionId = (await sessResp.json()).id;

    // Start session to get to "live"
    const startResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "e2e-lottery-test" },
    );
    expect(startResp.status()).toBe(202);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("135.1 Broadcaster creates lottery with 3 outcomes", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: `Giveaway ${TS}`,
        outcomes: [
          { display_label: "Grand Prize", weight_bps: 2000, payload_type: "text", text_content: "Free month" },
          { display_label: "Runner Up", weight_bps: 3000, payload_type: "text", text_content: "20% off" },
          { display_label: "Participation", weight_bps: 5000, payload_type: "text", text_content: "Thanks for playing" },
        ],
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.status).toBe("open");
    expect(body.entry_count).toBe(0);
    expect(body.outcomes).toHaveLength(3);
    expect(body.lottery_id).toMatch(/^lot_/);
    lotteryId = body.lottery_id;
  });

  test("135.2 Non-broadcaster cannot create lottery (403)", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: "Unauthorized Lottery",
        outcomes: [
          { display_label: "A", weight_bps: 5000, payload_type: "text", text_content: "a" },
          { display_label: "B", weight_bps: 5000, payload_type: "text", text_content: "b" },
        ],
      },
    );
    expect(resp.status()).toBe(403);
  });

  test("135.3 Invalid outcomes rejected (422)", async () => {
    // The 31s cooldown sleep exceeds the default 30s per-test timeout, which
    // would time out the test, recycle the Playwright worker, and reset the
    // describe-scoped `lotteryId` (set in 135.1, NOT in beforeAll) to undefined
    // -- cascading into 404s for every test from 135.4 onward.
    test.setTimeout(40_000);
    // Wait for create rate limit to expire
    await sleep(31_000);

    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: "Bad weights",
        outcomes: [
          { display_label: "A", weight_bps: 3000, payload_type: "text", text_content: "a" },
          { display_label: "B", weight_bps: 3000, payload_type: "text", text_content: "b" },
        ],
      },
    );
    expect(resp.status()).toBe(422);
  });

  test("135.4 Viewer enters free lottery", async () => {
    // Fail loudly if the lottery setup (135.1) did not run / was lost on a
    // worker restart, rather than silently 404-ing on a `.../undefined/enter` URL.
    expect(lotteryId, "lotteryId must be set by 135.1 before entering").toMatch(
      /^lot_/,
    );
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/enter`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.already_entered).toBe(false);
    expect(body.lottery_id).toBe(lotteryId);
  });

  test("135.5 Entering same lottery again is idempotent", async () => {
    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/enter`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.already_entered).toBe(true);
  });

  test("135.6 Broadcaster closes entries", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/close`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("entries_closed");
  });

  test("135.7 Viewer cannot enter after entries closed (409)", async () => {
    // Use a page for Bob to try entering the closed lottery
    const bobCtx = await alicePage.context().browser()!.newContext();
    const bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, BOB_ID);

    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/enter`,
      {},
    );
    expect(resp.status()).toBe(409);
    await bobCtx.close();
  });

  test("135.8 Broadcaster draws lottery", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/draw`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("drawn");
    expect(body.results.length).toBeGreaterThanOrEqual(1);
    for (const r of body.results) {
      expect(r.outcome_id).toMatch(/^oc_/);
      expect(r.rng_roll).toBeGreaterThanOrEqual(1);
      expect(r.rng_roll).toBeLessThanOrEqual(10000);
    }
  });

  test("135.9 Draw is idempotent", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotteryId}/draw`,
      {},
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.idempotent).toBe(true);
  });

  test("135.10 Lottery appears in chat history", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/chat?limit=50`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    const lotteryMsg = body.messages.find(
      (m: { kind: string; lottery_id?: string }) =>
        m.kind === "lottery" && m.lottery_id === lotteryId,
    );
    expect(lotteryMsg).toBeTruthy();
    expect(lotteryMsg.text).toBe(`Giveaway ${TS}`);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 136 -- Broadcast Lottery -- Entry Fee + Viewer Status      */
/* ------------------------------------------------------------------ */

test.describe("136 -- Broadcast Lottery -- Entry Fee + Viewer Status", () => {
  let rootPage: Page;
  let alicePage: Page;
  let profileId: string;
  let sessionId: string;
  let paidLotteryId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create broadcast profile + session
    const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
      name: `lottery-paid-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profResp.status()).toBe(201);
    profileId = (await profResp.json()).id;

    const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    sessionId = (await sessResp.json()).id;

    const startResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "e2e-lottery-paid-test" },
    );
    expect(startResp.status()).toBe(202);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("136.1 Paid lottery creation includes entry_fee_cents", async () => {
    const resp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: `Paid Lottery ${TS}`,
        outcomes: [
          { display_label: "Win", weight_bps: 5000, payload_type: "text", text_content: "You won!" },
          { display_label: "Lose", weight_bps: 5000, payload_type: "text", text_content: "Better luck" },
        ],
        entry_fee_cents: 500,
        max_entries: 10,
      },
    );
    expect(resp.status()).toBe(201);
    const body = await resp.json();
    expect(body.entry_fee_cents).toBe(500);
    expect(body.max_entries).toBe(10);
    paidLotteryId = body.lottery_id;
  });

  test("136.2 Viewer with payment method enters paid lottery", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const pmId = `pm_blot_${TS}_alice`;
    injectPaymentMethod(aliceSub, pmId);

    const resp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${paidLotteryId}/enter`,
      { payment_method_id: pmId },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.already_entered).toBe(false);
    expect(body.entry_fee_cents).toBe(500);
  });

  test("136.3 Entry fee creates billing ledger debit for entrant", async () => {
    const aliceSub = getSessions()[ALICE_ID].user_sub;
    const entries = queryLedger(aliceSub);
    const feeEntry = entries.find(
      (e) => e.reason === "Lottery entry fee" && (e.meta as Record<string, unknown>)?.lottery_id === paidLotteryId,
    );
    expect(feeEntry).toBeTruthy();
    expect(feeEntry!.type).toBe("debit");
    expect(Number(feeEntry!.amount_cents)).toBe(500);
  });

  test("136.4 Entry fee creates billing ledger credit for broadcaster", async () => {
    const rootSub = getSessions()[ROOT_ID].user_sub;
    const entries = queryLedger(rootSub);
    const creditEntry = entries.find(
      (e) => e.reason === "Lottery entry fee received" && (e.meta as Record<string, unknown>)?.lottery_id === paidLotteryId,
    );
    expect(creditEntry).toBeTruthy();
    expect(creditEntry!.type).toBe("credit");
    expect(Number(creditEntry!.amount_cents)).toBe(500);
  });

  test("136.5 Viewer status shows has_entered=true before draw", async () => {
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/chat/lottery/${paidLotteryId}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.has_entered).toBe(true);
    expect(body.status).toBe("open");
    expect(body.viewer_outcome).toBeNull();
  });

  test("136.6 Viewer status shows personal outcome after draw", async () => {
    // Draw the lottery
    const drawResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${paidLotteryId}/draw`,
      {},
    );
    expect(drawResp.status()).toBe(200);

    // Get viewer status
    const resp = await apiGet(
      alicePage,
      `/broadcast/sessions/${sessionId}/chat/lottery/${paidLotteryId}`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.status).toBe("drawn");
    expect(body.has_entered).toBe(true);
    expect(body.viewer_outcome).toBeTruthy();
    expect(body.viewer_outcome.outcome_id).toMatch(/^oc_/);
    expect(body.viewer_outcome.rng_roll).toBeGreaterThanOrEqual(1);
    expect(body.viewer_outcome.rng_roll).toBeLessThanOrEqual(10000);
  });

  test("136.7 Broadcaster can see full results", async () => {
    const resp = await apiGet(
      rootPage,
      `/broadcast/sessions/${sessionId}/chat/lottery/${paidLotteryId}/results`,
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.lottery_id).toBe(paidLotteryId);
    expect(body.status).toBe("drawn");
    expect(body.results.length).toBeGreaterThanOrEqual(1);
  });
});

/* ------------------------------------------------------------------ */
/*  Section 137 -- Broadcast Lottery -- Edge Cases                     */
/* ------------------------------------------------------------------ */

test.describe("137 -- Broadcast Lottery -- Edge Cases", () => {
  let rootPage: Page;
  let alicePage: Page;
  let profileId: string;
  let sessionId: string;

  test.beforeAll(async ({ browser }) => {
    const rootCtx = await browser.newContext();
    rootPage = await rootCtx.newPage();
    await injectAuth(rootPage, ROOT_ID);

    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create broadcast profile + session
    const profResp = await apiPost(rootPage, ROOT_ID, "/broadcast/profiles", {
      name: `lottery-edge-${TS}`,
      region: "us-east-1",
      rendition_preset: "720p30",
    });
    expect(profResp.status()).toBe(201);
    profileId = (await profResp.json()).id;

    const sessResp = await apiPost(rootPage, ROOT_ID, "/broadcast/sessions", {
      profile_id: profileId,
    });
    expect(sessResp.status()).toBe(201);
    sessionId = (await sessResp.json()).id;

    const startResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/start`,
      { reason: "e2e-lottery-edge" },
    );
    expect(startResp.status()).toBe(202);
  });

  test.afterAll(async () => {
    await rootPage.context().close();
    await alicePage.context().close();
  });

  test("137.1 Draw with zero entries returns 409", async () => {
    // Create a lottery
    const createResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: `Empty ${TS}`,
        outcomes: [
          { display_label: "A", weight_bps: 5000, payload_type: "text", text_content: "a" },
          { display_label: "B", weight_bps: 5000, payload_type: "text", text_content: "b" },
        ],
      },
    );
    expect(createResp.status()).toBe(201);
    const lotId = (await createResp.json()).lottery_id;

    const drawResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotId}/draw`,
      {},
    );
    expect(drawResp.status()).toBe(409);
    const body = await drawResp.json();
    expect(body.detail.code).toBe("LOTTERY_NO_ENTRIES");
  });

  test("137.2 Broadcaster cannot enter own lottery (403)", async () => {
    // 31s cooldown exceeds the default 30s per-test timeout -> bump it.
    test.setTimeout(40_000);
    // Wait for rate limit
    await sleep(31_000);

    const createResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: `Self-enter ${TS}`,
        outcomes: [
          { display_label: "A", weight_bps: 5000, payload_type: "text", text_content: "a" },
          { display_label: "B", weight_bps: 5000, payload_type: "text", text_content: "b" },
        ],
      },
    );
    expect(createResp.status()).toBe(201);
    const lotId = (await createResp.json()).lottery_id;

    const enterResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotId}/enter`,
      {},
    );
    expect(enterResp.status()).toBe(403);
    const body = await enterResp.json();
    expect(body.detail.code).toBe("BROADCASTER_CANNOT_ENTER");
  });

  test("137.3 Draw directly from open state (skip close)", async () => {
    // 31s cooldown exceeds the default 30s per-test timeout -> bump it.
    test.setTimeout(40_000);
    // Wait for rate limit
    await sleep(31_000);

    const createResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery`,
      {
        title: `Direct draw ${TS}`,
        outcomes: [
          { display_label: "A", weight_bps: 5000, payload_type: "text", text_content: "a" },
          { display_label: "B", weight_bps: 5000, payload_type: "text", text_content: "b" },
        ],
      },
    );
    expect(createResp.status()).toBe(201);
    const lotId = (await createResp.json()).lottery_id;

    // Alice enters
    const enterResp = await apiPost(
      alicePage,
      ALICE_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotId}/enter`,
      {},
    );
    expect(enterResp.status()).toBe(200);

    // Draw directly without closing first
    const drawResp = await apiPost(
      rootPage,
      ROOT_ID,
      `/broadcast/sessions/${sessionId}/chat/lottery/${lotId}/draw`,
      {},
    );
    expect(drawResp.status()).toBe(200);
    const drawBody = await drawResp.json();
    expect(drawBody.status).toBe("drawn");
    expect(drawBody.results.length).toBe(1);
  });
});
