/**
 * E2E tests for FIN-011: Collaboration Revenue Splitting.
 *
 * Extends the existing collaboration system with:
 *   - Content assignment (one-active-collab exclusivity rule)
 *   - Automatic revenue splits on assigned content
 *   - Split history / audit trail
 *   - Dispute create + resolve
 *
 * Sections:
 *   579 — Content assignment API (4 tests)
 *   580 — Automatic revenue split API (4 tests)
 *   581 — Split history + disputes API (4 tests)
 *   582 — Collaboration revenue UI (2 tests)
 *
 * Auth: Alice + Bob (collaboration parties), Charlie (non-party).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

const sessions = getSessions();
const aliceSub = sessions[ALICE_ID].user_sub;
const bobSub = sessions[BOB_ID].user_sub;

async function injectAuth(page: Page, identity: string) {
  const s = sessions[identity];
  await page.context().addCookies(s.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, s.user_sub);
}

// ─── API helpers ──────────────────────────────────────────────────────────────

async function apiPost(page: Page, identity: string, path: string, body: unknown) {
  return page.request.post(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
    data: body,
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

async function apiDelete(page: Page, identity: string, path: string) {
  return page.request.delete(`${BASE}${path}`, {
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

/**
 * Create a fresh collaboration (Alice → Bob) and have Bob accept it.
 * Returns the accepted collaboration_id.
 */
async function createAcceptedCollab(
  alicePage: Page,
  bobPage: Page,
  splitPctInitiator = 60,
): Promise<string> {
  const create = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
    recipient_id: bobSub,
    content_types: ["broadcast", "post", "vod"],
    split_pct: splitPctInitiator,
    title: `FIN011 Collab ${TS}-${Math.random().toString(36).slice(2, 8)}`,
    description: "Revenue split test",
  });
  expect(create.status()).toBe(201);
  const collab = await create.json();
  const collabId = collab.collaboration_id;

  // Bob (non-proposer) accepts.
  const accept = await apiPost(bobPage, BOB_ID, `/ui/collaborations/${collabId}/accept`, {});
  expect(accept.status()).toBe(200);
  return collabId;
}

/** Count ledger credit entries for a user mentioning a content_id. */
async function ledgerCreditsForContent(
  userSub: string,
  contentId: string,
): Promise<number> {
  const out = execSync(
    `set -a; source ${REPO_ROOT}/.env.local 2>/dev/null; set +a; ` +
      `PYTHONPATH=${REPO_ROOT} ${REPO_ROOT}/.venv/bin/python3 - <<'PY'
import json
from app.core.tables import T
from boto3.dynamodb.conditions import Key
resp = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#${userSub}"))
total = 0
for it in resp.get("Items", []):
    meta = it.get("meta") or {}
    if it.get("type") == "credit" and meta.get("content_id") == "${contentId}":
        total += int(it.get("amount_cents", 0))
print(total)
PY`,
    {
      cwd: REPO_ROOT,
      env: { ...process.env, PYTHONPATH: REPO_ROOT },
      shell: "/bin/bash",
    },
  )
    .toString()
    .trim();
  const lastLine = out.split("\n").pop()!.trim();
  return parseInt(lastLine || "0", 10);
}

// ==========================================================================
// Section 579: Content Assignment API
// ==========================================================================
test.describe("579 — Content assignment API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let collabId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    collabId = await createAcceptedCollab(alicePage, bobPage);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("579.1 — Assign content to accepted collaboration", async () => {
    const contentId = `content_${TS}_1`;
    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content`, {
      content_id: contentId,
      content_type: "post",
      title: "Collab Post",
    });
    expect(resp.status()).toBe(200);

    const list = await apiGet(alicePage, `/ui/collaborations/${collabId}/content`);
    expect(list.status()).toBe(200);
    const body = await list.json();
    expect(body.items.some((c: { content_id: string }) => c.content_id === contentId)).toBe(true);
  });

  test("579.2 — Cannot assign content to pending collaboration", async () => {
    // Fresh pending collab (not accepted).
    const create = await apiPost(alicePage, ALICE_ID, "/ui/collaborations", {
      recipient_id: bobSub,
      content_types: ["post"],
      split_pct: 50,
      title: `FIN011 Pending ${TS}`,
    });
    expect(create.status()).toBe(201);
    const pendingId = (await create.json()).collaboration_id;

    const resp = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${pendingId}/content`, {
      content_id: `content_${TS}_pending`,
      content_type: "post",
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(JSON.stringify(body).toLowerCase()).toContain("not active");

    // cleanup
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${pendingId}/cancel`, {});
  });

  test("579.3 — Cannot assign content already in another collaboration", async () => {
    const sharedContent = `content_${TS}_shared`;
    // Assign to collab A.
    const a = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content`, {
      content_id: sharedContent,
      content_type: "post",
    });
    expect(a.status()).toBe(200);

    // New accepted collab B.
    const collabB = await createAcceptedCollab(alicePage, bobPage);
    const b = await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabB}/content`, {
      content_id: sharedContent,
      content_type: "post",
    });
    expect(b.status()).toBe(409);
    const body = await b.json();
    expect(JSON.stringify(body).toLowerCase()).toContain("already");
  });

  test("579.4 — Unassign content from collaboration", async () => {
    const contentId = `content_${TS}_unassign`;
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content`, {
      content_id: contentId,
      content_type: "post",
    });

    const del = await apiDelete(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content/${contentId}`);
    expect(del.status()).toBe(200);

    const list = await apiGet(alicePage, `/ui/collaborations/${collabId}/content`);
    const body = await list.json();
    expect(body.items.some((c: { content_id: string }) => c.content_id === contentId)).toBe(false);
  });
});

// ==========================================================================
// Section 580: Automatic Revenue Split API
// ==========================================================================
test.describe("580 — Automatic revenue split API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let collabId: string;
  const contentId = `content_${TS}_rev`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    collabId = await createAcceptedCollab(alicePage, bobPage, 60); // Alice 60 / Bob 40
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content`, {
      content_id: contentId,
      content_type: "post",
      title: "Revenue Content",
    });
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("580.1 — Revenue event on collaboration content triggers split", async () => {
    const before = await ledgerCreditsForContent(bobSub, contentId);
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/content/${contentId}/revenue-event`,
      { content_id: contentId, amount_cents: 1000, source: "tip" },
    );
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.split.distributions.length).toBeGreaterThanOrEqual(2);

    const after = await ledgerCreditsForContent(bobSub, contentId);
    expect(after).toBeGreaterThan(before);
  });

  test("580.2 — Split amounts match collaboration percentages", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/content/${contentId}/revenue-event`,
      { content_id: contentId, amount_cents: 1000, source: "tip" },
    );
    expect(resp.status()).toBe(200);
    const split = (await resp.json()).split;
    const byUser: Record<string, number> = {};
    for (const d of split.distributions) byUser[d.user_id] = d.amount_cents;
    // Contract (FIN-018): tip-source revenue events deduct the admin-configured
    // platform fee from GROSS first, then split the NET by collaboration
    // percentages. So amounts are 60/40 of the distributable net, not of gross.
    const dists = split.distributions as Array<{ user_id: string; percentage: number }>;
    const byPct: Record<string, number> = {};
    for (const d of dists) byPct[d.user_id] = d.percentage;
    expect(byPct[aliceSub]).toBe(60);
    expect(byPct[bobSub]).toBe(40);
    // Sum of distributions == the distributable net (<= gross, fee deducted).
    const sum = split.distributions.reduce(
      (a: number, d: { amount_cents: number }) => a + d.amount_cents,
      0,
    );
    expect(sum).toBeGreaterThan(0);
    expect(sum).toBeLessThanOrEqual(split.gross_amount_cents);
    // Each share matches its percentage of the distributed net (floor rounding
    // favours the creator, so allow +/-1c).
    expect(Math.abs(byUser[aliceSub] - Math.round(sum * 0.6))).toBeLessThanOrEqual(1);
    expect(Math.abs(byUser[bobSub] - Math.round(sum * 0.4))).toBeLessThanOrEqual(1);
  });

  test("580.3 — Split writes immutable execution record", async () => {
    // Self-seed a split so this test is safe under fresh-worker retries (which
    // re-create the collab in beforeAll but do not re-run 580.1/580.2).
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/content/${contentId}/revenue-event`,
      { content_id: contentId, amount_cents: 1000, source: "tip" },
    );
    const hist = await apiGet(alicePage, `/ui/collaborations/${collabId}/splits`);
    expect(hist.status()).toBe(200);
    const body = await hist.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
    const rec = body.items[0];
    expect(rec.split_id).toBeTruthy();
    expect(rec.gross_amount_cents).toBeGreaterThan(0);
    expect(rec.distributions.length).toBeGreaterThanOrEqual(2);
  });

  test("580.4 — Content without collaboration gets no split", async () => {
    const orphan = `content_${TS}_orphan`;
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/content/${orphan}/revenue-event`,
      { content_id: orphan, amount_cents: 1000, source: "tip" },
    );
    // Orphan content not assigned → no split possible.
    expect(resp.status()).toBe(400);
  });
});

// ==========================================================================
// Section 581: Split History and Disputes API
// ==========================================================================
test.describe("581 — Split history and disputes API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let charliePage: Page;
  let collabId: string;
  let splitId: string;
  const contentId = `content_${TS}_disp`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    charliePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    await injectAuth(charliePage, CHARLIE_ID);
    collabId = await createAcceptedCollab(alicePage, bobPage);
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content`, {
      content_id: contentId,
      content_type: "post",
    });
    // Generate a split to dispute.
    const evt = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/content/${contentId}/revenue-event`,
      { content_id: contentId, amount_cents: 500, source: "tip" },
    );
    splitId = (await evt.json()).split.split_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
    await charliePage.close();
  });

  test("581.1 — Split history lists past splits newest first", async () => {
    const hist = await apiGet(bobPage, `/ui/collaborations/${collabId}/splits`);
    expect(hist.status()).toBe(200);
    const body = await hist.json();
    expect(body.items.length).toBeGreaterThanOrEqual(1);
    expect(body.items.some((s: { split_id: string }) => s.split_id === splitId)).toBe(true);
  });

  test("581.2 — File dispute on a split", async () => {
    const resp = await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/splits/${splitId}/dispute`,
      { reason: "The split percentage was incorrect for this content item." },
    );
    expect(resp.status()).toBe(200);
    expect((await resp.json()).dispute_status).toBe("disputed");

    // The split record now reports disputed.
    const hist = await apiGet(bobPage, `/ui/collaborations/${collabId}/splits`);
    const body = await hist.json();
    const rec = body.items.find((s: { split_id: string }) => s.split_id === splitId);
    expect(rec.dispute_status).toBe("disputed");
  });

  test("581.3 — Resolve dispute marks it resolved", async () => {
    const list = await apiGet(alicePage, `/ui/collaborations/${collabId}/disputes`);
    expect(list.status()).toBe(200);
    const disputes = (await list.json()).items;
    expect(disputes.length).toBeGreaterThanOrEqual(1);
    const disputeId = disputes[0].dispute_id;

    const resolve = await apiPost(
      alicePage,
      ALICE_ID,
      `/ui/collaborations/${collabId}/disputes/${disputeId}/resolve`,
      { resolution: "Reviewed and confirmed split is correct.", accept: true },
    );
    expect(resolve.status()).toBe(200);
    expect((await resolve.json()).status).toBe("resolved");
  });

  test("581.4 — Non-participant cannot file dispute or view revenue", async () => {
    // Charlie is not a party to this collaboration.
    const dispute = await apiPost(
      charliePage,
      CHARLIE_ID,
      `/ui/collaborations/${collabId}/splits/${splitId}/dispute`,
      { reason: "I should not be able to dispute this collaboration." },
    );
    expect(dispute.status()).toBe(403);

    const splits = await apiGet(charliePage, `/ui/collaborations/${collabId}/splits`);
    expect(splits.status()).toBe(403);
  });
});

// ==========================================================================
// Section 582: Collaboration Revenue UI
// ==========================================================================
test.describe("582 — Collaboration revenue UI", () => {
  let alicePage: Page;
  let bobPage: Page;
  let collabId: string;
  const contentId = `content_${TS}_ui`;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    collabId = await createAcceptedCollab(alicePage, bobPage);
    await apiPost(alicePage, ALICE_ID, `/ui/collaborations/${collabId}/content`, {
      content_id: contentId,
      content_type: "post",
      title: "UI Content",
    });
    await apiPost(
      bobPage,
      BOB_ID,
      `/ui/collaborations/${collabId}/content/${contentId}/revenue-event`,
      { content_id: contentId, amount_cents: 1000, source: "tip" },
    );
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("582.1 — Revenue page shows summary and assigned content", async () => {
    await alicePage.goto(`${BASE}/collaborations/${collabId}/revenue`, {
      waitUntil: "domcontentloaded",
    });
    await expect(alicePage.getByTestId("collab-revenue-page")).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.getByText("Revenue Summary")).toBeVisible();
    await expect(alicePage.getByText("Assigned Content")).toBeVisible();
    await expect(alicePage.getByTestId("collab-content-row").first()).toBeVisible({ timeout: 10_000 });
  });

  test("582.2 — Split history table shows split rows", async () => {
    await alicePage.goto(`${BASE}/collaborations/${collabId}/revenue`, {
      waitUntil: "domcontentloaded",
    });
    await expect(alicePage.getByText("Split History")).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.getByTestId("collab-split-row").first()).toBeVisible({ timeout: 10_000 });
  });
});
