/**
 * E2E tests for Syndicate Revenue Splitting (SYND-003)
 *
 * Section 431: Split Configuration API (4 tests)
 * Section 432: Split Execution API (5 tests)
 * Section 433: Split History & Earnings API (4 tests)
 * Section 434: Split Config UI (3 tests)
 *
 * Auth: admin session cookies (role-bearing JWT) via e2e_admin_session_setup.py.
 * All POST requests include x-csrf-token header.
 *
 * Split rules: percentages stored as integer basis points (10000 = 100%).
 * Money is integer cents. Alice = syndicate owner/admin; Bob = member.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

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

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const sessions = getSessions();
  const sess = sessions[identity];
  if (!sess) throw new Error(`No session for identity "${identity}"`);
  const page = await browser.newPage();
  await page.context().addCookies(sess.cookies);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  const sessions = getSessions();
  return page.request.post(`${BASE}${path}`, {
    data: body,
    headers: { "x-csrf-token": sessions[identity].csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${BASE}${path}`);
}

let alicePage: Page;
let bobPage: Page;
let syndicateId = "";

const RS = (id: string) => `/ui/syndicates/revenue-split/${id}`;

// Create a syndicate owned by Alice with Bob as a second member.
async function setupSyndicate(): Promise<string> {
  const createResp = await apiPost(alicePage, "alice", "/ui/syndicates", {
    name: `RevSplit Synd ${TS}`,
    description: "revenue split e2e",
  });
  expect(createResp.status()).toBe(201);
  const synd = await createResp.json();
  const sid = synd.syndicate_id as string;

  // Invite Bob, then accept.
  const inviteResp = await apiPost(alicePage, "alice", `/ui/syndicates/${sid}/invite`, {
    user_id: BOB_ID,
  });
  expect(inviteResp.ok()).toBeTruthy();
  const acceptResp = await apiPost(bobPage, "bob", `/ui/syndicates/${sid}/invite/respond`, {
    accept: true,
  });
  expect(acceptResp.ok()).toBeTruthy();

  return sid;
}

test.describe("Section 431: Split Configuration API", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    syndicateId = await setupSyndicate();
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("431.1 Admin sets equal split config", async () => {
    const resp = await apiPost(alicePage, "alice", `${RS(syndicateId)}/config`, {
      mode: "equal",
      platform_fee_bps: 1500,
    });
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(alicePage, `${RS(syndicateId)}/config`);
    const cfg = await getResp.json();
    expect(cfg.mode).toBe("equal");
    expect(cfg.platform_fee_bps).toBe(1500);
  });

  test("431.2 Admin sets weighted split config", async () => {
    const weights_bps = { [ALICE_ID]: 6000, [BOB_ID]: 4000 };
    const resp = await apiPost(alicePage, "alice", `${RS(syndicateId)}/config`, {
      mode: "weighted",
      weights_bps,
    });
    expect(resp.status()).toBe(200);
    const getResp = await apiGet(alicePage, `${RS(syndicateId)}/config`);
    const cfg = await getResp.json();
    expect(cfg.mode).toBe("weighted");
    expect(cfg.weights_bps[ALICE_ID]).toBe(6000);
    expect(cfg.weights_bps[BOB_ID]).toBe(4000);
  });

  test("431.3 Weights must sum to 100% (10000 bps)", async () => {
    const resp = await apiPost(alicePage, "alice", `${RS(syndicateId)}/config`, {
      mode: "weighted",
      weights_bps: { [ALICE_ID]: 6000, [BOB_ID]: 3000 }, // sums to 9000
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(JSON.stringify(body)).toContain("100");
  });

  test("431.4 Non-admin cannot set split config", async () => {
    const resp = await apiPost(bobPage, "bob", `${RS(syndicateId)}/config`, {
      mode: "equal",
    });
    expect(resp.status()).toBe(403);
  });
});

test.describe("Section 432: Split Execution API", () => {
  let equalSyndId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    equalSyndId = await setupSyndicate();
    // Configure equal split with 15% platform fee.
    await apiPost(alicePage, "alice", `${RS(equalSyndId)}/config`, {
      mode: "equal",
      platform_fee_bps: 1500,
    });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("432.1 Equal split divides payment evenly", async () => {
    const resp = await apiPost(alicePage, "alice", `${RS(equalSyndId)}/execute`, {
      source_type: "subscription",
      gross_amount_cents: 2000,
    });
    expect(resp.status()).toBe(200);
    const split = await resp.json();
    // gross 2000, fee 300, net 1700, split 2 ways -> 850 / 850.
    expect(split.platform_fee_cents).toBe(300);
    expect(split.net_amount_cents).toBe(1700);
    const amounts = split.distributions.map((d: any) => d.amount_cents).sort();
    expect(amounts).toEqual([850, 850]);
    const total = split.distributions.reduce((s: number, d: any) => s + d.amount_cents, 0);
    expect(total).toBe(split.net_amount_cents);
  });

  test("432.2 Weighted split respects percentages", async () => {
    await apiPost(alicePage, "alice", `${RS(equalSyndId)}/config`, {
      mode: "weighted",
      weights_bps: { [ALICE_ID]: 6000, [BOB_ID]: 4000 },
    });
    const resp = await apiPost(alicePage, "alice", `${RS(equalSyndId)}/execute`, {
      gross_amount_cents: 2000,
    });
    expect(resp.status()).toBe(200);
    const split = await resp.json();
    expect(split.mode).toBe("weighted");
    const byUser: Record<string, number> = {};
    split.distributions.forEach((d: any) => (byUser[d.user_id] = d.amount_cents));
    // net 1700: 60% = 1020, 40% = 680.
    expect(byUser[ALICE_ID]).toBe(1020);
    expect(byUser[BOB_ID]).toBe(680);
  });

  test("432.3 Platform fee deducted correctly", async () => {
    const resp = await apiPost(alicePage, "alice", `${RS(equalSyndId)}/execute`, {
      gross_amount_cents: 2000,
    });
    const split = await resp.json();
    expect(split.gross_amount_cents).toBe(2000);
    expect(split.platform_fee_cents).toBe(300);
    expect(split.net_amount_cents).toBe(1700);
    expect(split.platform_fee_cents + split.net_amount_cents).toBe(split.gross_amount_cents);
  });

  test("432.4 Ledger credit entries written for each member", async () => {
    const resp = await apiPost(alicePage, "alice", `${RS(equalSyndId)}/execute`, {
      gross_amount_cents: 2000,
    });
    const split = await resp.json();
    const splitId = split.split_id;

    const aliceLedger = await apiGet(alicePage, "/billing/ledger?limit=200");
    const aliceItems = (await aliceLedger.json()).items;
    const aliceCredit = aliceItems.find(
      (it: any) =>
        it.reason === "Syndicate bundle revenue share" &&
        it.meta?.split_id === splitId,
    );
    expect(aliceCredit).toBeTruthy();
    expect(aliceCredit.type).toBe("credit");

    const bobLedger = await apiGet(bobPage, "/billing/ledger?limit=200");
    const bobItems = (await bobLedger.json()).items;
    const bobCredit = bobItems.find(
      (it: any) =>
        it.reason === "Syndicate bundle revenue share" &&
        it.meta?.split_id === splitId,
    );
    expect(bobCredit).toBeTruthy();
    expect(bobCredit.type).toBe("credit");
  });

  test("432.5 Split record includes all distributions", async () => {
    const execResp = await apiPost(alicePage, "alice", `${RS(equalSyndId)}/execute`, {
      gross_amount_cents: 2000,
    });
    const created = await execResp.json();
    const detailResp = await apiGet(alicePage, `${RS(equalSyndId)}/splits/${created.split_id}`);
    expect(detailResp.status()).toBe(200);
    const detail = await detailResp.json();
    expect(detail.distributions.length).toBe(2);
    const ids = detail.distributions.map((d: any) => d.user_id).sort();
    expect(ids).toEqual([ALICE_ID, BOB_ID].sort());
    detail.distributions.forEach((d: any) => {
      expect(d.ledger_entry_id).toBeTruthy();
    });
  });
});

test.describe("Section 433: Split History & Earnings API", () => {
  let histSyndId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    histSyndId = await setupSyndicate();
    await apiPost(alicePage, "alice", `${RS(histSyndId)}/config`, {
      mode: "equal",
      platform_fee_bps: 1500,
    });
    // Two splits.
    await apiPost(alicePage, "alice", `${RS(histSyndId)}/execute`, { gross_amount_cents: 2000 });
    await apiPost(alicePage, "alice", `${RS(histSyndId)}/execute`, { gross_amount_cents: 1000 });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("433.1 Split history lists past splits newest first", async () => {
    const resp = await apiGet(alicePage, `${RS(histSyndId)}/splits`);
    expect(resp.status()).toBe(200);
    const splits = await resp.json();
    expect(splits.length).toBeGreaterThanOrEqual(2);
    for (let i = 1; i < splits.length; i++) {
      expect(splits[i - 1].created_at).toBeGreaterThanOrEqual(splits[i].created_at);
    }
  });

  test("433.2 Member can see own earnings", async () => {
    const resp = await apiGet(bobPage, `${RS(histSyndId)}/my-earnings`);
    expect(resp.status()).toBe(200);
    const earnings = await resp.json();
    // Bob: equal split of net(2000)=1700 -> 850, plus net(1000)=850 -> 425 => 1275.
    expect(earnings.total_cents).toBe(1275);
    expect(earnings.split_count).toBe(2);
    const summed = earnings.entries.reduce((s: number, e: any) => s + e.amount_cents, 0);
    expect(summed).toBe(earnings.total_cents);
  });

  test("433.3 Updated config applies to new splits only", async () => {
    // Switch to weighted; previous equal splits must stay unchanged.
    const before = await apiGet(alicePage, `${RS(histSyndId)}/splits`);
    const beforeSplits = await before.json();
    const firstId = beforeSplits[beforeSplits.length - 1].split_id;

    await apiPost(alicePage, "alice", `${RS(histSyndId)}/config`, {
      mode: "weighted",
      weights_bps: { [ALICE_ID]: 7000, [BOB_ID]: 3000 },
    });
    const newExec = await apiPost(alicePage, "alice", `${RS(histSyndId)}/execute`, {
      gross_amount_cents: 2000,
    });
    const newSplit = await newExec.json();
    expect(newSplit.mode).toBe("weighted");

    // Historical split unchanged (still equal-mode).
    const histResp = await apiGet(alicePage, `${RS(histSyndId)}/splits/${firstId}`);
    const hist = await histResp.json();
    expect(hist.mode).toBe("equal");
  });

  test("433.4 Split history accessible to non-admin member", async () => {
    const resp = await apiGet(bobPage, `${RS(histSyndId)}/splits`);
    expect(resp.status()).toBe(200);
    const splits = await resp.json();
    expect(Array.isArray(splits)).toBeTruthy();
  });
});

test.describe("Section 434: Split Config UI", () => {
  let uiSyndId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await newIdentityPage(browser, "alice");
    bobPage = await newIdentityPage(browser, "bob");
    uiSyndId = await setupSyndicate();
    await apiPost(alicePage, "alice", `${RS(uiSyndId)}/config`, {
      mode: "equal",
      platform_fee_bps: 1500,
    });
    await apiPost(alicePage, "alice", `${RS(uiSyndId)}/execute`, { gross_amount_cents: 2000 });
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  test("434.1 Revenue tab visible on syndicate page", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndId}`);
    await expect(alicePage.getByRole("tab", { name: "Revenue" })).toBeVisible();
  });

  test("434.2 Mode selector changes config form", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndId}`);
    await alicePage.getByRole("tab", { name: "Revenue" }).click();
    await expect(
      alicePage.getByText("Revenue Split Configuration"),
    ).toBeVisible();
    // Switch to weighted -> per-member weight editor appears.
    await alicePage.getByLabel("Split mode").click();
    await alicePage.getByRole("option", { name: "Weighted Split" }).click();
    await expect(alicePage.getByTestId("weight-editor")).toBeVisible();
  });

  test("434.3 Split history shows payment breakdowns", async () => {
    await alicePage.goto(`${BASE}/syndicates/${uiSyndId}`);
    await alicePage.getByRole("tab", { name: "Revenue" }).click();
    await expect(alicePage.getByText("Split History")).toBeVisible();
    await expect(alicePage.getByTestId("split-history")).toBeVisible();
    // Gross / Fee / Net breakdown rendered.
    await expect(alicePage.getByText(/Gross \$20\.00/)).toBeVisible();
  });
});
