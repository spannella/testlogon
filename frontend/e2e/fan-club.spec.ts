/**
 * E2E tests for CREATOR-002 Fan Clubs / Membership Tiers.
 *
 * Sections:
 *   1 — Tier CRUD API (7 tests)
 *   2 — Badge Resolution API (4 tests)
 *   3 — Exclusive Chat Channels API (6 tests)
 *   4 — Early Access Content API (4 tests)
 *   5 — Fan Club Page UI (5 tests)
 *   6 — Badge Display Integration (4 tests)
 *   7 — Tier Upgrade/Downgrade API (4 tests)
 *   8 — Channel Features API (4 tests)
 *
 * Auth:
 *   Fan Club API → session cookies + x-csrf-token header (require_ui_session)
 *   Subscription API → X-User-Id header (require_user)
 *
 * Test users (from e2e_session_setup.py):
 *   Alice   (e2e_alice@test.local) — creator with fan club tiers
 *   Bob     (e2e_bob@test.local)   — VIP subscriber (level 2)
 *   Charlie (e2e_charlie@test.local) — Basic subscriber (level 1)
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE       = "http://localhost:3000";
const API        = "http://localhost:8000";
const ALICE_ID   = "e2e_alice@test.local";
const BOB_ID     = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
const TS         = Date.now();

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

// ─── Auth helpers ─────────────────────────────────────────────────────────────

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

async function newIdentityPage(browser: Browser, userId: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, userId);
  return page;
}

// ─── Fan Club API helpers (cookie session + CSRF) ─────────────────────────────

function csrfHeaders(userId: string) {
  return { "x-csrf-token": getSessions()[userId].csrf_token };
}

async function fcPost(page: Page, userId: string, path: string, body: object) {
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: csrfHeaders(userId),
  });
}

async function fcGet(page: Page, _userId: string, path: string) {
  return page.request.get(`${API}${path}`);
}

async function fcPatch(page: Page, userId: string, path: string, body: object) {
  return page.request.patch(`${API}${path}`, {
    data: body,
    headers: csrfHeaders(userId),
  });
}

async function fcDelete(page: Page, userId: string, path: string) {
  return page.request.delete(`${API}${path}`, {
    headers: csrfHeaders(userId),
  });
}

async function fcPut(page: Page, userId: string, path: string, body?: object) {
  return page.request.put(`${API}${path}`, {
    data: body ?? {},
    headers: csrfHeaders(userId),
  });
}

// ─── Subscription API helpers (X-User-Id header auth) ─────────────────────────

async function subPost(page: Page, userId: string, path: string, body?: object) {
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: { "X-User-Id": userId },
  });
}

// ─── DDB cleanup helper ───────────────────────────────────────────────────────

function cleanupOldFanClubData() {
  try {
    execSync(
      "python3 /home/ubuntu/testlogon/scripts/fan_club_cleanup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 15_000 },
    );
  } catch {
    // Best-effort cleanup
  }
}

// ─── Shared state ─────────────────────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let charliePage: Page;

let basicPlanId: string;
let vipPlanId: string;
let tierId1: string;  // Basic, level 1
let tierId2: string;  // VIP, level 2
let channelId: string;

// ─── Setup ────────────────────────────────────────────────────────────────────

test.describe("Fan Club", () => {
  test.beforeAll(async ({ browser }) => {
    // Clean up old tiers and subscriptions from previous test runs
    cleanupOldFanClubData();

    alicePage = await newIdentityPage(browser, ALICE_ID);
    bobPage = await newIdentityPage(browser, BOB_ID);
    charliePage = await newIdentityPage(browser, CHARLIE_ID);

    // Create subscription plans for Alice via subscription server API
    const basicPlanResp = await subPost(alicePage, ALICE_ID, `/api/creators/${ALICE_ID}/plans`, {
      name: `FC Basic ${TS}`,
      price_cents: 499,
      currency: "usd",
      interval: "month",
    });
    expect(basicPlanResp.ok()).toBe(true);
    const basicPlan = await basicPlanResp.json();
    basicPlanId = basicPlan.plan_id;

    const vipPlanResp = await subPost(alicePage, ALICE_ID, `/api/creators/${ALICE_ID}/plans`, {
      name: `FC VIP ${TS}`,
      price_cents: 999,
      currency: "usd",
      interval: "month",
    });
    expect(vipPlanResp.ok()).toBe(true);
    const vipPlan = await vipPlanResp.json();
    vipPlanId = vipPlan.plan_id;

    // Create tiers in beforeAll so all tests can reference them
    const tier1Resp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/tiers", {
      plan_id: basicPlanId,
      name: `Basic ${TS}`,
      level: 1,
      color: "#3B82F6",
      badge_emoji: "star",
      description: "Basic tier",
      benefits: [{ type: "badge", display: true }],
    });
    expect(tier1Resp.status()).toBe(201);
    const tier1 = await tier1Resp.json();
    tierId1 = tier1.tier_id;

    const tier2Resp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/tiers", {
      plan_id: vipPlanId,
      name: `VIP ${TS}`,
      level: 2,
      color: "#FFD700",
      badge_emoji: "crown",
      description: "VIP tier",
      benefits: [
        { type: "badge", display: true },
        { type: "early_access", delay_hours: 0 },
      ],
    });
    expect(tier2Resp.status()).toBe(201);
    const tier2 = await tier2Resp.json();
    tierId2 = tier2.tier_id;

    // Create VIP channel
    const chanResp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/channels", {
      name: `VIP Lounge ${TS}`,
      description: "For VIP members only",
      min_tier_level: 2,
    });
    expect(chanResp.status()).toBe(201);
    const chan = await chanResp.json();
    channelId = chan.channel_id;

    // Subscribe Bob to VIP plan
    const bobSubResp = await subPost(bobPage, BOB_ID, `/api/plans/${vipPlanId}/subscribe`, {
      subscriber_id: BOB_ID,
    });
    expect(bobSubResp.ok()).toBe(true);

    // Subscribe Charlie to Basic plan
    const charlieSubResp = await subPost(charliePage, CHARLIE_ID, `/api/plans/${basicPlanId}/subscribe`, {
      subscriber_id: CHARLIE_ID,
    });
    expect(charlieSubResp.ok()).toBe(true);

    // Invalidate badge caches so new subscriptions/tiers are used
    await fcPost(bobPage, BOB_ID, `/ui/fan-club/badge/${ALICE_ID}/invalidate`, {});
    await fcPost(charliePage, CHARLIE_ID, `/ui/fan-club/badge/${ALICE_ID}/invalidate`, {});
    await fcPost(alicePage, ALICE_ID, `/ui/fan-club/badge/${ALICE_ID}/invalidate`, {});
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
    await charliePage?.close();
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 1 — Tier CRUD API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("1 — Tier CRUD API", () => {
    test("1.1 — Tiers were created successfully", async () => {
      expect(tierId1).toBeTruthy();
      expect(tierId2).toBeTruthy();
    });

    test("1.2 — List tiers returns active tiers", async () => {
      const resp = await fcGet(alicePage, ALICE_ID, "/ui/fan-club/tiers");
      expect(resp.ok()).toBe(true);
      const tiers = await resp.json();
      expect(tiers.length).toBeGreaterThanOrEqual(2);
      const names = tiers.map((t: any) => t.name);
      expect(names).toContain(`Basic ${TS}`);
      expect(names).toContain(`VIP ${TS}`);
    });

    test("1.3 — Get single tier", async () => {
      const resp = await fcGet(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tierId1}`);
      expect(resp.ok()).toBe(true);
      const tier = await resp.json();
      expect(tier.tier_id).toBe(tierId1);
      expect(tier.name).toBe(`Basic ${TS}`);
      expect(tier.level).toBe(1);
      expect(tier.color).toBe("#3B82F6");
      expect(tier.badge_emoji).toBe("star");
    });

    test("1.4 — Update tier description", async () => {
      const resp = await fcPatch(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tierId1}`, {
        description: `Updated desc ${TS}`,
      });
      expect(resp.ok()).toBe(true);
      const tier = await resp.json();
      expect(tier.description).toBe(`Updated desc ${TS}`);
    });

    test("1.5 — Reorder tiers", async () => {
      const resp = await fcPatch(alicePage, ALICE_ID, "/ui/fan-club/tiers/reorder", {
        tier_ids: [tierId2, tierId1],
      });
      expect(resp.ok()).toBe(true);
      const tiers = await resp.json();
      expect(tiers.length).toBeGreaterThanOrEqual(2);
    });

    test("1.6 — Duplicate level returns 409", async () => {
      const resp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/tiers", {
        plan_id: basicPlanId,
        name: `Dup Level ${TS}`,
        level: 1, // same as Basic
        color: "#FF0000",
        benefits: [],
      });
      expect(resp.status()).toBe(409);
    });

    test("1.7 — Archive tier sets active=false", async () => {
      // Create a temporary tier to archive (use level 5 — within 1-6 range)
      const createResp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/tiers", {
        plan_id: basicPlanId,
        name: `Temp ${TS}`,
        level: 5,
        color: "#999999",
        benefits: [],
      });
      expect(createResp.status()).toBe(201);
      const tempTier = await createResp.json();

      const delResp = await fcDelete(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tempTier.tier_id}`);
      expect(delResp.ok()).toBe(true);

      // Verify it no longer appears in the active list
      const listResp = await fcGet(alicePage, ALICE_ID, "/ui/fan-club/tiers");
      const tiers = await listResp.json();
      const ids = tiers.map((t: any) => t.tier_id);
      expect(ids).not.toContain(tempTier.tier_id);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 2 — Badge Resolution API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("2 — Badge Resolution API", () => {
    test("2.1 — Bob (VIP subscriber) gets badge", async () => {
      const resp = await fcGet(bobPage, BOB_ID, `/ui/fan-club/badge/${ALICE_ID}`);
      expect(resp.ok()).toBe(true);
      const badge = await resp.json();
      expect(badge).not.toBeNull();
      expect(badge.tier_name).toBe(`VIP ${TS}`);
      expect(badge.tier_level).toBe(2);
      expect(badge.badge_emoji).toBe("crown");
    });

    test("2.2 — Charlie (Basic subscriber) gets badge", async () => {
      // Badge resolution caches a null result for 60s when the subscription
      // isn't yet visible. Under full-suite load a transient miss can poison
      // that cache, so invalidate first and poll until the badge resolves.
      await fcPost(charliePage, CHARLIE_ID, `/ui/fan-club/badge/${ALICE_ID}/invalidate`, {});
      let badge: any = null;
      await expect
        .poll(
          async () => {
            await fcPost(charliePage, CHARLIE_ID, `/ui/fan-club/badge/${ALICE_ID}/invalidate`, {});
            const resp = await fcGet(charliePage, CHARLIE_ID, `/ui/fan-club/badge/${ALICE_ID}`);
            if (!resp.ok()) return null;
            badge = await resp.json();
            return badge?.tier_name ?? null;
          },
          { timeout: 15_000, intervals: [500, 1000, 2000] },
        )
        .toBe(`Basic ${TS}`);
      expect(badge).not.toBeNull();
      expect(badge.tier_level).toBe(1);
      expect(badge.badge_emoji).toBe("star");
    });

    test("2.3 — Alice (creator) gets null badge for self", async () => {
      const resp = await fcGet(alicePage, ALICE_ID, `/ui/fan-club/badge/${ALICE_ID}`);
      expect(resp.ok()).toBe(true);
      const badge = await resp.json();
      expect(badge).toBeNull();
    });

    test("2.4 — Badge includes color", async () => {
      const resp = await fcGet(bobPage, BOB_ID, `/ui/fan-club/badge/${ALICE_ID}`);
      expect(resp.ok()).toBe(true);
      const badge = await resp.json();
      expect(badge.badge_color).toBe("#FFD700");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 3 — Exclusive Chat Channels API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("3 — Exclusive Chat Channels API", () => {
    test("3.1 — Channel was created with correct settings", async () => {
      const resp = await fcGet(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}`);
      expect(resp.ok()).toBe(true);
      const ch = await resp.json();
      expect(ch.name).toBe(`VIP Lounge ${TS}`);
      expect(ch.min_tier_level).toBe(2);
    });

    test("3.2 — Alice lists channels (sees all)", async () => {
      const resp = await fcGet(alicePage, ALICE_ID, "/ui/fan-club/channels");
      expect(resp.ok()).toBe(true);
      const channels = await resp.json();
      expect(channels.length).toBeGreaterThanOrEqual(1);
      const names = channels.map((c: any) => c.name);
      expect(names).toContain(`VIP Lounge ${TS}`);
    });

    test("3.3 — Bob (VIP) sends message to VIP channel", async () => {
      const resp = await fcPost(bobPage, BOB_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `Hello from VIP Bob ${TS}`,
      });
      expect(resp.status()).toBe(201);
      const msg = await resp.json();
      expect(msg.text).toBe(`Hello from VIP Bob ${TS}`);
      expect(msg.sender_id).toBe(BOB_ID);
      expect(msg.sender_badge).not.toBeNull();
      expect(msg.sender_badge.tier_name).toBe(`VIP ${TS}`);
    });

    test("3.4 — Get channel message history", async () => {
      const resp = await fcGet(bobPage, BOB_ID, `/ui/fan-club/channels/${channelId}/messages`);
      expect(resp.ok()).toBe(true);
      const messages = await resp.json();
      expect(messages.length).toBeGreaterThanOrEqual(1);
      const texts = messages.map((m: any) => m.text);
      expect(texts).toContain(`Hello from VIP Bob ${TS}`);
    });

    test("3.5 — Alice deletes a channel message", async () => {
      const sendResp = await fcPost(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `To be deleted ${TS}`,
      });
      expect(sendResp.status()).toBe(201);
      const sentMsg = await sendResp.json();

      const delResp = await fcDelete(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}/messages/${sentMsg.message_id}`);
      expect(delResp.ok()).toBe(true);

      const histResp = await fcGet(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}/messages`);
      const messages = await histResp.json();
      const ids = messages.map((m: any) => m.message_id);
      expect(ids).not.toContain(sentMsg.message_id);
    });

    test("3.6 — Charlie (Basic, level 1) gets 403 on VIP channel message", async () => {
      const resp = await fcPost(charliePage, CHARLIE_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: "I should not be able to send this",
      });
      expect(resp.status()).toBe(403);
      const body = await resp.json();
      expect(body.detail).toContain("membership tier");
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 4 — Early Access Content API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("4 — Early Access Content API", () => {
    test("4.1 — Bob (VIP) can view early access content", async () => {
      const resp = await fcPost(bobPage, BOB_ID, "/ui/fan-club/early-access-check", {
        creator_id: ALICE_ID,
        content: {
          early_access_tier_level: 2,
          general_release_at: Math.floor(Date.now() / 1000) + 86400,
        },
      });
      expect(resp.ok()).toBe(true);
      const result = await resp.json();
      expect(result.can_view).toBe(true);
      expect(result.is_early_access).toBe(true);
    });

    test("4.2 — Charlie (Basic) cannot view VIP early access content", async () => {
      const resp = await fcPost(charliePage, CHARLIE_ID, "/ui/fan-club/early-access-check", {
        creator_id: ALICE_ID,
        content: {
          early_access_tier_level: 2,
          general_release_at: Math.floor(Date.now() / 1000) + 86400,
        },
      });
      expect(resp.ok()).toBe(true);
      const result = await resp.json();
      expect(result.can_view).toBe(false);
      expect(result.required_tier_level).toBe(2);
      expect(result.user_tier_level).toBe(1);
    });

    test("4.3 — Past general release time allows access", async () => {
      const resp = await fcPost(charliePage, CHARLIE_ID, "/ui/fan-club/early-access-check", {
        creator_id: ALICE_ID,
        content: {
          early_access_tier_level: 2,
          general_release_at: Math.floor(Date.now() / 1000) - 3600,
        },
      });
      expect(resp.ok()).toBe(true);
      const result = await resp.json();
      expect(result.can_view).toBe(true);
    });

    test("4.4 — Creator always can view own content", async () => {
      const resp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/early-access-check", {
        creator_id: ALICE_ID,
        content: {
          early_access_tier_level: 99,
          general_release_at: Math.floor(Date.now() / 1000) + 999999,
        },
      });
      expect(resp.ok()).toBe(true);
      const result = await resp.json();
      expect(result.can_view).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 5 — Fan Club Page UI
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("5 — Fan Club Page UI", () => {
    test("5.1 — Page loads with tiers tab", async () => {
      await alicePage.goto(`${BASE}/fan-club`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.locator("h1, h2, h3, [class*='title']").filter({ hasText: "Fan Club" }).first()).toBeVisible({ timeout: 10_000 });
      await expect(alicePage.getByRole("tab", { name: "Tiers" })).toBeVisible();
      await expect(alicePage.getByRole("tab", { name: "Channels" })).toBeVisible();
    });

    test("5.2 — Tiers tab shows tier cards", async () => {
      await alicePage.goto(`${BASE}/fan-club`, { waitUntil: "domcontentloaded" });
      await expect(alicePage.getByText(`Basic ${TS}`).first()).toBeVisible({ timeout: 10_000 });
      await expect(alicePage.getByText(`VIP ${TS}`).first()).toBeVisible();
    });

    test("5.3 — Create tier dialog opens", async () => {
      await alicePage.goto(`${BASE}/fan-club`, { waitUntil: "domcontentloaded" });
      // Wait for tiers to load first
      await expect(alicePage.getByText(`Basic ${TS}`).first()).toBeVisible({ timeout: 10_000 });
      await alicePage.getByRole("button", { name: /Create Tier/i }).click();
      await expect(alicePage.getByRole("dialog")).toBeVisible();
      await expect(alicePage.getByLabel("Name")).toBeVisible();
      await expect(alicePage.getByLabel("Level")).toBeVisible();
      await alicePage.keyboard.press("Escape");
    });

    test("5.4 — Channels tab shows channel list", async () => {
      await alicePage.goto(`${BASE}/fan-club`, { waitUntil: "domcontentloaded" });
      await alicePage.getByRole("tab", { name: "Channels" }).click();
      await expect(alicePage.getByText(`VIP Lounge ${TS}`).first()).toBeVisible({ timeout: 10_000 });
    });

    test("5.5 — Channel card opens chat view", async () => {
      await alicePage.goto(`${BASE}/fan-club`, { waitUntil: "domcontentloaded" });
      await alicePage.getByRole("tab", { name: "Channels" }).click();
      await expect(alicePage.getByText(`VIP Lounge ${TS}`).first()).toBeVisible({ timeout: 10_000 });
      await alicePage.getByText(`VIP Lounge ${TS}`).first().click();
      await expect(alicePage.getByPlaceholder("Type a message...")).toBeVisible({ timeout: 5_000 });
      await expect(alicePage.getByRole("button", { name: "Back" })).toBeVisible();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 6 — Badge Display Integration
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("6 — Badge Display Integration", () => {
    test("6.1 — Channel message contains sender badge", async () => {
      const resp = await fcPost(bobPage, BOB_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `Badge test ${TS}`,
      });
      expect(resp.status()).toBe(201);
      const msg = await resp.json();
      expect(msg.sender_badge).toBeTruthy();
      expect(msg.sender_badge.tier_name).toBe(`VIP ${TS}`);
      expect(msg.sender_badge.badge_emoji).toBe("crown");
      expect(msg.sender_badge.badge_color).toBe("#FFD700");
    });

    test("6.2 — Creator message has no badge in own channel", async () => {
      const resp = await fcPost(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `Creator msg ${TS}`,
      });
      expect(resp.status()).toBe(201);
      const msg = await resp.json();
      expect(msg.sender_badge).toBeNull();
    });

    test("6.3 — Public tier listing returns tiers", async () => {
      const resp = await alicePage.request.get(`${API}/api/creators/${ALICE_ID}/tiers`);
      expect(resp.ok()).toBe(true);
      const tiers = await resp.json();
      expect(tiers.length).toBeGreaterThanOrEqual(2);
      const names = tiers.map((t: any) => t.name);
      expect(names).toContain(`Basic ${TS}`);
      expect(names).toContain(`VIP ${TS}`);
    });

    test("6.4 — Tier members endpoint returns structure", async () => {
      const resp = await fcGet(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tierId2}/members`);
      expect(resp.ok()).toBe(true);
      const result = await resp.json();
      expect(result).toBeDefined();
      expect(result.members).toBeDefined();
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 7 — Tier Upgrade/Downgrade API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("7 — Tier Upgrade/Downgrade API", () => {
    test("7.1 — Charlie upgrades to VIP — can access VIP channel", async () => {
      // Charlie subscribes to VIP plan (in addition to Basic)
      const subResp = await subPost(charliePage, CHARLIE_ID, `/api/plans/${vipPlanId}/subscribe`, {
        subscriber_id: CHARLIE_ID,
      });
      expect(subResp.ok()).toBe(true);

      // Invalidate Charlie's badge cache so the new VIP sub is picked up
      const invResp = await fcPost(charliePage, CHARLIE_ID, `/ui/fan-club/badge/${ALICE_ID}/invalidate`, {});
      expect(invResp.ok()).toBe(true);

      // Now Charlie should be able to send to VIP channel
      const resp = await fcPost(charliePage, CHARLIE_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `Charlie VIP access ${TS}`,
      });
      expect(resp.status()).toBe(201);
    });

    test("7.2 — Update tier name", async () => {
      const resp = await fcPatch(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tierId2}`, {
        name: `VIP Updated ${TS}`,
      });
      expect(resp.ok()).toBe(true);
      const tier = await resp.json();
      expect(tier.name).toBe(`VIP Updated ${TS}`);

      // Restore name
      await fcPatch(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tierId2}`, {
        name: `VIP ${TS}`,
      });
    });

    test("7.3 — Create and archive tier", async () => {
      const createResp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/tiers", {
        plan_id: basicPlanId,
        name: `Temp7 ${TS}`,
        level: 6,
        color: "#999999",
        benefits: [],
      });
      expect(createResp.status()).toBe(201);
      const tempTier = await createResp.json();

      const delResp = await fcDelete(alicePage, ALICE_ID, `/ui/fan-club/tiers/${tempTier.tier_id}`);
      expect(delResp.ok()).toBe(true);

      const listResp = await fcGet(alicePage, ALICE_ID, "/ui/fan-club/tiers");
      const tiers = await listResp.json();
      const ids = tiers.map((t: any) => t.tier_id);
      expect(ids).not.toContain(tempTier.tier_id);
    });

    test("7.4 — Reorder persists sort_order", async () => {
      const resp = await fcPatch(alicePage, ALICE_ID, "/ui/fan-club/tiers/reorder", {
        tier_ids: [tierId1, tierId2],
      });
      expect(resp.ok()).toBe(true);
      const tiers = await resp.json();
      const t1 = tiers.find((t: any) => t.tier_id === tierId1);
      const t2 = tiers.find((t: any) => t.tier_id === tierId2);
      expect(t1?.sort_order).toBe(0);
      expect(t2?.sort_order).toBe(1);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // Section 8 — Channel Features API
  // ═══════════════════════════════════════════════════════════════════════════

  test.describe("8 — Channel Features API", () => {
    let channelId2: string;

    test("8.1 — Create channel with slowmode and length limit", async () => {
      const resp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/channels", {
        name: `Slow Channel ${TS}`,
        description: "Channel with slowmode",
        min_tier_level: 1,
        slowmode_seconds: 5,
        max_message_length: 50,
      });
      expect(resp.status()).toBe(201);
      const ch = await resp.json();
      expect(ch.slowmode_seconds).toBe(5);
      expect(ch.max_message_length).toBe(50);
      channelId2 = ch.channel_id;
    });

    test("8.2 — Message length limit enforced", async () => {
      // Create a fresh channel for this test (channelId2 might be undefined if 8.1 ran in different worker)
      let testChanId = channelId2;
      if (!testChanId) {
        const resp = await fcPost(alicePage, ALICE_ID, "/ui/fan-club/channels", {
          name: `Len Limit ${TS}`,
          min_tier_level: 1,
          max_message_length: 50,
        });
        const ch = await resp.json();
        testChanId = ch.channel_id;
      }
      const longText = "A".repeat(51);
      const resp = await fcPost(bobPage, BOB_ID, `/ui/fan-club/channels/${testChanId}/messages`, {
        text: longText,
      });
      expect(resp.status()).toBe(400);
      const body = await resp.json();
      expect(body.detail).toContain("Message too long");
    });

    test("8.3 — Pin message", async () => {
      const sendResp = await fcPost(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `Pinned msg ${TS}`,
      });
      expect(sendResp.status()).toBe(201);
      const msg = await sendResp.json();

      const pinResp = await fcPut(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}/pin/${msg.message_id}`);
      expect(pinResp.ok()).toBe(true);

      const chResp = await fcGet(alicePage, ALICE_ID, `/ui/fan-club/channels/${channelId}`);
      const ch = await chResp.json();
      expect(ch.pinned_message_id).toBe(msg.message_id);
    });

    test("8.4 — Add reaction to message", async () => {
      const sendResp = await fcPost(bobPage, BOB_ID, `/ui/fan-club/channels/${channelId}/messages`, {
        text: `React to me ${TS}`,
      });
      expect(sendResp.status()).toBe(201);
      const msg = await sendResp.json();

      const reactResp = await fcPost(bobPage, BOB_ID, `/ui/fan-club/channels/${channelId}/messages/${msg.message_id}/react`, {
        emoji: "thumbsup",
      });
      expect(reactResp.ok()).toBe(true);

      const histResp = await fcGet(bobPage, BOB_ID, `/ui/fan-club/channels/${channelId}/messages`);
      const messages = await histResp.json();
      const reactedMsg = messages.find((m: any) => m.message_id === msg.message_id);
      expect(reactedMsg).toBeTruthy();
      expect(reactedMsg.reactions).toBeTruthy();
      expect(reactedMsg.reactions["thumbsup"]).toBeTruthy();
      expect(reactedMsg.reactions["thumbsup"][BOB_ID]).toBe(true);
    });
  });
});
