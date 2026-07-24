/**
 * E2E tests for Bot Auto-Reply Rules (BOT-003).
 *
 * Sections:
 *   80 — Auto-Reply Rule CRUD (API)
 *   81 — Match type behavior (API)
 *   82 — Priority ordering & disabled rules (API)
 *   83 — Test message endpoint (API)
 *
 * Auth:
 *   Cookie session + x-csrf-token header (require_ui_session)
 *
 * Test users (from e2e_session_setup.py):
 *   Alice (e2e_alice@test.local) — bot owner
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
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
    _sessions = loadSessions();
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

// ─── API helpers (cookie session + CSRF) ──────────────────────────────────────

async function apiPost(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

async function apiPut(page: Page, userId: string, path: string, body: object) {
  const session = getSessions()[userId];
  return page.request.put(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": session.csrf_token },
  });
}

async function apiDelete(page: Page, userId: string, path: string) {
  const session = getSessions()[userId];
  return page.request.delete(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
  });
}

// ─── Test-scoped state ────────────────────────────────────────────────────────

let alicePage: Page;
let botId: string;

test.describe("Bot Auto-Reply (BOT-003)", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);

    // Create a bot for testing
    const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots", {
      name: `AutoReply Test Bot ${TS}`,
      description: "Bot for auto-reply E2E tests",
      personality: "friendly",
    });
    expect(resp.status()).toBe(201);
    const bot = await resp.json();
    botId = bot.bot_id;
  });

  test.afterAll(async () => {
    // Clean up bot
    if (botId) {
      await apiDelete(alicePage, ALICE_ID, `/ui/bots/${botId}`);
    }
    await alicePage?.close();
  });

  // ===========================================================================
  // Section 80 — Auto-Reply Rule CRUD (API)
  // ===========================================================================

  test.describe("80 — Auto-Reply Rule CRUD", () => {
    let ruleId: string;

    test("80.1 create auto-reply rule", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `hello_${TS}`,
        response_template: "Hi there! How can I help?",
        match_type: "contains",
        priority: 10,
        enabled: true,
      });
      expect(resp.status()).toBe(201);
      const rule = await resp.json();
      expect(rule.rule_id).toBeTruthy();
      expect(rule.bot_id).toBe(botId);
      expect(rule.trigger_pattern).toBe(`hello_${TS}`);
      expect(rule.response_template).toBe("Hi there! How can I help?");
      expect(rule.match_type).toBe("contains");
      expect(rule.priority).toBe(10);
      expect(rule.enabled).toBe(true);
      expect(rule.match_count).toBe(0);
      ruleId = rule.rule_id;
    });

    test("80.2 list auto-reply rules returns the created rule", async () => {
      const resp = await apiGet(alicePage, `/ui/bots/${botId}/auto-replies`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.rules).toBeInstanceOf(Array);
      const found = data.rules.find((r: any) => r.rule_id === ruleId);
      expect(found).toBeTruthy();
      expect(found.trigger_pattern).toBe(`hello_${TS}`);
    });

    test("80.3 get single auto-reply rule", async () => {
      const resp = await apiGet(alicePage, `/ui/bots/${botId}/auto-replies/${ruleId}`);
      expect(resp.status()).toBe(200);
      const rule = await resp.json();
      expect(rule.rule_id).toBe(ruleId);
      expect(rule.trigger_pattern).toBe(`hello_${TS}`);
    });

    test("80.4 update auto-reply rule", async () => {
      const resp = await apiPut(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/${ruleId}`, {
        response_template: "Updated response!",
        priority: 5,
      });
      expect(resp.status()).toBe(200);
      const rule = await resp.json();
      expect(rule.response_template).toBe("Updated response!");
      expect(rule.priority).toBe(5);
      // Trigger pattern should remain unchanged
      expect(rule.trigger_pattern).toBe(`hello_${TS}`);
    });

    test("80.5 delete auto-reply rule", async () => {
      const resp = await apiDelete(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/${ruleId}`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.ok).toBe(true);

      // Verify deleted
      const getResp = await apiGet(alicePage, `/ui/bots/${botId}/auto-replies/${ruleId}`);
      expect(getResp.status()).toBe(404);
    });

    test("80.6 delete non-existent rule returns 404", async () => {
      const resp = await apiDelete(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/nonexistent`);
      expect(resp.status()).toBe(404);
    });

    test("80.7 create rule on non-existent bot returns 404", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots/nonexistent/auto-replies", {
        trigger_pattern: "test",
        response_template: "test response",
      });
      expect(resp.status()).toBe(404);
    });
  });

  // ===========================================================================
  // Section 81 — Match type behavior (API)
  // ===========================================================================

  test.describe("81 — Match types", () => {
    let containsRuleId: string;
    let exactRuleId: string;
    let keywordRuleId: string;
    let regexRuleId: string;

    test.beforeAll(async () => {
      // Create rules with different match types
      const containsResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `support_${TS}`,
        response_template: "Contains match response",
        match_type: "contains",
        priority: 100,
      });
      containsRuleId = (await containsResp.json()).rule_id;

      const exactResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `exact_match_${TS}`,
        response_template: "Exact match response",
        match_type: "exact",
        priority: 100,
      });
      exactRuleId = (await exactResp.json()).rule_id;

      const keywordResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `kw1_${TS}, kw2_${TS}`,
        response_template: "Keyword match response",
        match_type: "keyword",
        priority: 100,
      });
      keywordRuleId = (await keywordResp.json()).rule_id;

      const regexResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `^regex_${TS}_\\d+$`,
        response_template: "Regex match response",
        match_type: "regex",
        priority: 100,
      });
      regexRuleId = (await regexResp.json()).rule_id;
    });

    test.afterAll(async () => {
      for (const id of [containsRuleId, exactRuleId, keywordRuleId, regexRuleId]) {
        if (id) await apiDelete(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/${id}`);
      }
    });

    test("81.1 contains match works with substring", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `I need support_${TS} please`,
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.matched).toBe(true);
      expect(data.first_match.response_text).toBe("Contains match response");
    });

    test("81.2 exact match only matches full text", async () => {
      // Should NOT match with extra text
      const resp1 = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `exact_match_${TS} plus more`,
      });
      const data1 = await resp1.json();
      // The exact rule should NOT match but contains might still match
      const exactMatch = data1.all_matches?.find((m: any) => m.match_type === "exact");
      expect(exactMatch).toBeUndefined();

      // Should match exact text
      const resp2 = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `exact_match_${TS}`,
      });
      const data2 = await resp2.json();
      expect(data2.matched).toBe(true);
      const exactMatch2 = data2.all_matches?.find((m: any) => m.match_type === "exact");
      expect(exactMatch2).toBeTruthy();
      expect(exactMatch2.response_text).toBe("Exact match response");
    });

    test("81.3 keyword match works with any keyword", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `please kw2_${TS} help`,
      });
      const data = await resp.json();
      expect(data.matched).toBe(true);
      const kwMatch = data.all_matches?.find((m: any) => m.match_type === "keyword");
      expect(kwMatch).toBeTruthy();
      expect(kwMatch.response_text).toBe("Keyword match response");
    });

    test("81.4 regex match works with pattern", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `regex_${TS}_42`,
      });
      const data = await resp.json();
      expect(data.matched).toBe(true);
      const regexMatch = data.all_matches?.find((m: any) => m.match_type === "regex");
      expect(regexMatch).toBeTruthy();
      expect(regexMatch.response_text).toBe("Regex match response");
    });
  });

  // ===========================================================================
  // Section 82 — Priority ordering & disabled rules (API)
  // ===========================================================================

  test.describe("82 — Priority & disabled rules", () => {
    let highPriorityId: string;
    let lowPriorityId: string;
    let disabledRuleId: string;

    test.beforeAll(async () => {
      // Create rules with different priorities
      const highResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `priority_${TS}`,
        response_template: "High priority response",
        match_type: "contains",
        priority: 1,
      });
      highPriorityId = (await highResp.json()).rule_id;

      const lowResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `priority_${TS}`,
        response_template: "Low priority response",
        match_type: "contains",
        priority: 999,
      });
      lowPriorityId = (await lowResp.json()).rule_id;

      const disabledResp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `disabled_${TS}`,
        response_template: "This should never be returned",
        match_type: "contains",
        priority: 1,
        enabled: false,
      });
      disabledRuleId = (await disabledResp.json()).rule_id;
    });

    test.afterAll(async () => {
      for (const id of [highPriorityId, lowPriorityId, disabledRuleId]) {
        if (id) await apiDelete(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/${id}`);
      }
    });

    test("82.1 rules are listed in priority order", async () => {
      const resp = await apiGet(alicePage, `/ui/bots/${botId}/auto-replies`);
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      const rules = data.rules;
      // Check that rules are sorted by priority (ascending)
      for (let i = 1; i < rules.length; i++) {
        expect(rules[i].priority).toBeGreaterThanOrEqual(rules[i - 1].priority);
      }
    });

    test("82.2 first matching rule (highest priority) wins in test", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `has priority_${TS} in it`,
      });
      const data = await resp.json();
      expect(data.matched).toBe(true);
      // first_match should be the high-priority rule
      expect(data.first_match.response_text).toBe("High priority response");
      expect(data.first_match.priority).toBe(1);
      // all_matches should include both
      expect(data.match_count).toBeGreaterThanOrEqual(2);
    });

    test("82.3 disabled rule is skipped in matching", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `contains disabled_${TS}`,
      });
      const data = await resp.json();
      // The disabled rule should not match
      expect(data.matched).toBe(false);
      expect(data.match_count).toBe(0);
    });

    test("82.4 enabling a disabled rule makes it match", async () => {
      // Enable the rule
      const enableResp = await apiPut(
        alicePage,
        ALICE_ID,
        `/ui/bots/${botId}/auto-replies/${disabledRuleId}`,
        { enabled: true },
      );
      expect(enableResp.status()).toBe(200);

      // Now test again
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `contains disabled_${TS}`,
      });
      const data = await resp.json();
      expect(data.matched).toBe(true);
      expect(data.first_match.response_text).toBe("This should never be returned");

      // Disable again for cleanup
      await apiPut(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/${disabledRuleId}`, {
        enabled: false,
      });
    });
  });

  // ===========================================================================
  // Section 83 — Test message endpoint (API)
  // ===========================================================================

  test.describe("83 — Test message endpoint", () => {
    let testRuleId: string;

    test.beforeAll(async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies`, {
        trigger_pattern: `testmsg_${TS}`,
        response_template: "Test response for test endpoint",
        match_type: "contains",
        priority: 50,
      });
      testRuleId = (await resp.json()).rule_id;
    });

    test.afterAll(async () => {
      if (testRuleId) {
        await apiDelete(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/${testRuleId}`);
      }
    });

    test("83.1 test endpoint returns match result without side effects", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `message with testmsg_${TS} inside`,
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.matched).toBe(true);
      expect(data.first_match).toBeTruthy();
      expect(data.first_match.rule_id).toBe(testRuleId);
      expect(data.first_match.response_text).toBe("Test response for test endpoint");
      expect(data.all_matches).toBeInstanceOf(Array);
      expect(data.match_count).toBeGreaterThanOrEqual(1);
    });

    test("83.2 test endpoint returns no match for non-matching message", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: "this will not match anything unique " + Date.now(),
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.matched).toBe(false);
      expect(data.first_match).toBeNull();
      expect(data.all_matches).toEqual([]);
      expect(data.match_count).toBe(0);
    });

    test("83.3 test on non-existent bot returns 404", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, "/ui/bots/nonexistent/auto-replies/test", {
        message_text: "test",
      });
      expect(resp.status()).toBe(404);
    });

    test("83.4 test with case-insensitive matching", async () => {
      const resp = await apiPost(alicePage, ALICE_ID, `/ui/bots/${botId}/auto-replies/test`, {
        message_text: `MESSAGE WITH TESTMSG_${TS} UPPERCASE`,
      });
      expect(resp.status()).toBe(200);
      const data = await resp.json();
      expect(data.matched).toBe(true);
    });
  });
});
