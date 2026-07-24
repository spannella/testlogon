/**
 * E2E tests for KYC-011: KYC Webhooks & Notifications.
 *
 * Section 194: KYC event-type registry + preferences (list, defaults, update,
 *   filter invalid, per-user).
 * Section 195: Event dispatch — user subscribes a webhook endpoint to a kyc.*
 *   event, an admin test-emit fires the event → a webhook delivery is recorded
 *   on that endpoint AND an in-app notification is written for the user.
 * Section 196: Negatives — unknown kyc event rejected (422); test-emit requires
 *   admin/root.
 *
 * Reuses the EXISTING webhook infrastructure: subscriptions via /ui/webhooks,
 * deliveries via the existing webhook_deliveries table, in-app via alerts.
 *
 * Auth: cookie + CSRF via e2e_admin_session_setup.py (root, alice, bob,
 * charlie_admin). User endpoints use require_ui_session; test-emit uses
 * require_admin_or_root.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");


interface SessionData {
  user_sub: string;
  csrf_token: string;
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

async function injectAuth(page: Page, identity: string): Promise<void> {
  await page.context().addCookies(getSessions()[identity].cookies);
  await page.goto("http://localhost:3000/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, getSessions()[identity].user_sub);
}

async function newIdentityPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await injectAuth(page, identity);
  return page;
}

async function apiPost(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.post(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiPatch(page: Page, identity: string, path: string, body?: unknown) {
  const sess = getSessions()[identity];
  return page.request.patch(`${API}/${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": sess.csrf_token, "Content-Type": "application/json" },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}/${path}`, { params });
}

const TS = Date.now();

// ─── Section 194: Event-type registry + preferences ─────────────────────────

test.describe("194: KYC webhook event types + preferences", () => {
  let alice: Page;
  let bob: Page;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    bob = await newIdentityPage(browser, "bob");
  });
  test.afterAll(async () => {
    await alice.close();
    await bob.close();
  });

  test("194.1 List KYC event types returns canonical kyc.* allowlist", async () => {
    const resp = await apiGet(alice, "ui/kyc/webhooks/event-types");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const types: string[] = data.event_types.map((e: { event_type: string }) => e.event_type);
    expect(types).toContain("kyc.case.submitted");
    expect(types).toContain("kyc.document.verified");
    expect(types).toContain("kyc.sanctions.match");
    // every entry is a kyc.* event with a description
    for (const e of data.event_types) {
      expect(e.event_type.startsWith("kyc.")).toBe(true);
      expect(typeof e.description).toBe("string");
    }
  });

  test("194.2 Preferences return defaults for a new user", async () => {
    const resp = await apiGet(alice, "ui/kyc/webhooks/preferences");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.in_app_enabled).toBe("boolean");
    expect(typeof data.email_enabled).toBe("boolean");
    expect(Array.isArray(data.events)).toBe(true);
  });

  test("194.3 PATCH preferences updates email_enabled", async () => {
    const patch = await apiPatch(alice, "alice", "ui/kyc/webhooks/preferences", {
      email_enabled: false,
    });
    expect(patch.status()).toBe(200);
    const data = await patch.json();
    expect(data.email_enabled).toBe(false);
    const get = await apiGet(alice, "ui/kyc/webhooks/preferences");
    expect((await get.json()).email_enabled).toBe(false);
    // restore
    await apiPatch(alice, "alice", "ui/kyc/webhooks/preferences", { email_enabled: true });
  });

  test("194.4 PATCH preferences filters out invalid event types", async () => {
    const patch = await apiPatch(alice, "alice", "ui/kyc/webhooks/preferences", {
      events: ["kyc.case.approved", "not.a.real.event", "kyc.case.submitted"],
    });
    expect(patch.status()).toBe(200);
    const events: string[] = (await patch.json()).events;
    expect(events).toContain("kyc.case.approved");
    expect(events).toContain("kyc.case.submitted");
    expect(events).not.toContain("not.a.real.event");
  });

  test("194.5 Preferences are per-user (alice change does not affect bob)", async () => {
    await apiPatch(alice, "alice", "ui/kyc/webhooks/preferences", { events: ["kyc.case.approved"] });
    const bobResp = await apiGet(bob, "ui/kyc/webhooks/preferences");
    const bobEvents: string[] = (await bobResp.json()).events;
    // bob keeps full defaults (not narrowed to alice's single event)
    expect(bobEvents.length).toBeGreaterThan(1);
  });
});

// ─── Section 195: Dispatch → webhook delivery + in-app notification ──────────

test.describe("195: KYC event dispatch via existing webhook + alert infra", () => {
  let alice: Page;
  let root: Page;
  let endpointId = "";

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");

    // Ensure alice subscribes to the kyc events we test-emit.
    await apiPatch(alice, "alice", "ui/kyc/webhooks/preferences", {
      in_app_enabled: true,
      email_enabled: true,
      events: ["kyc.case.submitted", "kyc.case.approved", "kyc.sanctions.match"],
    });

    // Register a webhook endpoint for alice subscribed to kyc.case.submitted.
    const create = await apiPost(alice, "alice", "ui/webhooks", {
      url: `https://kyc-hook-${TS}.example.com/ingest`,
      description: "KYC-011 e2e",
      event_types: ["kyc.case.submitted", "kyc.case.approved"],
    });
    expect(create.status()).toBe(201);
    endpointId = (await create.json()).endpoint_id;
    expect(endpointId).toBeTruthy();
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("195.1 Webhook endpoint accepts kyc.* event types", async () => {
    const list = await apiGet(alice, "ui/webhooks");
    const eps = await list.json();
    const ep = eps.find((e: { endpoint_id: string }) => e.endpoint_id === endpointId);
    expect(ep).toBeTruthy();
    expect(ep.event_types).toContain("kyc.case.submitted");
  });

  test("195.2 Admin test-emit dispatches a delivery to the subscribed endpoint", async () => {
    const aliceSub = getSessions().alice.user_sub;
    const emit = await apiPost(root, "root", "ui/kyc/webhooks/test-emit", {
      event: "kyc.case.submitted",
      user_sub: aliceSub,
      case_id: `kyc_e2e_${TS}`,
    });
    expect(emit.status()).toBe(200);
    const result = await emit.json();
    expect(result.dispatched).toBe(true);
    expect(result.channels.in_app).toBe(true);
    expect(result.channels.webhook).toBe(true);
    expect(result.webhook_delivery_ids.length).toBeGreaterThanOrEqual(1);

    // The delivery is recorded on alice's endpoint via the existing delivery log.
    const deliveries = await apiGet(alice, `ui/webhooks/${endpointId}/deliveries`);
    expect(deliveries.status()).toBe(200);
    const body = await deliveries.json();
    const found = body.deliveries.find(
      (d: { event_type: string }) => d.event_type === "kyc.case.submitted",
    );
    expect(found).toBeTruthy();
  });

  test("195.3 Dispatch writes an in-app KYC notification for the user", async () => {
    const notifs = await apiGet(alice, "ui/kyc/webhooks/notifications");
    expect(notifs.status()).toBe(200);
    const body = await notifs.json();
    const submitted = body.items.find(
      (n: { event: string }) => n.event === "kyc.case.submitted",
    );
    expect(submitted).toBeTruthy();
    expect(submitted.action_url).toContain("/kyc");
  });

  test("195.4 Notification history only contains kyc.* events", async () => {
    const notifs = await apiGet(alice, "ui/kyc/webhooks/notifications");
    const body = await notifs.json();
    for (const n of body.items) {
      expect(n.event.startsWith("kyc.")).toBe(true);
    }
  });

  test("195.5 A sanctions match emit dispatches and notifies", async () => {
    const aliceSub = getSessions().alice.user_sub;
    const emit = await apiPost(root, "root", "ui/kyc/webhooks/test-emit", {
      event: "kyc.sanctions.match",
      user_sub: aliceSub,
      case_id: `kyc_san_${TS}`,
      data: { match_count: 2 },
    });
    expect(emit.status()).toBe(200);
    const result = await emit.json();
    expect(result.dispatched).toBe(true);
    expect(result.channels.in_app).toBe(true);
    // admin/compliance audit channel fires for sanctions match
    expect(result.channels.admin).toBe(true);
  });
});

// ─── Section 196: Negatives + access control ────────────────────────────────

test.describe("196: KYC webhook negatives + access control", () => {
  let alice: Page;
  let root: Page;

  test.beforeAll(async ({ browser }) => {
    alice = await newIdentityPage(browser, "alice");
    root = await newIdentityPage(browser, "root");
  });
  test.afterAll(async () => {
    await alice.close();
    await root.close();
  });

  test("196.1 Unknown kyc event type is rejected (422)", async () => {
    const emit = await apiPost(root, "root", "ui/kyc/webhooks/test-emit", {
      event: "kyc.not.a.real.event",
      user_sub: getSessions().alice.user_sub,
    });
    expect(emit.status()).toBe(422);
  });

  test("196.2 Subscribing a webhook endpoint to an unknown kyc event is rejected", async () => {
    const create = await apiPost(alice, "alice", "ui/webhooks", {
      url: `https://kyc-bad-${TS}.example.com/ingest`,
      event_types: ["kyc.totally.bogus"],
    });
    expect(create.status()).toBe(400);
  });

  test("196.3 Non-admin user cannot test-emit (403)", async () => {
    const emit = await apiPost(alice, "alice", "ui/kyc/webhooks/test-emit", {
      event: "kyc.case.submitted",
      user_sub: getSessions().alice.user_sub,
    });
    expect(emit.status()).toBe(403);
  });

  test("196.4 Unauthenticated event-type listing is rejected (401)", async ({ request }) => {
    const resp = await request.get(`${API}/ui/kyc/webhooks/event-types`);
    expect(resp.status()).toBe(401);
  });
});
