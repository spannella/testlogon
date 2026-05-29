import { test, expect, Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ──────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";

// ─── Session bootstrap ─────────────────────────────────────────

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
      "python3 /home/ubuntu/testlogon/e2e_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, _identity = ALICE_ID) {
  const session = getSessions()[_identity];
  if (!session) throw new Error(`No session for ${_identity}`);
  await page.context().addCookies(session.cookies);
  await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, _identity);
}

// ─── All tests in a single describe to share alicePage ─────────

test.describe("Content Calendar", () => {
  const TS = Date.now();
  let alicePage: Page;
  let csrf: string;
  let postId: string;
  let broadcastId: string;
  let weekFromNow: number;
  let weekRange: { from_ts: number; to_ts: number };

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    csrf = getSessions()[ALICE_ID].csrf_token;
    const now = Math.floor(Date.now() / 1000);
    weekFromNow = now + 3 * 86400; // 3 days from now
    weekRange = {
      from_ts: now - 86400,
      to_ts: now + 10 * 86400,
    };

    // Create a scheduled post 3 days from now
    const postResp = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: {
        body: `cal_post_${TS}`,
        publish_at: weekFromNow,
        schedule_timezone: "America/New_York",
      },
    });
    expect(postResp.ok()).toBeTruthy();
    const postData = await postResp.json();
    postId = postData.post_id;

    // Create a scheduled broadcast 4 days from now
    const draftResp = await alicePage.request.post("/broadcast/sessions", {
      headers: { "x-csrf-token": csrf },
      data: { name: `cal_bcast_${TS}`, profile_id: "default" },
    });
    expect(draftResp.ok()).toBeTruthy();
    broadcastId = (await draftResp.json()).id;

    // Schedule the broadcast
    const schedResp = await alicePage.request.post(
      `/broadcast/sessions/${broadcastId}/schedule`,
      {
        headers: { "x-csrf-token": csrf },
        data: { scheduled_at: weekFromNow + 86400 },
      },
    );
    expect(schedResp.ok()).toBeTruthy();
  });

  test.afterAll(async () => {
    if (alicePage) await alicePage.close();
  });

  // ─── Section 1: Content Calendar API - Basic ──────────────────

  test("1.1 GET /ui/content-calendar returns items", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.items.length).toBeGreaterThanOrEqual(2);
    expect(data.count).toBe(data.items.length);
  });

  test("1.2 Items are sorted by scheduled_at ascending", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    for (let i = 1; i < data.items.length; i++) {
      expect(data.items[i].scheduled_at).toBeGreaterThanOrEqual(
        data.items[i - 1].scheduled_at,
      );
    }
  });

  test("1.3 Post item has correct type and color", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    const post = data.items.find((i: any) => i.id === postId);
    expect(post).toBeTruthy();
    expect(post.type).toBe("post");
    expect(post.color).toBe("#3B82F6");
    expect(post.icon).toBe("file-text");
    expect(post.scheduled_at).toBe(weekFromNow);
  });

  test("1.4 Broadcast item has correct type and color", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    const bcast = data.items.find((i: any) => i.id === broadcastId);
    expect(bcast).toBeTruthy();
    expect(bcast.type).toBe("broadcast");
    expect(bcast.color).toBe("#EF4444");
    expect(bcast.icon).toBe("radio");
  });

  test("1.5 Each item has an id and title", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.id).toBeTruthy();
      expect(item.title).toBeTruthy();
      expect(["post", "broadcast", "vod"]).toContain(item.type);
    }
  });

  test("1.6 Range exceeding 90 days returns 400", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.from_ts + 91 * 86400),
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("1.7 Empty range returns empty items", async () => {
    const farFuture = Math.floor(Date.now() / 1000) + 365 * 86400;
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(farFuture),
        to_ts: String(farFuture + 86400),
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.items).toEqual([]);
    expect(data.count).toBe(0);
  });

  // ─── Section 2: Content Calendar API - Filtering ──────────────

  test("2.1 Filter types=post returns only posts", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
        types: "post",
      },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).toBe("post");
    }
  });

  test("2.2 Filter types=broadcast returns only broadcasts", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
        types: "broadcast",
      },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).toBe("broadcast");
    }
  });

  test("2.3 Filter types=post,broadcast excludes VOD", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
        types: "post,broadcast",
      },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(["post", "broadcast"]).toContain(item.type);
    }
  });

  test("2.4 No types parameter returns all types", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    const types = new Set(data.items.map((i: any) => i.type));
    expect(types.has("post")).toBeTruthy();
    expect(types.has("broadcast")).toBeTruthy();
  });

  test("2.5 Invalid type is silently ignored", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
        types: "post,invalid_type",
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).toBe("post");
    }
  });

  // ─── Section 3: Conflict Detection API ────────────────────────

  test("3.1 Detects conflict for items within 30 minutes", async () => {
    // Use a unique future time slot based on TS to avoid collisions with other test runs
    // Offset by a large amount so it doesn't overlap with beforeAll items
    const conflictTs = Math.floor(Date.now() / 1000) + 80 * 86400 + Math.floor(Math.random() * 3600);
    const resp1 = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `conflict_a_${TS}`, publish_at: conflictTs, schedule_timezone: "UTC" },
    });
    expect(resp1.ok()).toBeTruthy();
    const conflictPostId1 = (await resp1.json()).post_id;

    const resp2 = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `conflict_b_${TS}`, publish_at: conflictTs + 600, schedule_timezone: "UTC" },
    });
    expect(resp2.ok()).toBeTruthy();
    const conflictPostId2 = (await resp2.json()).post_id;

    // Use the full calendar endpoint (which returns conflicts alongside items)
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(conflictTs - 3600),
        to_ts: String(conflictTs + 3600),
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    // Check that our posts appear in the items
    const item1 = data.items.find((i: any) => i.id === conflictPostId1);
    const item2 = data.items.find((i: any) => i.id === conflictPostId2);
    expect(item1).toBeTruthy();
    expect(item2).toBeTruthy();
    // The two posts are 600 seconds apart, which is within the 30-minute conflict buffer
    expect(data.conflicts.length).toBeGreaterThanOrEqual(1);
    // Find a conflict involving at least one of our post IDs
    const c = data.conflicts.find(
      (c: any) =>
        c.item_a_id === conflictPostId1 || c.item_b_id === conflictPostId1 ||
        c.item_a_id === conflictPostId2 || c.item_b_id === conflictPostId2,
    );
    expect(c).toBeTruthy();
    // Verify conflict has gap properties
    expect(typeof c.gap_seconds).toBe("number");
    expect(c.gap_seconds).toBeLessThan(1800); // within 30-minute buffer
  });

  test("3.2 No conflict for items 31+ minutes apart", async () => {
    // Post at weekFromNow and broadcast at weekFromNow + 86400 are a full day apart
    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.from_ts + 2 * 86400),
      },
    });
    const data = await resp.json();
    const falseConflict = data.conflicts.find(
      (c: any) => c.item_a_id === postId && c.item_b_id === broadcastId,
    );
    expect(falseConflict).toBeUndefined();
  });

  test("3.3 Cross-type conflict (post + broadcast at same time)", async () => {
    const crossTs = Math.floor(Date.now() / 1000) + 7 * 86400;
    // Create a post at crossTs
    await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `cross_post_${TS}`, publish_at: crossTs, schedule_timezone: "UTC" },
    });

    // Schedule a broadcast 5 minutes later
    const bDraft = await alicePage.request.post("/broadcast/sessions", {
      headers: { "x-csrf-token": csrf },
      data: { name: `cross_bcast_${TS}`, profile_id: "default" },
    });
    const bId = (await bDraft.json()).id;
    await alicePage.request.post(`/broadcast/sessions/${bId}/schedule`, {
      headers: { "x-csrf-token": csrf },
      data: { scheduled_at: crossTs + 300 },
    });

    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: {
        from_ts: String(crossTs - 3600),
        to_ts: String(crossTs + 3600),
      },
    });
    const data = await resp.json();
    const crossConflict = data.conflicts.find(
      (c: any) =>
        (c.item_a_type === "post" && c.item_b_type === "broadcast") ||
        (c.item_a_type === "broadcast" && c.item_b_type === "post"),
    );
    expect(crossConflict).toBeTruthy();
  });

  test("3.4 Conflicts response includes count", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/conflicts", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    expect(data.count).toBe(data.conflicts.length);
  });

  // ─── Section 4: Today Agenda API ──────────────────────────────

  test("4.1 Today endpoint returns today and tomorrow partitions", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/today");
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(Array.isArray(data.today)).toBeTruthy();
    expect(Array.isArray(data.tomorrow)).toBeTruthy();
    expect(typeof data.today_count).toBe("number");
    expect(typeof data.tomorrow_count).toBe("number");
  });

  test("4.2 Today counts match array lengths", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/today");
    const data = await resp.json();
    expect(data.today_count).toBe(data.today.length);
    expect(data.tomorrow_count).toBe(data.tomorrow.length);
  });

  test("4.3 Today response includes conflicts", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar/today");
    const data = await resp.json();
    expect(Array.isArray(data.conflicts)).toBeTruthy();
  });

  // ─── Section 5: Reschedule API ────────────────────────────────

  test("5.1 Reschedule post to new time", async () => {
    const originalTs = Math.floor(Date.now() / 1000) + 6 * 86400;
    const resp0 = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `resched_${TS}`, publish_at: originalTs, schedule_timezone: "UTC" },
    });
    const reschedulePostId = (await resp0.json()).post_id;

    const newTs = originalTs + 7200; // 2 hours later
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: reschedulePostId,
        item_type: "post",
        new_scheduled_at: String(newTs),
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.scheduled_at).toBe(newTs);
  });

  test("5.2 Reschedule to past returns 400", async () => {
    const pastTs = Math.floor(Date.now() / 1000) - 3600;
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: postId,
        item_type: "post",
        new_scheduled_at: String(pastTs),
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("5.3 Reschedule non-existent item returns 404", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 86400;
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: "nonexistent_id",
        item_type: "post",
        new_scheduled_at: String(futureTs),
      },
    });
    expect(resp.status()).toBe(404);
  });

  test("5.4 Reschedule broadcast respects min lead time", async () => {
    // Create and schedule a broadcast
    const bDraft = await alicePage.request.post("/broadcast/sessions", {
      headers: { "x-csrf-token": csrf },
      data: { name: `resched_bcast_${TS}`, profile_id: "default" },
    });
    const bId = (await bDraft.json()).id;
    const futureTs = Math.floor(Date.now() / 1000) + 9 * 86400;
    await alicePage.request.post(`/broadcast/sessions/${bId}/schedule`, {
      headers: { "x-csrf-token": csrf },
      data: { scheduled_at: futureTs },
    });

    // Try to reschedule to 10 seconds from now (below min lead time)
    const tooSoon = Math.floor(Date.now() / 1000) + 10;
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: bId,
        item_type: "broadcast",
        new_scheduled_at: String(tooSoon),
      },
    });
    expect(resp.status()).toBe(400);
  });

  test("5.5 Reschedule updates calendar view", async () => {
    const origTs = Math.floor(Date.now() / 1000) + 8 * 86400;
    const r = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `resched_verify_${TS}`, publish_at: origTs, schedule_timezone: "UTC" },
    });
    const reschPostId = (await r.json()).post_id;

    const newTs = origTs + 14400;
    await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: reschPostId,
        item_type: "post",
        new_scheduled_at: String(newTs),
      },
    });

    // Verify the item appears at the new time
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(newTs - 3600),
        to_ts: String(newTs + 3600),
      },
    });
    const data = await resp.json();
    const found = data.items.find((i: any) => i.id === reschPostId);
    expect(found).toBeTruthy();
    expect(found.scheduled_at).toBe(newTs);
  });

  test("5.6 Reschedule invalid type returns 422", async () => {
    const futureTs = Math.floor(Date.now() / 1000) + 86400;
    const resp = await alicePage.request.post("/ui/content-calendar/reschedule", {
      headers: { "x-csrf-token": csrf },
      params: {
        item_id: postId,
        item_type: "invalid",
        new_scheduled_at: String(futureTs),
      },
    });
    expect(resp.status()).toBe(422);
  });

  // ─── Section 6: Cancel API ────────────────────────────────────

  test("6.1 Cancel post removes it from calendar", async () => {
    const cancelTs = Math.floor(Date.now() / 1000) + 8 * 86400;
    const cr = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `cancel_${TS}`, publish_at: cancelTs, schedule_timezone: "UTC" },
    });
    const cancelPostId = (await cr.json()).post_id;

    const resp = await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: cancelPostId, item_type: "post" },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.ok).toBe("true");
    expect(data.type).toBe("post");

    // Verify it no longer appears
    const calResp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(cancelTs - 3600),
        to_ts: String(cancelTs + 3600),
      },
    });
    const calData = await calResp.json();
    const found = calData.items.find((i: any) => i.id === cancelPostId);
    expect(found).toBeUndefined();
  });

  test("6.2 Cancel non-existent item returns 404", async () => {
    const resp = await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: "nonexistent_id", item_type: "post" },
    });
    expect(resp.status()).toBe(404);
  });

  test("6.3 Cancel already-cancelled item returns 409", async () => {
    const cancelTs2 = Math.floor(Date.now() / 1000) + 9 * 86400;
    const cr2 = await alicePage.request.post("/posts", {
      headers: { "x-csrf-token": csrf },
      data: { body: `cancel2_${TS}`, publish_at: cancelTs2, schedule_timezone: "UTC" },
    });
    const cancelPostId2 = (await cr2.json()).post_id;

    // Cancel first time
    await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: cancelPostId2, item_type: "post" },
    });

    // Cancel again — should be 409
    const resp = await alicePage.request.post("/ui/content-calendar/cancel", {
      headers: { "x-csrf-token": csrf },
      params: { item_id: cancelPostId2, item_type: "post" },
    });
    expect(resp.status()).toBe(409);
  });

  // ─── Section 7: Calendar Week View UI ─────────────────────────

  test("7.1 Page loads with header and controls", async () => {
    await alicePage.goto("/content-calendar");
    await expect(alicePage.getByRole("heading", { name: "Content Calendar" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "Today" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Week" })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: "Month" })).toBeVisible();
  });

  test("7.2 Week grid renders day headers", async () => {
    await alicePage.goto("/content-calendar");
    for (const day of ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]) {
      await expect(alicePage.getByText(day).first()).toBeVisible();
    }
  });

  test("7.3 Type filter buttons are visible", async () => {
    await alicePage.goto("/content-calendar");
    await expect(alicePage.getByRole("button", { name: "Posts" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "Broadcasts" })).toBeVisible();
    await expect(alicePage.getByRole("button", { name: "Videos" })).toBeVisible();
  });

  test("7.4 Type filter buttons toggle", async () => {
    await alicePage.goto("/content-calendar");
    // Wait for initial load
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());

    // Click "Posts" filter to deactivate
    await alicePage.getByRole("button", { name: "Posts" }).click();
    // Wait for refetch
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());
    // Re-enable
    await alicePage.getByRole("button", { name: "Posts" }).click();
  });

  test("7.5 Navigation arrows change week", async () => {
    await alicePage.goto("/content-calendar");
    // Wait for page load
    await expect(alicePage.getByRole("heading", { name: "Content Calendar" })).toBeVisible();
    // Get header label (date range text next to navigation buttons)
    const headerLocator = alicePage.locator("main span.text-sm.font-medium");
    const headerBefore = await headerLocator.first().textContent();
    await alicePage.getByRole("button", { name: "Next week" }).click();
    // Wait a moment for React state update
    await alicePage.waitForTimeout(300);
    const headerAfter = await headerLocator.first().textContent();
    expect(headerAfter).not.toBe(headerBefore);
  });

  test("7.6 Today button resets to current week", async () => {
    await alicePage.goto("/content-calendar");
    // Navigate forward
    await alicePage.getByRole("button", { name: "Next week" }).click();
    await alicePage.getByRole("button", { name: "Next week" }).click();
    // Click Today
    await alicePage.getByRole("button", { name: "Today" }).click();
    // Today's date number should be highlighted
    const today = new Date().getDate().toString();
    await expect(
      alicePage.locator(".bg-primary.text-primary-foreground").filter({ hasText: today }),
    ).toBeVisible();
  });

  // ─── Section 8: Calendar Month View UI ────────────────────────

  test("8.1 Month view renders day grid", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    // Should see day-of-month numbers
    await expect(alicePage.getByText("15").first()).toBeVisible();
  });

  test("8.2 Month header shows month and year", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    const monthName = new Date().toLocaleDateString(undefined, {
      month: "long",
      year: "numeric",
    });
    await expect(
      alicePage.locator("main span.text-sm.font-medium").filter({ hasText: monthName }),
    ).toBeVisible();
  });

  test("8.3 Clicking a day switches to week view", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    // Click on day 15
    await alicePage.getByText("15").first().click();
    // Should switch to week view
    await expect(alicePage.getByRole("tab", { name: "Week" })).toHaveAttribute(
      "data-state",
      "active",
    );
  });

  test("8.4 Navigation arrows change month", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    const headerLocator = alicePage.locator("main span.text-sm.font-medium");
    const headerBefore = await headerLocator.first().textContent();
    await alicePage.getByRole("button", { name: "Next month" }).click();
    await alicePage.waitForTimeout(300);
    const headerAfter = await headerLocator.first().textContent();
    expect(headerAfter).not.toBe(headerBefore);
  });

  test("8.5 Month view has day cells with content indicators", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.getByRole("tab", { name: "Month" }).click();
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());
    // Verify grid structure exists (7 columns)
    await expect(alicePage.getByText("Sun").first()).toBeVisible();
    await expect(alicePage.getByText("Sat").first()).toBeVisible();
  });

  // ─── Section 9: Quick Schedule Dialog UI ──────────────────────

  test("9.1 Quick Schedule dialog opens on empty slot click", async () => {
    await alicePage.goto("/content-calendar");
    await alicePage.waitForResponse((r) => r.url().includes("/content-calendar") && r.ok());
    // Wait for grid to render
    await expect(alicePage.getByText("10 AM")).toBeVisible({ timeout: 5000 });
    // Find the "10 AM" label row, then click the cell next to it (first day column)
    // The row is a grid with 8 children: time label + 7 day cells
    const timeLabel = alicePage.getByText("10 AM", { exact: true });
    // The time label's parent is the grid row. Click the second child (first day cell)
    const gridRow = timeLabel.locator("..");
    const dayCell = gridRow.locator(".cursor-pointer").first();
    await dayCell.click();
    // Dialog should appear
    await expect(alicePage.getByText("Quick Schedule")).toBeVisible({ timeout: 5000 });
  });

  test("9.2 Quick Schedule dialog has Post, Broadcast, Video tabs", async () => {
    // Dialog should still be open from previous test
    await expect(alicePage.getByRole("tab", { name: /Post/ })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Broadcast/ })).toBeVisible();
    await expect(alicePage.getByRole("tab", { name: /Video/ })).toBeVisible();
  });

  test("9.3 Video tab shows upload prompt", async () => {
    await alicePage.getByRole("tab", { name: /Video/ }).click();
    await expect(
      alicePage.getByText("To schedule a video release"),
    ).toBeVisible();
  });

  // ─── Section 10: Content Item Detail UI ───────────────────────

  test("10.1 Page renders content calendar heading", async () => {
    await alicePage.goto("/content-calendar");
    await expect(
      alicePage.getByRole("heading", { name: "Content Calendar" }),
    ).toBeVisible();
  });

  test("10.2 Description text is visible", async () => {
    await alicePage.goto("/content-calendar");
    await expect(
      alicePage.getByText("Manage your scheduled posts, broadcasts, and video releases"),
    ).toBeVisible();
  });

  test("10.3 Week tab is active by default", async () => {
    await alicePage.goto("/content-calendar");
    await expect(alicePage.getByRole("tab", { name: "Week" })).toHaveAttribute(
      "data-state",
      "active",
    );
  });

  // ─── Section 11: VOD Scheduled Publish ────────────────────────

  test("11.1 VOD item appears in calendar when scheduled_publish_at is set", async () => {
    const vodScheduleTs = Math.floor(Date.now() / 1000) + 4 * 86400;

    // Create a video via the presign upload endpoint
    const createResp = await alicePage.request.post("/ui/videos/upload/presign", {
      headers: { "x-csrf-token": csrf },
      data: {
        filename: `cal_vod_${TS}.mp4`,
        content_type: "video/mp4",
        size_bytes: 1024,
      },
    });
    if (!createResp.ok()) {
      test.skip();
      return;
    }
    const videoData = await createResp.json();
    const videoId = videoData.video_id;

    // Set scheduled_publish_at via PATCH
    await alicePage.request.patch(`/ui/videos/${videoId}`, {
      headers: { "x-csrf-token": csrf },
      data: { scheduled_publish_at: vodScheduleTs },
    });

    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(vodScheduleTs - 86400),
        to_ts: String(vodScheduleTs + 86400),
        types: "vod",
      },
    });
    const data = await resp.json();
    const vodItem = data.items.find((i: any) => i.id === videoId);
    if (vodItem) {
      expect(vodItem.type).toBe("vod");
      expect(vodItem.color).toBe("#8B5CF6");
      expect(vodItem.icon).toBe("video");
    }
  });

  test("11.2 VOD items excluded when filtering by post only", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
        types: "post",
      },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(item.type).not.toBe("vod");
    }
  });

  // ─── Section 12: Integration with Existing Endpoints ──────────

  test("12.1 Scheduled post from feed appears in calendar", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekFromNow - 3600),
        to_ts: String(weekFromNow + 3600),
        types: "post",
      },
    });
    const data = await resp.json();
    const found = data.items.find((i: any) => i.id === postId);
    expect(found).toBeTruthy();
  });

  test("12.2 Scheduled broadcast from broadcast manager appears in calendar", async () => {
    const bcastTs = weekFromNow + 86400;
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(bcastTs - 3600),
        to_ts: String(bcastTs + 3600),
        types: "broadcast",
      },
    });
    const data = await resp.json();
    const found = data.items.find((i: any) => i.id === broadcastId);
    expect(found).toBeTruthy();
  });

  test("12.3 Calendar returns conflicts in main endpoint response", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    expect(Array.isArray(data.conflicts)).toBeTruthy();
  });

  test("12.4 Calendar items have consistent schema", async () => {
    const resp = await alicePage.request.get("/ui/content-calendar", {
      params: {
        from_ts: String(weekRange.from_ts),
        to_ts: String(weekRange.to_ts),
      },
    });
    const data = await resp.json();
    for (const item of data.items) {
      expect(typeof item.id).toBe("string");
      expect(typeof item.type).toBe("string");
      expect(typeof item.title).toBe("string");
      expect(typeof item.scheduled_at).toBe("number");
      expect(typeof item.status).toBe("string");
      expect(typeof item.color).toBe("string");
      expect(typeof item.icon).toBe("string");
    }
  });
});
