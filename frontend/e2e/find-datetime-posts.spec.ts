/**
 * FEED-003: Find-a-DateTime Newsfeed Posts E2E tests.
 *
 * Section 717: FADT Post Creation API
 * Section 718: FADT Post Availability & Results API
 * Section 719: FADT Post Validation Edge Cases
 * Section 720: FADT Availability Update & Deadline
 * Section 721: FADT Post Rendering (UI)
 * Section 722: FADT Post Interactions API
 *
 * Reuses the MSG-009 overlap-computation service (messaging_find_datetime) and
 * the shared AvailabilityGrid component — no logic is duplicated.
 *
 * Repo gotcha: GET /feed queries GSI1PK = FEED#{viewer_user_id} and only
 * returns the viewer's OWN posts (no fan-out). To assert a created post is
 * present we fetch the AUTHOR's own feed, or GET /posts/{post_id}.
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:3000";
const API = "http://localhost:8000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";

const TS = Date.now();
// Date range comfortably in the future (current env date is 2026).
const D1 = "2027-06-05";
const D2 = "2027-06-07";

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 " + REPO_ROOT + "/e2e_session_setup.py",
      { cwd: REPO_ROOT, timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, userId: string) {
  const session = getSessions()[userId];
  if (!session) throw new Error(`No session for ${userId}`);
  await page.context().addCookies(session.cookies);
  await page.goto(BASE + "/login", { waitUntil: "domcontentloaded" });
  await page.evaluate((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, userId);
}

/** POST helper that includes session cookies and CSRF header. */
async function feedPost(page: Page, path: string, body: object, userId = ALICE_ID) {
  const session = getSessions()[userId];
  return page.request.post(`${API}${path}`, {
    headers: { "x-csrf-token": session.csrf_token },
    data: body,
  });
}

async function feedGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

function validPostBody(extra: Record<string, unknown> = {}) {
  return {
    title: `Meetup ${TS}`,
    from_date: D1,
    to_date: D2,
    start_hour: 9,
    end_hour: 17,
    slot_duration_minutes: 60,
    deadline_hours: 72,
    body: `When are you free ${TS}`,
    ...extra,
  };
}

// ─── Section 717: FADT Post Creation API ──────────────────────────────────────

test.describe("717 — FADT Post Creation API", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("717.1 — create FADT post with valid params", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody());
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.post_kind).toBe("find_datetime");
    expect(typeof data.find_datetime_id).toBe("string");
    expect(data.find_datetime_id).toMatch(/^fadt_/);
    expect(typeof data.post_id).toBe("string");
    expect(data.from_date).toBe(D1);
    expect(data.to_date).toBe(D2);
    expect(data.status).toBe("open");
  });

  test("717.2 — FADT post appears in creator's feed", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `FeedShow ${TS}` }));
    const created = await create.json();
    const resp = await feedGet(alicePage, "/feed?limit=50");
    expect(resp.ok()).toBeTruthy();
    const feed = await resp.json();
    const items: Array<Record<string, unknown>> = feed.items ?? [];
    const found = items.find((p) => p.find_datetime_id === created.find_datetime_id);
    expect(found).toBeTruthy();
    expect(found!.post_kind).toBe("find_datetime");
  });

  test("717.3 — FADT poll data retrievable via poll endpoint", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `PollGet ${TS}` }));
    const created = await create.json();
    const resp = await feedGet(alicePage, `/posts/find-datetime/${created.find_datetime_id}`);
    expect(resp.ok()).toBeTruthy();
    const poll = await resp.json();
    expect(poll.title).toBe(`PollGet ${TS}`);
    expect(poll.from_date).toBe(D1);
    expect(poll.to_date).toBe(D2);
    expect(poll.status).toBe("open");
    expect(poll.creator_sub).toBe(ALICE_ID);
  });

  test("717.4 — reject FADT post with from_date >= to_date (400)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ from_date: D2, to_date: D1 }));
    expect(resp.status()).toBe(400);
  });

  test("717.5 — unauthenticated create rejected", async ({ browser }) => {
    const ctx = await browser.newContext();
    const anonPage = await ctx.newPage();
    const resp = await anonPage.request.post(`${API}/posts/find-datetime`, {
      data: validPostBody({ title: `Anon ${TS}` }),
    });
    expect(resp.status()).toBeGreaterThanOrEqual(401);
    expect(resp.status()).toBeLessThan(500);
    await ctx.close();
  });
});

// ─── Section 718: FADT Post Availability & Results API ─────────────────────────

test.describe("718 — FADT Post Availability & Results API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let pollId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Results ${TS}` }));
    pollId = (await create.json()).find_datetime_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("718.1 — Bob submits availability", async () => {
    const resp = await feedPost(
      bobPage,
      `/posts/find-datetime/${pollId}/availability`,
      { slots: [`${D1}T09:00`, `${D1}T10:00`, `${D1}T14:00`] },
      BOB_ID,
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.your_slot_count).toBe(3);
  });

  test("718.2 — Alice submits availability; participant_count = 2", async () => {
    const resp = await feedPost(
      alicePage,
      `/posts/find-datetime/${pollId}/availability`,
      { slots: [`${D1}T09:00`, `${D1}T10:00`, `${D1}T11:00`] },
    );
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.participant_count).toBe(2);
  });

  test("718.3 — Alice closes the poll; best_windows present", async () => {
    const resp = await feedPost(alicePage, `/posts/find-datetime/${pollId}/close`, {});
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.status).toBe("closed");
    expect(Array.isArray(data.best_windows)).toBe(true);
    expect(data.best_windows.length).toBeGreaterThan(0);
  });

  test("718.4 — best window reflects overlapping slots", async () => {
    const resp = await feedGet(alicePage, `/posts/find-datetime/${pollId}`);
    const poll = await resp.json();
    expect(poll.status).toBe("closed");
    const top = poll.best_windows[0];
    // Both Alice and Bob marked 09:00 and 10:00 → overlap count 2.
    expect(top.count).toBeGreaterThanOrEqual(2);
    expect(top.start).toBe(`${D1}T09:00`);
  });

  test("718.5 — Bob cannot close Alice's poll (403)", async ({ browser }) => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `BobClose ${TS}` }));
    const pid = (await create.json()).find_datetime_id;
    const resp = await feedPost(bobPage, `/posts/find-datetime/${pid}/close`, {}, BOB_ID);
    expect(resp.status()).toBe(403);
  });
});

// ─── Section 719: FADT Post Validation Edge Cases ──────────────────────────────

test.describe("719 — FADT Post Validation Edge Cases", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("719.1 — reject date range exceeding 14 days (400)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({
      from_date: "2027-06-01",
      to_date: "2027-06-30",
    }));
    expect(resp.status()).toBe(400);
  });

  test("719.2 — reject start_hour >= end_hour (422)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ start_hour: 18, end_hour: 9 }));
    expect(resp.status()).toBe(422);
  });

  test("719.3 — reject empty title (422)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: "" }));
    expect(resp.status()).toBe(422);
  });

  test("719.4 — reject deadline_hours > 336 (422)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ deadline_hours: 500 }));
    expect(resp.status()).toBe(422);
  });

  test("719.5 — reject invalid slot_duration_minutes (422)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ slot_duration_minutes: 45 }));
    expect(resp.status()).toBe(422);
  });

  test("719.6 — accept slot_duration_minutes 30 (201)", async () => {
    const resp = await feedPost(alicePage, "/posts/find-datetime", validPostBody({
      title: `Dur30 ${TS}`,
      slot_duration_minutes: 30,
    }));
    expect(resp.status()).toBe(201);
  });
});

// ─── Section 720: FADT Availability Update & Deadline ──────────────────────────

test.describe("720 — FADT Availability Update & Deadline", () => {
  let alicePage: Page;
  let bobPage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("720.1 — update availability overwrites previous selection", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Update ${TS}` }));
    const pid = (await create.json()).find_datetime_id;
    await feedPost(bobPage, `/posts/find-datetime/${pid}/availability`, { slots: [`${D1}T09:00`, `${D1}T10:00`] }, BOB_ID);
    const re = await feedPost(
      bobPage,
      `/posts/find-datetime/${pid}/availability`,
      { slots: [`${D1}T09:00`, `${D1}T10:00`, `${D1}T11:00`, `${D1}T12:00`, `${D1}T13:00`] },
      BOB_ID,
    );
    expect((await re.json()).your_slot_count).toBe(5);
    const poll = await (await feedGet(alicePage, `/posts/find-datetime/${pid}`)).json();
    // Still a single participant (overwrite, not append).
    expect(poll.participant_count).toBe(1);
    const bobAvail = poll.availabilities.find((a: { user_sub: string }) => a.user_sub === BOB_ID);
    expect(bobAvail.slots.length).toBe(5);
  });

  test("720.2 — availability rejected on closed poll (400)", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Closed ${TS}` }));
    const pid = (await create.json()).find_datetime_id;
    await feedPost(alicePage, `/posts/find-datetime/${pid}/close`, {});
    const resp = await feedPost(bobPage, `/posts/find-datetime/${pid}/availability`, { slots: [`${D1}T09:00`] }, BOB_ID);
    expect(resp.status()).toBe(400);
  });

  test("720.3 — empty slots array rejected (422)", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Empty ${TS}` }));
    const pid = (await create.json()).find_datetime_id;
    const resp = await feedPost(bobPage, `/posts/find-datetime/${pid}/availability`, { slots: [] }, BOB_ID);
    expect(resp.status()).toBe(422);
  });

  test("720.4 — slot outside date range rejected (400)", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `OutRange ${TS}` }));
    const pid = (await create.json()).find_datetime_id;
    const resp = await feedPost(
      bobPage,
      `/posts/find-datetime/${pid}/availability`,
      { slots: ["2099-01-01T09:00"] },
      BOB_ID,
    );
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 721: FADT Post Rendering (UI) ─────────────────────────────────────

test.describe("721 — FADT Post Rendering (UI)", () => {
  let alicePage: Page;

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
  });

  test.afterAll(async () => {
    await alicePage.close();
  });

  test("721.1 — Find a Time composer toggle is available", async () => {
    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const toggle = alicePage.getByTestId("find-time-toggle-btn");
    await expect(toggle).toBeVisible({ timeout: 15_000 });
    await toggle.click();
    await expect(alicePage.getByTestId("find-time-composer")).toBeVisible();
    await expect(alicePage.getByTestId("find-time-title-input")).toBeVisible();
  });

  test("721.2 — FADT post card renders grid + submit button", async () => {
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Render ${TS}` }));
    const created = await create.json();
    await alicePage.goto(`${BASE}/feed`, { waitUntil: "domcontentloaded" });
    const card = alicePage.getByTestId("fadt-post-card").first();
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(alicePage.getByTestId("fadt-post-submit-btn").first()).toBeVisible();
    // Confirm the post can be fetched and exposes find-datetime fields.
    const detail = await (await feedGet(alicePage, `/posts/${created.post_id}`)).json();
    expect(detail.find_datetime_id).toBe(created.find_datetime_id);
    expect(detail.find_datetime_title).toBe(`Render ${TS}`);
  });

  test("721.3 — closed FADT post exposes best_windows + participant count", async ({ browser }) => {
    const bobPage = await browser.newPage();
    await injectAuth(bobPage, BOB_ID);
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Closed UI ${TS}` }));
    const pid = (await create.json()).find_datetime_id;
    await feedPost(bobPage, `/posts/find-datetime/${pid}/availability`, { slots: [`${D1}T09:00`, `${D1}T10:00`] }, BOB_ID);
    await feedPost(alicePage, `/posts/find-datetime/${pid}/availability`, { slots: [`${D1}T09:00`, `${D1}T10:00`] });
    await feedPost(alicePage, `/posts/find-datetime/${pid}/close`, {});
    const poll = await (await feedGet(alicePage, `/posts/find-datetime/${pid}`)).json();
    expect(poll.status).toBe("closed");
    expect(poll.participant_count).toBe(2);
    expect(poll.best_windows.length).toBeGreaterThan(0);
    await bobPage.close();
  });
});

// ─── Section 722: FADT Post Interactions API ───────────────────────────────────

test.describe("722 — FADT Post Interactions API", () => {
  let alicePage: Page;
  let bobPage: Page;
  let postId = "";

  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    bobPage = await browser.newPage();
    await injectAuth(alicePage, ALICE_ID);
    await injectAuth(bobPage, BOB_ID);
    const create = await feedPost(alicePage, "/posts/find-datetime", validPostBody({ title: `Interact ${TS}` }));
    postId = (await create.json()).post_id;
  });

  test.afterAll(async () => {
    await alicePage.close();
    await bobPage.close();
  });

  test("722.1 — like FADT post", async () => {
    const resp = await feedPost(bobPage, `/posts/${postId}/like`, {}, BOB_ID);
    expect(resp.ok()).toBeTruthy();
    const detail = await (await feedGet(alicePage, `/posts/${postId}`)).json();
    expect(detail.like_count).toBeGreaterThanOrEqual(1);
  });

  test("722.2 — comment on FADT post", async () => {
    const resp = await feedPost(bobPage, `/posts/${postId}/comments`, { body: `Nice ${TS}` }, BOB_ID);
    expect(resp.status()).toBeGreaterThanOrEqual(200);
    expect(resp.status()).toBeLessThan(300);
  });

  test("722.3 — react to FADT post", async () => {
    const resp = await feedPost(bobPage, `/posts/${postId}/reactions`, { emoji: "fire" }, BOB_ID);
    expect(resp.ok()).toBeTruthy();
  });
});
