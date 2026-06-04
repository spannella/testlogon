import { test, expect, type Page } from "@playwright/test";
import { injectAuth } from "./helpers";

// FEED-006 — Hide Post (unhide + list-hidden).
//
// The hide endpoint (POST /feed/hide) and the feed-exclusion filter already
// exist. This spec exercises the two NEW endpoints — POST /feed/unhide and
// GET /feed/hidden — alongside the existing hide flow.
//
// Auth: cookie sessions via injectAuth(); the ui_csrf cookie value is sent as
// the x-csrf-token header on non-GET requests (page.request carries cookies, so
// the backend uses session auth and enforces CSRF).

const { describe, beforeAll } = test;

async function csrf(page: Page): Promise<string> {
  const cookies = await page.context().cookies();
  const c = cookies.find((x) => x.name === "ui_csrf");
  return c?.value ?? "";
}

async function createPost(page: Page, body: string): Promise<string> {
  const res = await page.request.post("/posts", {
    headers: { "x-csrf-token": await csrf(page) },
    data: { body },
  });
  expect(res.ok(), `createPost failed: ${res.status()}`).toBeTruthy();
  const json = await res.json();
  return (json.post_id ?? json.id) as string;
}

async function feedPostIds(page: Page): Promise<string[]> {
  const res = await page.request.get("/feed?limit=50");
  expect(res.ok()).toBeTruthy();
  const json = await res.json();
  return (json.items ?? []).map((p: { post_id: string }) => p.post_id);
}

async function hiddenPostIds(page: Page): Promise<string[]> {
  const res = await page.request.get("/feed/hidden?limit=100");
  expect(res.ok()).toBeTruthy();
  const json = await res.json();
  return (json.items ?? []).map((p: { post_id: string }) => p.post_id);
}

async function hide(page: Page, postId: string) {
  return page.request.post("/feed/hide", {
    headers: { "x-csrf-token": await csrf(page) },
    data: { post_id: postId },
  });
}

async function unhide(page: Page, postId: string) {
  return page.request.post("/feed/unhide", {
    headers: { "x-csrf-token": await csrf(page) },
    data: { post_id: postId },
  });
}

describe("Section: Post Hide / Unhide (FEED-006)", () => {
  const TS = Date.now();
  let alicePage: Page;
  let bobPage: Page;
  let bobPost = "";
  let alicePost = "";

  beforeAll(async ({ browser }) => {
    const aliceCtx = await browser.newContext();
    alicePage = await aliceCtx.newPage();
    await injectAuth(alicePage, "alice");

    const bobCtx = await browser.newContext();
    bobPage = await bobCtx.newPage();
    await injectAuth(bobPage, "bob");

    bobPost = await createPost(bobPage, `bob-hide-${TS}`);
    alicePost = await createPost(alicePage, `alice-hide-${TS}`);
  });

  test("hide excludes the post from the viewer's feed", async () => {
    expect(await feedPostIds(bobPage)).toContain(bobPost);

    const res = await hide(bobPage, bobPost);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.post_id).toBe(bobPost);

    expect(await feedPostIds(bobPage)).not.toContain(bobPost);
  });

  test("list-hidden returns posts hidden by the viewer", async () => {
    const r = await hide(bobPage, alicePost);
    expect(r.ok()).toBeTruthy();

    const ids = await hiddenPostIds(bobPage);
    expect(ids).toContain(bobPost);
    expect(ids).toContain(alicePost);
  });

  test("hide is per-viewer: alice's feed and hidden list are unaffected", async () => {
    expect(await feedPostIds(alicePage)).toContain(alicePost);
    expect(await hiddenPostIds(alicePage)).not.toContain(alicePost);
  });

  test("unhide restores the post and removes it from list-hidden", async () => {
    const res = await unhide(bobPage, bobPost);
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.post_id).toBe(bobPost);
    expect(body.hidden).toBe(false);

    expect(await feedPostIds(bobPage)).toContain(bobPost);
    expect(await hiddenPostIds(bobPage)).not.toContain(bobPost);
  });

  test("unhide is idempotent (no-op success on a non-hidden post)", async () => {
    const res = await unhide(bobPage, bobPost);
    expect(res.ok()).toBeTruthy();
    expect((await res.json()).hidden).toBe(false);

    const neverHidden = `p_never_${TS}`;
    const res2 = await unhide(bobPage, neverHidden);
    expect(res2.ok()).toBeTruthy();
    const body2 = await res2.json();
    expect(body2.post_id).toBe(neverHidden);
    expect(body2.hidden).toBe(false);
  });
});
