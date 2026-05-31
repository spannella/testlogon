// BCAST-010 — Broadcast Newsfeed Promotion E2E.
//
// Covers: promote (idempotent) -> newsfeed post linked, get status (404 when
// not promoted), sync on broadcast end, unpromote, live discovery, and
// ownership (non-owner gets 403).
import { test, expect, request as playwrightRequest } from "@playwright/test";
import type { APIRequestContext } from "@playwright/test";

const BASE = process.env.E2E_BASE_URL || "http://localhost:8000";

// Identities. In the full stack these map to seeded sessions; here we drive the
// API with the session header + csrf header per the documented convention.
const ALICE = "e2e_alice@test.local"; // broadcaster / owner
const BOB = "e2e_bob@test.local"; // feed viewer / non-owner

function authHeaders(identity: string, csrf = true): Record<string, string> {
  const h: Record<string, string> = { "X-User-Id": identity };
  // Non-GET cookie requests require a CSRF token in the real stack.
  if (csrf) h["x-csrf-token"] = `csrf-${identity}`;
  return h;
}

async function createBroadcast(
  ctx: APIRequestContext,
  identity: string,
  title: string
): Promise<string> {
  const res = await ctx.post(`${BASE}/ui/broadcast/sessions`, {
    headers: authHeaders(identity),
    data: { title },
  });
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  return body.id as string;
}

async function goLive(ctx: APIRequestContext, identity: string, id: string) {
  const res = await ctx.post(`${BASE}/ui/broadcast/sessions/${id}/go-live`, {
    headers: authHeaders(identity),
    data: {},
  });
  expect(res.ok()).toBeTruthy();
}

async function endBroadcast(ctx: APIRequestContext, identity: string, id: string) {
  const res = await ctx.post(`${BASE}/ui/broadcast/sessions/${id}/end`, {
    headers: authHeaders(identity),
    data: {},
  });
  expect(res.ok()).toBeTruthy();
}

test.describe("BCAST-010 Broadcast Newsfeed Promotion", () => {
  let ctx: APIRequestContext;

  test.beforeAll(async () => {
    ctx = await playwrightRequest.newContext();
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("promote creates a linked newsfeed post (idempotent, no duplicate)", async () => {
    const bid = await createBroadcast(ctx, ALICE, "Promo Test 1");
    await goLive(ctx, ALICE, bid);

    const res1 = await ctx.post(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE),
    });
    expect(res1.ok()).toBeTruthy();
    const link1 = (await res1.json()).link;
    expect(link1.broadcast_id).toBe(bid);
    expect(link1.post_id).toBeTruthy();
    expect(link1.last_synced_status).toBe("live");
    expect(link1.removed).toBe(false);

    // Promote again -> same post id (idempotent update).
    const res2 = await ctx.post(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE),
    });
    expect(res2.ok()).toBeTruthy();
    const link2 = (await res2.json()).link;
    expect(link2.post_id).toBe(link1.post_id);
  });

  test("get promotion status returns the link, 404 when not promoted", async () => {
    const bid = await createBroadcast(ctx, ALICE, "Promo Test 2");

    const notYet = await ctx.get(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE, false),
    });
    expect(notYet.status()).toBe(404);

    await ctx.post(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE),
    });
    const now = await ctx.get(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE, false),
    });
    expect(now.ok()).toBeTruthy();
    expect((await now.json()).link.broadcast_id).toBe(bid);
  });

  test("ending a broadcast syncs the promoted post to ended (and sync endpoint)", async () => {
    const bid = await createBroadcast(ctx, ALICE, "Promo Test 3");
    await goLive(ctx, ALICE, bid);
    await ctx.post(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE),
    });

    await endBroadcast(ctx, ALICE, bid);

    // Auto-synced on end.
    const after = await ctx.get(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE, false),
    });
    expect((await after.json()).link.last_synced_status).toBe("ended");

    // Explicit sync endpoint is idempotent.
    const synced = await ctx.post(`${BASE}/ui/broadcast/promo/${bid}/sync`, {
      headers: authHeaders(ALICE),
    });
    expect(synced.ok()).toBeTruthy();
    expect((await synced.json()).link.last_synced_status).toBe("ended");
  });

  test("live discovery lists only currently-live promoted broadcasts", async () => {
    const liveBid = await createBroadcast(ctx, ALICE, "Promo Live A");
    await goLive(ctx, ALICE, liveBid);
    await ctx.post(`${BASE}/ui/broadcast/promo/${liveBid}`, {
      headers: authHeaders(ALICE),
    });

    const endedBid = await createBroadcast(ctx, ALICE, "Promo Live B");
    await goLive(ctx, ALICE, endedBid);
    await ctx.post(`${BASE}/ui/broadcast/promo/${endedBid}`, {
      headers: authHeaders(ALICE),
    });
    await endBroadcast(ctx, ALICE, endedBid);

    // Bob (a viewer) can discover live promoted broadcasts.
    const res = await ctx.get(`${BASE}/ui/broadcast/promo/live`, {
      headers: authHeaders(BOB, false),
    });
    expect(res.ok()).toBeTruthy();
    const items = (await res.json()).items as Array<{ broadcast_id: string }>;
    const ids = items.map((i) => i.broadcast_id);
    expect(ids).toContain(liveBid);
    expect(ids).not.toContain(endedBid);
  });

  test("unpromote removes the link and the promoted post", async () => {
    const bid = await createBroadcast(ctx, ALICE, "Promo Test 4");
    await goLive(ctx, ALICE, bid);
    await ctx.post(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE),
    });

    const del = await ctx.delete(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE),
    });
    expect(del.ok()).toBeTruthy();
    expect((await del.json()).ok).toBe(true);

    const after = await ctx.get(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(ALICE, false),
    });
    expect(after.status()).toBe(404);
  });

  test("ownership enforced: non-owner gets 403", async () => {
    const bid = await createBroadcast(ctx, ALICE, "Promo Test 5");
    await goLive(ctx, ALICE, bid);

    const res = await ctx.post(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(BOB),
    });
    expect(res.status()).toBe(403);

    const getRes = await ctx.get(`${BASE}/ui/broadcast/promo/${bid}`, {
      headers: authHeaders(BOB, false),
    });
    expect(getRes.status()).toBe(403);
  });
});
