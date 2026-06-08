/**
 * VIDEO SEGMENT 11 — Tickets & Helpdesk  (~60-95s)
 *
 * A guided tour of the platform's support tooling:
 *   - Support Tickets (/tickets): the TicketsPage — create a ticket, list, thread
 *   - Admin queue + ops: status summary cards + assign / mark-done controls (root)
 *   - Ticket Spaces (/tickets/spaces): private/shared grouping boards
 *   - Live Helpdesk chat (/helpdesk): "Your Support Chats" + the agent bridge
 *
 * Pattern mirrors seg10-calendar.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py + e2e_session_setup.py):
 *   - root  — on camera for /tickets (role=root → admin queue + assign/status ops)
 *   - bob   — customer; raises tickets + a helpdesk support chat
 *   - alice — owns a ticket space; is the seeded helpdesk agent
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - Two support tickets raised by Bob (one left open) via POST /tickets.
 *   - One ticket space ("Billing Disputes") owned by Alice via POST /ticket-spaces.
 *   - One helpdesk conversation raised by Bob + a message, so /helpdesk has a
 *     real "Your Support Chats" entry.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg11-tickets.demo.ts
 */
import { test, expect, type APIResponse } from "@playwright/test";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const ROOT = "root";
const BOB = "bob";
const ALICE = "alice";
const HELPDESK_GROUP_ID = "e2e-helpdesk";

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** CSRF-authenticated POST from the page's browser context as identity `key`. */
function poster(page: import("@playwright/test").Page, sess: SessionData) {
  return (path: string, body: unknown) =>
    page.request.post(`${API}${path}`, {
      headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
      data: body,
    });
}

test("Segment 11 — Tickets & Helpdesk", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const root: SessionData = sessions[ROOT];
  const bob: SessionData = sessions[BOB];
  const alice: SessionData = sessions[ALICE];
  const stamp = Date.now();

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  // Bob raises two support tickets (CSRF auth needs Bob's cookies on the request
  // context). We inject Bob first only to borrow his request context, then swap to
  // root for the on-camera tour.
  await injectAuth(page, BOB);
  const postBob = poster(page, bob);

  await jsonOk(
    (await postBob("/tickets", {
      subject: `Cannot reset my password ${stamp}`,
      description: "The reset email never arrives. Please help.",
    })) as APIResponse,
    "create ticket 1",
  );
  // This one becomes the "admin ops" subject — root will assign + resolve it
  // off-camera so the on-camera reveal shows a deterministic assigned+done state.
  const opsSubject = `Invoice charged twice ${stamp}`;
  const opsTicket = (await jsonOk(
    (await postBob("/tickets", {
      subject: opsSubject,
      description: "I was billed two times for March. Requesting a refund.",
    })) as APIResponse,
    "create ticket 2",
  )) as { ticket: { ticket_id: string } };
  const opsTicketId = opsTicket.ticket.ticket_id;

  // Bob raises a helpdesk live-chat conversation + a first message.
  const convo = (await jsonOk(
    (await postBob("/messaging/conversations", {
      routing_mode: "helpdesk_bridge",
      helpdesk_group_id: HELPDESK_GROUP_ID,
      type: "dm",
    })) as APIResponse,
    "create helpdesk convo",
  )) as { conversation_id: string };
  await postBob(`/messaging/conversations/${convo.conversation_id}/messages`, {
    text: "Hi — I need help with a duplicate charge on my account.",
  });

  // Alice owns a ticket space (re-use if one already exists so re-runs don't pile up).
  await injectAuth(page, ALICE);
  const postAlice = poster(page, alice);
  const existingSpaces = (await jsonOk(
    (await page.request.get(`${API}/ticket-spaces`)) as APIResponse,
    "list spaces",
  )) as { items?: Array<{ name: string }> };
  if (!(existingSpaces.items ?? []).some((s) => s.name === "Billing Disputes")) {
    await jsonOk(
      (await postAlice("/ticket-spaces", {
        name: "Billing Disputes",
        visibility: "shared",
      })) as APIResponse,
      "create ticket space",
    );
  }

  // Alice (the seeded agent) sends a presence heartbeat so the helpdesk queue is live.
  await postAlice("/messaging/presence/heartbeat", { status: "online" });

  // ── Switch to root for the on-camera tour ───────────────────────────────────
  await injectAuth(page, ROOT);
  const postRoot = poster(page, root);

  // Root resolves the "admin ops" ticket off-camera (assign to self → mark done)
  // so the on-camera reveal shows a deterministic assigned + done state rather
  // than racing the page's 15s auto-refresh + auto-select.
  await jsonOk(
    (await postRoot(`/tickets/${opsTicketId}/assign`, {
      assignee_admin_sub: root.user_sub,
    })) as APIResponse,
    "assign ops ticket",
  );
  await jsonOk(
    (await postRoot(`/tickets/${opsTicketId}/status`, { status: "done" })) as APIResponse,
    "resolve ops ticket",
  );

  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);

  // ── 1. Intro ────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    11,
    "Tickets & Helpdesk",
    "Support tickets · agent queue · spaces · live helpdesk chat",
  );

  // ── 2. The Support Tickets page ─────────────────────────────────────────────
  await page.goto(`${BASE}/tickets`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("h1").filter({ hasText: /support tickets/i })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForTimeout(1000);

  await reveal(
    page,
    page.locator("h1").filter({ hasText: /support tickets/i }).first(),
    "Support Tickets",
    "Open, track, and resolve customer issues — list or kanban board",
    { ms: 3200 },
  );

  await reveal(
    page,
    page.getByText("Admin queue").first(),
    "The admin queue",
    "Admins see every ticket, with live counts by status",
    { ms: 3200 },
  );

  // ── 3. Create a ticket via the UI ───────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Open a ticket").first(),
    "Raise a ticket in seconds",
    "Anyone can file a ticket from the New ticket form",
    { ms: 3400 },
  );

  const uiSubject = `Feature request: dark mode ${stamp}`;
  await page.locator("#ticket-subject").fill(uiSubject);
  await page.waitForTimeout(400);
  await page.locator("#ticket-description").fill("Would love an opt-in dark theme across the app.");
  await page.waitForTimeout(500);
  await reveal(
    page,
    page.locator("#ticket-subject"),
    "Subject + description",
    "Describe the issue — validation keeps it short and clear",
    { ms: 3200, ring: false },
  );

  const createBtn = page.getByRole("button", { name: "Create ticket" });
  await createBtn.scrollIntoViewIfNeeded().catch(() => {});
  const [createResp] = await Promise.all([
    page.waitForResponse(
      (r) =>
        r.url().includes("/tickets") &&
        r.request().method() === "POST" &&
        !r.url().includes("/messages"),
      { timeout: 15_000 },
    ),
    createBtn.click(),
  ]);
  expect(createResp.status()).toBe(200);
  await page.waitForTimeout(1200);

  // Deterministically open the just-created ticket's row (don't rely on auto-select,
  // which the 15s poll can re-target). Click its row in the list, then wait for the
  // detail GET so the thread panel reflects THIS ticket.
  const createdRow = page
    .locator("button")
    .filter({ hasText: uiSubject })
    .first();
  await createdRow.scrollIntoViewIfNeeded().catch(() => {});
  await Promise.all([
    page
      .waitForResponse(
        (r) => /\/tickets\/tkt_[0-9a-f]+(\?|$)/.test(r.url()) && r.request().method() === "GET",
        { timeout: 12_000 },
      )
      .catch(() => null),
    createdRow.click(),
  ]);
  await page.waitForTimeout(900);

  // The created ticket is now open in the thread panel.
  await reveal(
    page,
    page.getByText(uiSubject).first(),
    "Filed and threaded",
    "The new ticket opens instantly with a full reply thread",
    { ms: 3400 },
  );

  // ── 4. Admin operations: assigned + resolved ticket ─────────────────────────
  // Filter the admin queue to status=done so the seeded "admin ops" ticket (which
  // root assigned + resolved during seeding) is guaranteed on the first page.
  const statusSelect = page.locator("select").first();
  await statusSelect.scrollIntoViewIfNeeded().catch(() => {});
  await caption(page, "Filter the queue", "Slice by status, owner, or assignee");
  await statusSelect.selectOption("done").catch(() => {});
  await page.waitForTimeout(400);
  await Promise.all([
    page
      .waitForResponse(
        (r) =>
          r.url().includes("/tickets") &&
          r.url().includes("status=done") &&
          r.request().method() === "GET",
        { timeout: 12_000 },
      )
      .catch(() => null),
    page.getByRole("button", { name: "Apply filters" }).click(),
  ]);
  await page.waitForTimeout(1200);

  // Open the resolved ops ticket deterministically, then wait for its detail GET.
  const opsRow = page.locator("button").filter({ hasText: opsSubject }).first();
  await expect(opsRow).toBeVisible({ timeout: 12_000 });
  await opsRow.scrollIntoViewIfNeeded().catch(() => {});
  await Promise.all([
    page
      .waitForResponse(
        (r) => r.url().includes(opsTicketId) && r.request().method() === "GET",
        { timeout: 12_000 },
      )
      .catch(() => null),
    opsRow.click(),
  ]);
  await page.waitForTimeout(1100);

  await reveal(
    page,
    page.getByText("Assign admin sub").first(),
    "Admin operations",
    "Assign to a teammate, claim it yourself, resolve, or reopen",
    { ms: 3800 },
  );
  await reveal(
    page,
    page.getByText(`Assigned:`).first(),
    "Assigned to an admin",
    "Root claimed this billing dispute and worked it to resolution",
    { ms: 3600 },
  );
  // The thread panel's status Badge (variant="secondary" → .bg-secondary) reads "done".
  await reveal(
    page,
    page.locator(".bg-secondary").filter({ hasText: /^done$/ }).first(),
    "Status: done",
    "Status transitions — assign → resolve → reopen — are tracked end-to-end",
    { ms: 3200 },
  );

  // ── 5. Ticket Spaces ────────────────────────────────────────────────────────
  // View as Alice — she owns the seeded "Billing Disputes" space (the spaces list
  // only shows spaces you own or are a member of, so root would see none).
  await caption(page, "Ticket Spaces", "Loading the shared-space boards…");
  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/tickets/spaces`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("h1").filter({ hasText: /ticket spaces/i })).toBeVisible({
    timeout: 12_000,
  });
  await page.waitForTimeout(1000);

  await reveal(
    page,
    page.locator("h1").filter({ hasText: /ticket spaces/i }).first(),
    "Ticket Spaces",
    "Group tickets into private or shared team boards",
    { ms: 3200 },
  );
  await reveal(
    page,
    page.getByText("Billing Disputes").first(),
    "A shared space",
    "Invite owners, editors, and viewers to collaborate on a queue",
    { ms: 3400 },
  );

  // ── 6. Live Helpdesk chat (Bob's customer view) ─────────────────────────────
  await caption(page, "Live Helpdesk", "Switching to the customer's support chat…");
  await injectAuth(page, BOB);
  await page.goto(`${BASE}/helpdesk`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Your Support Chats")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);

  await reveal(
    page,
    page.getByText("Your Support Chats"),
    "Live helpdesk chat",
    "Customers chat with support in real time — bridged to the agent queue",
    { ms: 3400 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: /contact support/i }),
    "One-tap support",
    "Start a new live chat with the support team anytime",
    { ms: 3200 },
  );

  // ── 7. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Tickets & Helpdesk ✓", "Next: KYC");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
