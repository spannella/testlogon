/**
 * VIDEO SEGMENT 20 — Delegate Messaging  (~1.5 min)
 *
 * Creators can hand off their inbox to a trusted team member — a "delegate" who
 * reads and replies on the creator's behalf, with every action scoped, tagged
 * and audited. The story on camera:
 *   - Alice grants Bob a scoped "Chat Agent" delegation (read + respond)
 *   - Delegation settings: require-acceptance, max delegates, the "[via @…]" tag
 *   - Bob replies in Alice's DM as Alice — the reply carries a "via @Bob" tag
 *   - Alice's audit log shows exactly what the delegate did
 *   - Bob's "Managing" view: the creators he can act for
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py):
 *   - Alice — the creator. We grant Bob delegation + seed a DM with a delegated
 *             reply via the real APIs (cookie + CSRF), so the UI is truthful.
 *   - Bob   — the delegate / chat agent.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg20-delegates.demo.ts
 */
import { test } from "@playwright/test";
import { BASE, API, injectAuth, reauth, caption, clearCaption, titleCard, beat, reveal, api, loadSessions } from "./_demo";

test("Segment 20 — Delegate Messaging", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const aliceSub = sessions["alice"].user_sub;
  const bobSub = sessions["bob"].user_sub;

  // ── Seed (off camera): grant Bob a chat delegation + a tagged delegated reply ──
  // Auth as Alice FIRST — api() rides the page context's cookies, so the session
  // must be injected before any seeding call or every request 401s.
  await injectAuth(page, "alice");
  await api(page, "put", "/ui/delegates/settings", "alice", {
    require_acceptance: false,
    max_delegates: 10,
    delegate_tag_enabled: true,
    delegate_tag_format: "[via @{delegate_name}]",
  });
  await api(page, "post", "/ui/delegates", "alice", {
    delegate_id: bobSub,
    permissions: ["chat_read", "chat_respond"],
    preset: "chat_agent",
    label: "Bob — Chat Agent",
  });

  // A DM between Alice and Bob; Alice writes, then Bob replies *as Alice*.
  let convId = "";
  try {
    const dm = await api(page, "post", "/messaging/conversations/dm/find-or-create", "alice", {
      user_id: bobSub,
    });
    convId = ((await (dm as { json: () => Promise<{ conversation_id?: string }> }).json()) || {})
      .conversation_id || "";
  } catch {
    /* tolerate — the delegates page is the core of the segment regardless */
  }
  if (convId) {
    await api(page, "post", `/messaging/conversations/${convId}/messages`, "alice", {
      text: "Hey! Can your team help cover replies while I'm filming today?",
    });
    // Bob (the delegate) responds on Alice's behalf — backend appends the tag.
    // Swap the page's cookie jar to Bob just for this call, then restore Alice's
    // so the on-camera tour runs as her.
    await page.context().clearCookies();
    await page.context().addCookies(sessions["bob"].cookies);
    await api(
      page,
      "post",
      `/messaging/delegate/${encodeURIComponent(aliceSub)}/conversations/${convId}/messages`,
      "bob",
      { text: "Absolutely — I've got the inbox covered. Reply sent on your behalf." },
    );
    await page.context().clearCookies();
    await page.context().addCookies(sessions["alice"].cookies);
  }

  // ── 1. Intro ────────────────────────────────────────────────────────────
  await page.goto(`${BASE}/delegates`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1400);
  await titleCard(
    page,
    20,
    "Delegate Messaging",
    "Hand off your inbox — scoped, tagged and fully audited",
  );

  // ── 2. The delegates management page ──────────────────────────────────────
  await reveal(
    page,
    page.getByRole("heading", { name: "Delegates" }).first(),
    "Delegates",
    "Grant trusted teammates permission to act on your behalf",
    { ms: 3500 },
  );
  await reveal(
    page,
    page.getByText("Bob — Chat Agent").first(),
    "A scoped delegate",
    "Bob is a Chat Agent — he can read and respond, nothing more",
    { ms: 4200 },
  ).catch(() => {});
  await reveal(
    page,
    page.getByText("Active", { exact: true }).first(),
    "Active access",
    "Permissions are explicit per delegate and revocable in one click",
    { ms: 3800 },
  ).catch(() => {});

  // Open the Add-Delegate dialog to show the permission presets, then close it.
  await page.getByRole("button", { name: /add delegate/i }).first().click().catch(() => {});
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByText("Permissions").first(),
    "Granular permissions",
    "chat · feed · broadcast — pick a preset or compose your own",
    { ms: 4200 },
  ).catch(() => {});
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(700);

  // Delegation settings — the audit tag that stamps every delegated action.
  await reveal(
    page,
    page.getByText("Delegation Settings").first(),
    "Delegation settings",
    "Require acceptance, cap the number of delegates, and brand the audit tag",
    { ms: 4200 },
  ).catch(() => {});

  // ── 3. The delegated reply in context (carries the "via @…" tag) ──────────
  if (convId) {
    await page.goto(`${BASE}/messages/${convId}`, { waitUntil: "domcontentloaded" });
    await page.waitForTimeout(1600);
    await reveal(
      page,
      page.locator("p, div, span").filter({ hasText: /via @/i }).first(),
      "Sent on your behalf",
      "The reply posts as Alice — but is transparently tagged 'via @Bob'",
      { ms: 5000 },
    ).catch(() => {});
  }

  // ── 4. The audit trail ────────────────────────────────────────────────────
  await page.goto(`${BASE}/delegates`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  await page.getByRole("tab", { name: /audit/i }).first().click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText(/audit log/i).first(),
    "Every action, logged",
    "A complete, tamper-evident record of what each delegate did",
    { ms: 4500 },
  ).catch(() => {});

  // ── 5. The delegate's own "Managing" view (Bob) ───────────────────────────
  await caption(page, "Switching to Bob, the delegate", "He sees the creators he's allowed to act for");
  await beat(page, 1800);
  await reauth(page, "bob");
  await page.goto(`${BASE}/delegates`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1400);
  await page.getByRole("tab", { name: /managing/i }).first().click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByRole("tab", { name: /managing/i }).first(),
    "The delegate's side",
    "Bob's 'Managing' tab lists every creator who's delegated access to him",
    { ms: 4500 },
  ).catch(() => {});

  // ── 6. Outro ──────────────────────────────────────────────────────────────
  await caption(page, "Delegate Messaging ✓", "Team inboxes, without sharing a password");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 800);
});
