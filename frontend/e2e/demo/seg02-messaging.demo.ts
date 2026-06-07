/**
 * VIDEO SEGMENT 02 — Messaging  (~3.5 min)
 *
 * A guided tour of the real-time messaging feature: DMs & groups, view-once,
 * client-side encryption, tips, locked (pay-to-unlock) messages, scheduled
 * sends, and rich attachments (files / calendar / voice).
 *
 * Pattern mirrors seg01-auth.demo.ts: one long test, paced with beat() and
 * narrated with caption()/titleCard(). Every feature shown is brought
 * on-screen and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg02-messaging.demo.ts
 */
import { test, expect, type APIRequestContext } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
  API,
  injectAuth,
  api,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
} from "./_demo";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

/** Inject a test payment method (DDB) so tip/unlock affordances are enabled. */
function injectPaymentMethod(userSub: string, pmId: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path
env_file = Path('/home/ubuntu/testlogon/.env.local')
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
pm_id = '${pmId}'
tbl.put_item(Item={'pk': pk,'sk': 'PM#'+pm_id,'payment_method_id': pm_id,'provider': 'stripe','provider_method_id': pm_id,'method_type': 'card','label': 'Test Card ****4242','brand': 'visa','last4': '4242','exp_month': 12,'exp_year': 2099,'priority': 0,'created_at': int(time.time())})
tbl.put_item(Item={'pk': pk,'sk': 'BILLING','autopay_enabled': False,'currency': 'usd','default_payment_method_id': pm_id})
print('injected')
"`,
    { timeout: 12_000 },
  );
}

/**
 * POST as a non-Alice identity using a dev-mode Bearer token via the global
 * APIRequestContext (no browser cookies → backend uses get_current_user_id,
 * which accepts `Bearer <user_id>` in dev mode). page.request can't be used for
 * other identities because it carries Alice's session cookies.
 */
async function apiBearer(
  req: APIRequestContext,
  userSub: string,
  path: string,
  body: object = {},
) {
  return req.post(`${API}${path}`, {
    data: body,
    headers: { Authorization: `Bearer ${userSub}` },
  });
}

test("Segment 02 — Messaging", async ({ page, request }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const aliceSub = sessions["alice"].user_sub;
  const bobSub = sessions["bob"].user_sub;
  const charlieSub = sessions["charlie_admin"].user_sub;
  const TS = Date.now();

  // Payment methods so "Attach tip" / "Unlock for" affordances are enabled.
  injectPaymentMethod(aliceSub, `pm_demo_alice_${TS}`);
  injectPaymentMethod(bobSub, `pm_demo_bob_${TS}`);

  // ── Auth + intro ─────────────────────────────────────────────────────────
  await injectAuth(page, "alice");
  await page.goto(`${BASE}/messages`, { waitUntil: "domcontentloaded" });
  await titleCard(
    page,
    2,
    "Messaging",
    "Real-time DMs & groups · view-once · encryption · tips · scheduling",
  );

  // ── Seed a rich Alice↔Bob DM ─────────────────────────────────────────────
  const dmResp = await api(page, "post", "/messaging/conversations", "alice", {
    type: "dm",
    participant_ids: [bobSub],
  });
  const dm = (await dmResp.json()) as { conversation_id: string };
  const dmId = dm.conversation_id;

  // Seed a conversation history (Bob ↔ Alice) so the DM looks like a real
  // two-sided thread. Bob's messages go through the global request fixture
  // (Bearer auth) since page.request carries Alice's cookies.
  await apiBearer(request, bobSub, `/messaging/conversations/${dmId}/messages`, {
    text: `Hey Alice! Are we still on for the launch review? [${TS}]`,
  });
  await beat(page, 400);
  await api(page, "post", `/messaging/conversations/${dmId}/messages`, "alice", {
    text: `Absolutely — pushing the new build now. [${TS}]`,
  });
  await beat(page, 400);
  await apiBearer(request, bobSub, `/messaging/conversations/${dmId}/messages`, {
    text: `Perfect. Sending you the secret access code separately. [${TS}]`,
  });
  await beat(page, 400);

  // Seed a TIPPED message from Bob (so Alice, the recipient, sees the tip).
  await apiBearer(request, bobSub, `/messaging/conversations/${dmId}/messages`, {
    text: `Thanks for the great work — here's a little something! [${TS}]`,
    tip_amount_cents: 500,
    tip_payment_method_id: `pm_demo_bob_${TS}`,
  });
  await beat(page, 400);

  // Seed a LOCKED (pay-to-unlock) message from Bob.
  await apiBearer(request, bobSub, `/messaging/conversations/${dmId}/messages`, {
    text: `The exclusive launch deck is attached. [${TS}]`,
    lock_price_cents: 199,
    lock_description: "Exclusive launch deck",
  });
  await beat(page, 400);

  // ── 2. Open the DM via deep-link ─────────────────────────────────────────
  await page.goto(`${BASE}/messages/${dmId}`, { waitUntil: "load" });
  await expect(page.locator("textarea").last()).toBeVisible({ timeout: 15_000 });
  // Wait for the thread content (not skeletons) to render before showing it.
  await expect(
    page.locator("p").filter({ hasText: "still on for the launch review" }).first(),
  ).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1500);

  await reveal(
    page,
    page.locator("textarea").last(),
    "Real-time conversations",
    "Direct messages and group chats, live over the wire",
    { ms: 7500, ring: false },
  );
  await reveal(
    page,
    page.locator("p").filter({ hasText: "still on for the launch review" }).first(),
    "A live thread",
    "Two-sided history syncs instantly between participants",
    { ms: 7950 },
  );

  // ── 3. Send a text message from the UI ───────────────────────────────────
  const textMsg = `Build is live — take a look! [${TS}]`;
  const ta = page.locator("textarea").last();
  await ta.scrollIntoViewIfNeeded();
  await caption(page, "Compose & send", "Type a message and fire it off");
  await ta.click();
  await ta.fill(textMsg);
  await beat(page, 1400);
  await page.getByRole("button", { name: "Send message" }).click();
  await page.waitForTimeout(2000);
  await reveal(
    page,
    page.locator("p").filter({ hasText: textMsg }).first(),
    "Message delivered",
    "Your sent bubble appears at the bottom, newest-first",
    { ms: 7950 },
  );

  // ── 4. View-once ─────────────────────────────────────────────────────────
  const viewOnceToggle = page.getByText("View once", { exact: true }).first();
  await reveal(
    page,
    viewOnceToggle,
    "View-once messages",
    "Recipients can open them exactly once, then they're gone",
    { ms: 6600 },
  );
  await viewOnceToggle.click().catch(() => {});
  await page.waitForTimeout(600);
  await ta.click();
  await ta.fill(`This disappears after one peek. [${TS}]`);
  await beat(page, 1400);
  await page.getByRole("button", { name: "Send message" }).click();
  await page.waitForTimeout(1800);
  await reveal(
    page,
    page.locator("p").filter({ hasText: "disappears after one peek" }).first(),
    "Gated by design",
    "The recipient taps to view once — then the content self-destructs",
    { ms: 7500 },
  );
  // Turn view-once back off for subsequent sends.
  if (await viewOnceToggle.isChecked?.().catch(() => false)) {
    await viewOnceToggle.click().catch(() => {});
  }
  await page.waitForTimeout(400);

  // ── 5. Encryption ────────────────────────────────────────────────────────
  const encToggle = page.getByText("Encrypt message", { exact: true }).first();
  await reveal(
    page,
    encToggle,
    "Client-side encryption",
    "Messages encrypted in the browser before they ever leave your device",
    { ms: 6600 },
  );
  await encToggle.click().catch(() => {});
  await page.waitForTimeout(700);
  const pw = page.getByPlaceholder("Encryption password");
  const cpw = page.getByPlaceholder("Confirm password");
  await reveal(
    page,
    pw,
    "Password-protected",
    "AES-256-GCM with a key derived from a shared password",
    { ms: 6300, ring: false },
  );
  await pw.fill("launch-secret-2026");
  await cpw.fill("launch-secret-2026");
  await beat(page, 1400);
  await ta.click();
  await ta.fill(`Access code: HORIZON-9 [${TS}]`);
  await beat(page, 1200);
  await page.getByRole("button", { name: "Send message" }).click();
  await page.waitForTimeout(2200);
  // The "Encrypted" badge appears on the sent bubble.
  await reveal(
    page,
    page.getByText("Encrypted", { exact: true }).last(),
    "Encrypted at rest",
    "The server only ever stores ciphertext — never the plaintext",
    { ms: 6900 },
  );
  // Open the decrypt dialog.
  const decryptBtn = page.getByRole("button", { name: "Decrypt message" }).last();
  if (await decryptBtn.count().catch(() => 0)) {
    await decryptBtn.scrollIntoViewIfNeeded().catch(() => {});
    await caption(page, "Decrypt on demand", "Enter the password to reveal the contents");
    await decryptBtn.click().catch(() => {});
    await page.waitForTimeout(1200);
    const dlgPw = page.getByPlaceholder(/password/i).last();
    if (await dlgPw.count().catch(() => 0)) {
      await dlgPw.fill("launch-secret-2026").catch(() => {});
      await beat(page, 1200);
      const doDecrypt = page
        .getByRole("button", { name: /^decrypt/i })
        .last();
      await doDecrypt.click().catch(() => {});
      await page.waitForTimeout(1500);
    }
    await beat(page, 4000);
    // Close any open dialog.
    await page.keyboard.press("Escape").catch(() => {});
    await page.waitForTimeout(600);
  }
  // Turn encryption back off.
  if (await encToggle.isChecked?.().catch(() => false)) {
    await encToggle.click().catch(() => {});
  }
  await page.waitForTimeout(400);

  // ── 6. Tips ──────────────────────────────────────────────────────────────
  await reveal(
    page,
    page.locator("p").filter({ hasText: "here's a little something" }).first(),
    "Tips",
    "Send money with a message — micro-payments baked right in",
    { ms: 7500 },
  );
  // Show the "Attach tip" composer affordance too.
  const tipToggle = page.getByText("Attach tip", { exact: true }).first();
  await reveal(
    page,
    tipToggle,
    "Attach a tip",
    "Pick an amount and a payment method, then send",
    { ms: 6600 },
  );

  // ── 7. Locked / pay-to-unlock ────────────────────────────────────────────
  await reveal(
    page,
    page.getByText(/Unlock for \$/).first(),
    "Pay-to-unlock messages",
    "Lock premium content behind a one-time payment",
    { ms: 7500 },
  );

  // ── 8. Scheduled send ────────────────────────────────────────────────────
  const scheduleBtn = page.getByRole("button", { name: "Schedule send" });
  await reveal(
    page,
    scheduleBtn,
    "Schedule a send",
    "Queue a message to deliver automatically at a future time",
    { ms: 7200 },
  );

  // ── 9. Attachments ───────────────────────────────────────────────────────
  await reveal(
    page,
    page.getByRole("button", { name: "Attach file" }),
    "Rich attachments",
    "Images, video, and PDFs — with optional view-once",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: "Share file from Files" }),
    "Share from Files",
    "Send a file straight from your file manager",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: "Calendar actions" }),
    "Calendar & scheduling",
    "Share events, propose meeting times, run polls",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: "Record voice message" }),
    "Voice notes",
    "Record and send audio — including listen-once",
    { ms: 6000 },
  );

  // ── 10. Group chat ───────────────────────────────────────────────────────
  await caption(page, "Group chats", "Everything DMs can do — for teams");
  const grpResp = await api(page, "post", "/messaging/conversations/group", "alice", {
    participant_ids: [bobSub, charlieSub],
    title: "Launch Team",
  });
  const grp = (await grpResp.json()) as { conversation_id: string };
  const grpId = grp.conversation_id;
  // Bob + Charlie accept the invite so they're active participants.
  await apiBearer(request, bobSub, `/messaging/conversations/${grpId}/accept`, {});
  await apiBearer(request, charlieSub, `/messaging/conversations/${grpId}/accept`, {});
  await beat(page, 400);
  // Seed a group message from Bob and a reaction from Charlie.
  const gmResp = await apiBearer(
    request,
    bobSub,
    `/messaging/conversations/${grpId}/messages`,
    { text: `Team, the launch is GO for Friday! 🚀 [${TS}]` },
  );
  const gm = (await gmResp.json()) as { message_id: string };
  await apiBearer(
    request,
    charlieSub,
    `/messaging/conversations/${grpId}/messages/${gm.message_id}/reactions`,
    { emoji: "🔥" },
  );
  await api(page, "post", `/messaging/conversations/${grpId}/messages`, "alice", {
    text: `Love it. Final checklist going out now. [${TS}]`,
  });
  await beat(page, 400);

  await page.goto(`${BASE}/messages/${grpId}`, { waitUntil: "load" });
  await expect(page.locator("textarea").last()).toBeVisible({ timeout: 15_000 });
  // Wait for the group thread content (not skeletons) before revealing it.
  await expect(
    page.locator("p").filter({ hasText: "the launch is GO for Friday" }).first(),
  ).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1800);
  await reveal(
    page,
    page.locator("p").filter({ hasText: "the launch is GO for Friday" }).first(),
    "Group messaging",
    "Sender names, reactions, and the same rich toolset",
    { ms: 8700 },
  );

  // ── 11. Outro ────────────────────────────────────────────────────────────
  await caption(page, "Messaging ✓", "Next: Calls");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
