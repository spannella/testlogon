/**
 * VIDEO SEGMENT 04 — Newsfeed  (~2 min)
 *
 * A guided tour of the newsfeed (/feed): rich-text / markdown posts, emoji
 * reactions, comments, tips, pay-to-unlock locked posts, polls, and bookmarks.
 *
 * Pattern mirrors seg02-messaging.demo.ts: one long test, paced with beat() and
 * narrated with caption()/titleCard(). Every feature shown is brought on-screen
 * and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Seeding notes (from project memory):
 *   - GET /feed only returns the viewer's OWN posts plus posts fanned out from
 *     authors they follow. So Alice's own content is seeded AS Alice, and the
 *     locked-post / tip affordances (which only render on NON-own posts) come
 *     from Bob: Alice follows Bob, then Bob publishes public posts that fan out
 *     into Alice's feed.
 *   - A payment method is injected for Alice so the unlock / tip CTAs enable.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg04-newsfeed.demo.ts
 */
import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
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
tbl.put_item(Item={'pk': pk,'sk': 'PM#'+pm_id,'payment_method_id': pm_id,'provider': 'stripe','provider_method_id': pm_id,'method_type': 'card','label': 'Visa ****4242','brand': 'visa','last4': '4242','exp_month': 12,'exp_year': 2099,'is_default': True,'priority': 0,'created_at': int(time.time())})
tbl.put_item(Item={'pk': pk,'sk': 'BILLING','autopay_enabled': False,'currency': 'usd','default_payment_method_id': pm_id})
print('injected')
"`,
    { timeout: 12_000 },
  );
}

/** Navigate to /feed via the sidebar (the Vite proxy returns JSON for direct GET /feed). */
async function gotoFeed(page: Page): Promise<void> {
  await page.goto(`${BASE}/`, { waitUntil: "load" });
  await page.waitForTimeout(900);
  await page.locator('a[href="/feed"]').first().click();
  await expect(page).toHaveURL(/\/feed/, { timeout: 12_000 });
  await page.waitForTimeout(1600);
}

test("Segment 04 — Newsfeed", async ({ page, browser }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const aliceSub = sessions["alice"].user_sub;
  const bobSub = sessions["bob"].user_sub;
  const TS = Date.now();

  await injectAuth(page, "alice");
  // Load the app shell up front so the seeding phase records over the real UI
  // (not a blank page) before the title card appears.
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

  // Payment method so the unlock / tip affordances enable.
  injectPaymentMethod(aliceSub, `pm_demo_alice_${TS}`);

  // A separate Bob page (own cookies) so Bob can publish posts that fan out to
  // Alice. api(bobPage, …, "bob") sends Bob's CSRF with Bob's session cookies.
  const bobPage = await browser.newPage();
  await injectAuth(bobPage, "bob");

  // ── Seed: Alice follows Bob (so Bob's posts fan out into her feed) ─────────
  await api(page, "post", "/ui/social/follow", "alice", { target_user_id: bobSub })
    .catch(() => {});
  await beat(page, 60);

  // ── Seed: Alice's own posts (rich text + a plain one) ─────────────────────
  await api(page, "post", "/posts", "alice", {
    body_plain: "Big news — the spring collection drops Friday. Behind-the-scenes all week!",
    body_markdown:
      "## Spring collection drops **Friday** 🌸\n\nBehind-the-scenes all week. Here's what's coming:\n\n- New limited prints\n- A members-only livestream\n- Early access for subscribers",
    body_format: "markdown",
    body_version: 1,
  });
  await beat(page, 60);
  const welcomeResp = await api(page, "post", "/posts", "alice", {
    body_plain: "Welcome to the feed! Drop a comment and let me know what you want to see next.",
  });
  const welcome = (await welcomeResp.json()) as { post_id: string };
  const welcomePostId = welcome.post_id;
  await beat(page, 60);

  // Seed reactions + a comment on the welcome post so reactions/comments are live.
  await api(page, "post", `/posts/${welcomePostId}/reactions`, "alice", { emoji: "🔥" });
  await api(page, "post", `/posts/${welcomePostId}/comments`, "alice", {
    body: "So excited for this — counting down the days!",
  });
  await beat(page, 60);

  // ── Seed: a poll (Alice can vote on her own poll) ─────────────────────────
  await api(page, "post", "/posts", "alice", {
    body_plain: "What should I stream next?",
    post_type: "poll",
    visibility: "public",
    poll_data: {
      questions: [
        {
          text: "What should I stream next?",
          choice_mode: "single",
          options: [
            { text: "Studio tour" },
            { text: "Q&A session" },
            { text: "Live design sprint" },
          ],
        },
      ],
      anonymous: true,
      allow_vote_change: true,
    },
  });
  await beat(page, 60);

  // ── Seed: Bob's posts (fan out to Alice; render with Tip + Unlock CTAs) ────
  // A normal Bob post → Tip affordance (only shows on NON-own posts).
  await api(bobPage, "post", "/posts", "bob", {
    body_plain: "Thanks for following! Here's a free wallpaper pack for the community. 💙",
    visibility: "public",
  });
  await beat(page, 60);
  // A locked Bob post → pay-to-unlock CTA.
  await api(bobPage, "post", "/posts", "bob", {
    body_plain: "Exclusive: the full editing preset bundle is in this post.",
    visibility: "public",
    unlock_price_cents: 299,
  });
  await beat(page, 60);

  // ── Intro ─────────────────────────────────────────────────────────────────
  await gotoFeed(page);
  await titleCard(
    page,
    4,
    "Newsfeed",
    "Posts · rich text · reactions · comments · tips · polls · bookmarks",
  );

  // ── 2. The feed ────────────────────────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Welcome to the feed!").first(),
    "A living newsfeed",
    "Your posts and updates from creators you follow, all in one timeline",
    { ms: 6500 },
  );
  // Show a rendered markdown post (headings, bold) already in the feed.
  await reveal(
    page,
    page.getByText("Spring collection drops").first(),
    "Rich, formatted posts",
    "Markdown and rich text render right in the timeline",
    { ms: 6000 },
  );

  // ── 3. Create a post (markdown) ────────────────────────────────────────────
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" as ScrollBehavior }));
  await page.waitForTimeout(400);
  const composer = page.locator("textarea[placeholder*=\"What's on your mind\"]");
  await reveal(
    page,
    composer,
    "Compose a post",
    "Write a quick update — or switch to rich text and markdown",
    { ms: 4500, ring: false },
  );
  // Switch to Markdown mode and type formatted content (live preview renders).
  await page.getByRole("button", { name: "Markdown", exact: true }).first().click().catch(() => {});
  await page.waitForTimeout(500);
  await composer.click();
  await composer.fill(
    "## Studio refresh ✨\n\nJust **repainted** the whole set. Come see it on the next stream!",
  );
  await beat(page, 2200);
  await reveal(
    page,
    page.locator("text=Preview").first(),
    "Rich text & markdown",
    "Headings, bold, lists — with a live preview as you type",
    { ms: 4500, ring: false },
  );
  // Publish it.
  await caption(page, "Publish", "One click and it's live in the feed");
  await page.locator("button[type='submit']").filter({ hasText: /^post$/i }).first().click();
  await page.waitForTimeout(2600);
  await reveal(
    page,
    page.getByText("Studio refresh").first(),
    "Posted instantly",
    "Your new post appears at the top of the timeline",
    { ms: 6000 },
  );

  // ── 4. Reactions ───────────────────────────────────────────────────────────
  // Reveal the emoji reaction bar (👍 button) on a post.
  const thumbsUp = page.locator("button").filter({ hasText: "👍" }).first();
  await reveal(
    page,
    thumbsUp,
    "Emoji reactions",
    "React with a tap — 👍 ❤️ 😂 🔥 😮 — counts update live",
    { ms: 5200 },
  );
  await thumbsUp.click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    thumbsUp,
    "Reacted",
    "Your reaction is highlighted and counted immediately",
    { ms: 4500 },
  );

  // ── 5. Comments ────────────────────────────────────────────────────────────
  // Open the comments thread on the welcome post. Scope to that card, then click
  // the comment toggle (2nd action button, immediately after the Like button).
  const welcomeCard = page
    .locator(".rounded-lg, [class*='card']")
    .filter({ hasText: "Welcome to the feed!" })
    .last();
  await welcomeCard.scrollIntoViewIfNeeded().catch(() => {});
  await page.waitForTimeout(300);
  const commentToggle = welcomeCard
    .getByRole("button", { name: "Like" })
    .locator("xpath=following-sibling::button[1]");
  await caption(page, "Comments", "Open a threaded conversation under any post");
  await commentToggle.click().catch(() => {});
  await page.waitForTimeout(1300);
  await reveal(
    page,
    page.getByText("counting down the days").first(),
    "Threaded comments",
    "Reply, react, edit, and even tip individual comments",
    { ms: 6500 },
  );

  // ── 6. Tips ────────────────────────────────────────────────────────────────
  const tipBob = page.getByText("free wallpaper pack").first();
  await tipBob.scrollIntoViewIfNeeded().catch(() => {});
  await page.waitForTimeout(300);
  // The Tip button (DollarSign + "Tip") only renders on non-own posts.
  const tipBtn = page.getByRole("button", { name: "Tip" }).first();
  await reveal(
    page,
    tipBtn,
    "Tips",
    "Send a creator money directly from any post — micro-payments built in",
    { ms: 6000 },
  );

  // ── 7. Locked / pay-to-unlock ──────────────────────────────────────────────
  const unlockBtn = page.getByRole("button", { name: /Unlock for \$/ }).first();
  await reveal(
    page,
    unlockBtn,
    "Pay-to-unlock posts",
    "Lock premium content behind a one-time payment",
    { ms: 5200 },
  );
  // Open the unlock dialog to show the payment flow.
  await caption(page, "Unlock flow", "Pick a payment method and unlock in one tap");
  await unlockBtn.click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByRole("button", { name: /Pay & Unlock/ }).first(),
    "Secure unlock",
    "Choose a card, confirm the total, and the post reveals instantly",
    { ms: 5500, ring: false },
  );
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(700);

  // ── 8. Poll ────────────────────────────────────────────────────────────────
  const pollCard = page.locator("[data-testid='poll-card']").first();
  await reveal(
    page,
    page.locator("[data-testid='poll-question-text']").first(),
    "Polls & surveys",
    "Ask your audience — single or multi-choice, with live results",
    { ms: 5200 },
  );
  // Cast a vote to animate the results bars.
  await caption(page, "Cast a vote", "Tap an option and watch the results fill in");
  await pollCard.locator("button[data-testid^='poll-option-']").first().click().catch(() => {});
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.locator("[data-testid='poll-total-votes']").first(),
    "Live results",
    "Percentages and totals update the moment a vote lands",
    { ms: 5000 },
  );

  // ── 9. Bookmarks ───────────────────────────────────────────────────────────
  const bookmarkBtn = page.getByRole("button", { name: /Bookmark post|Remove bookmark/ }).first();
  await reveal(
    page,
    bookmarkBtn,
    "Bookmarks",
    "Save any post to read later — collected in your saved items",
    { ms: 5200 },
  );
  await bookmarkBtn.click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    bookmarkBtn,
    "Saved",
    "Bookmarked posts are tucked away for whenever you come back",
    { ms: 4500 },
  );

  // ── 10. Outro ──────────────────────────────────────────────────────────────
  await caption(page, "Newsfeed ✓", "Next: Social");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);

  await bobPage.close();
});
