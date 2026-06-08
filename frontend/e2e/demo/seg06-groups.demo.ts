/**
 * VIDEO SEGMENT 06 — Groups & Syndicates  (~1.5 min)
 *
 * A guided tour of community groups (/groups/{id}) and creator syndicates
 * (/syndicates/{id}/manage): a community feed with pinned posts, a shared group
 * treasury you can contribute to, and syndicate bundle plans that grant members
 * access to every creator in the syndicate.
 *
 * Pattern mirrors seg04-newsfeed.demo.ts: one long test, paced with beat() and
 * narrated with caption()/titleCard(). Every feature shown is brought on-screen
 * and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Seeding notes:
 *   - All seeding is done as Alice via session-auth API calls (CSRF). Alice is
 *     the group admin and the syndicate admin/creator.
 *   - Group treasury contributions debit the contributor's personal wallet
 *     (billing pk=USER#... sk=WALLET, wallet_balance_cents), so Alice's wallet is
 *     pre-funded directly in DynamoDB before the contribution beats.
 *   - Posts are seeded, then one is pinned so the GroupPage shows a "Pinned"
 *     badge (the group feed loads via useInfiniteQuery).
 *   - A syndicate + an active bundle plan are seeded so the Plans tab renders a
 *     plan card; the Members tab shows the membership/access roster.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg06-groups.demo.ts
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

/** Pre-fund a user's personal wallet (DDB) so treasury contributions succeed. */
function fundWallet(userSub: string, cents: number): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
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
tbl.update_item(Key={'pk': 'USER#${userSub}', 'sk': 'WALLET'}, UpdateExpression='SET wallet_balance_cents = :v', ExpressionAttributeValues={':v': ${cents}})
print('wallet funded')
"`,
    { timeout: 12_000 },
  );
}

test("Segment 06 — Groups & Syndicates", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const aliceSub = sessions["alice"].user_sub;

  await injectAuth(page, "alice");
  // Load the app shell up front so the seeding phase records over the real UI.
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

  // Fund Alice's wallet so the live contribution beat succeeds.
  fundWallet(aliceSub, 50000);

  // ── Seed: a community group (Alice is admin) ───────────────────────────────
  const groupResp = await api(page, "post", "/ui/groups", "alice", {
    name: "Atelier Collective",
    description: "A members' community for the studio — drops, behind-the-scenes, and shared funds.",
    visibility: "public",
    topic: "creators",
  });
  const group = (await groupResp.json()) as { group_id: string };
  const groupId = group.group_id;
  await beat(page, 60);

  // Seed a few posts; capture the one we'll pin.
  await api(page, "post", `/ui/groups/${groupId}/posts`, "alice", {
    text: "Welcome to the Atelier Collective! Introduce yourself in the thread below.",
    audience: "public",
  });
  await beat(page, 60);
  const pinResp = await api(page, "post", `/ui/groups/${groupId}/posts`, "alice", {
    text: "Community rules & weekly schedule — read this first. Livestreams every Friday at 6pm.",
    audience: "public",
  });
  const pinPost = (await pinResp.json()) as { post_id: string };
  await beat(page, 60);
  await api(page, "post", `/ui/groups/${groupId}/posts`, "alice", {
    text: "Members-only: early access link for the spring drop is now live.",
    audience: "members_only",
  });
  await beat(page, 60);

  // Pin the rules post so the GroupPage shows a "Pinned" badge.
  await api(page, "post", `/ui/groups/${groupId}/posts/${pinPost.post_id}/pin`, "alice", {});
  await beat(page, 60);

  // Seed a treasury balance so the balance widget shows a real figure (this also
  // creates a ledger entry + contributor row). We still do a live contribution
  // on-camera below; this just guarantees a non-zero starting balance.
  await api(page, "post", `/ui/groups/${groupId}/treasury/contribute`, "alice", {
    amount_cents: 15000,
  });
  await beat(page, 60);

  // ── Seed: a syndicate + an active bundle plan (Alice is admin) ─────────────
  const syndResp = await api(page, "post", "/ui/syndicates", "alice", {
    name: "Studio Syndicate",
    description: "A collective of creators bundled into one subscription.",
  });
  const synd = (await syndResp.json()) as { syndicate_id: string };
  const syndicateId = synd.syndicate_id;
  await beat(page, 60);

  await api(page, "post", `/ui/syndicates/${syndicateId}/plans`, "alice", {
    name: "All-Access Bundle",
    description: "Every creator in the syndicate — one monthly price.",
    price_cents: 2000,
    interval: "month",
  });
  await beat(page, 60);

  // ── Intro ───────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    6,
    "Groups & Syndicates",
    "Community feeds · pinned posts · shared treasury · creator bundles",
  );

  // ── 2. Group page: header + feed ───────────────────────────────────────────
  await page.goto(`${BASE}/groups/${groupId}`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("group-page").waitFor({ timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(1500);

  await reveal(
    page,
    page.getByText("Atelier Collective").first(),
    "A community group",
    "Each group has its own header, membership, and a dedicated feed",
    { ms: 6000 },
  );
  // Member count / nav lives in the header card.
  await reveal(
    page,
    page.getByText(/member/).first(),
    "Members & navigation",
    "Member count, group settings, and the shared treasury — all in one place",
    { ms: 5000 },
  );

  // ── 3. Pinned post ─────────────────────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Pinned").first(),
    "Pinned posts",
    "Admins pin the most important updates to the top of the group feed",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByText("Community rules & weekly schedule").first(),
    "Always at the top",
    "Rules, schedules, and announcements stay front and centre for every member",
    { ms: 5500 },
  );

  // ── 4. Treasury: balance + contribution ────────────────────────────────────
  await page.goto(`${BASE}/groups/${groupId}/treasury`, { waitUntil: "domcontentloaded" });
  await page.getByTestId("group-treasury-page").waitFor({ timeout: 15_000 }).catch(() => {});
  await page.waitForTimeout(1500);

  await reveal(
    page,
    page.getByTestId("treasury-balance-card"),
    "A shared treasury",
    "Every group has a pooled balance — funded by its members",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByTestId("balance-amount"),
    "Live balance",
    "Contributions, donations, and spending are all tracked here",
    { ms: 5000 },
  );

  // Live contribution: pick a quick-amount chip, then Contribute.
  await reveal(
    page,
    page.getByTestId("contribute-section"),
    "Contribute to the pool",
    "Members chip in straight from their wallet",
    { ms: 4500, ring: false },
  );
  await page.getByRole("button", { name: "$50.00" }).first().click().catch(() => {});
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByTestId("contribute-button"),
    "One tap to contribute",
    "Choose an amount and it's added to the treasury instantly",
    { ms: 3500 },
  );
  await page.getByTestId("contribute-button").click().catch(() => {});
  // Wait for the balance to refetch and climb.
  await expect
    .poll(
      async () => (await page.getByTestId("balance-amount").textContent()) ?? "",
      { timeout: 12_000 },
    )
    .toContain("200.00");
  await page.waitForTimeout(600);
  await reveal(
    page,
    page.getByTestId("balance-amount"),
    "Balance updated",
    "The pooled total climbs the moment a contribution lands",
    { ms: 6000 },
  );

  // ── 5. Syndicates: bundle plan + membership ────────────────────────────────
  await page.goto(`${BASE}/syndicates/${syndicateId}/manage`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1800);

  await reveal(
    page,
    page.getByText("Studio Syndicate").first(),
    "Creator syndicates",
    "Multiple creators band together into one collective",
    { ms: 5500 },
  );

  // Plans tab → bundle plan card.
  await page.getByRole("tab", { name: "Plans" }).click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("All-Access Bundle").first(),
    "Bundle subscriptions",
    "One subscription unlocks every creator in the syndicate",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByText("/month").first(),
    "One price, all creators",
    "A single monthly plan — subscribers get access to the whole collective",
    { ms: 5500 },
  );

  // Members tab → membership / access roster.
  await page.getByRole("tab", { name: "Members" }).click().catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("Members", { exact: true }).first(),
    "Dynamic membership",
    "As creators join or leave, bundle subscribers' access updates automatically",
    { ms: 6000 },
  );

  // ── 6. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Groups & Syndicates ✓", "Next: Subscriptions & Monetization");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
