/**
 * VIDEO SEGMENT 05 — Social  (~1.5 min)
 *
 * A guided tour of the social layer:
 *   - Public profiles (/u/{identifier}): avatar, name, bio, follower stats
 *   - Follow / unfollow with a live follower count
 *   - Block (the "⋮" more-actions menu next to Follow)
 *   - Discovery search (/discover)
 *   - Achievements & display badges (/achievements)
 *
 * Pattern mirrors seg04-newsfeed.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Every feature shown is brought on-screen
 * and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Seeding notes:
 *   - The whole tour is viewed AS Alice. The Follow + Block affordances on a
 *     public profile only render for a NON-own profile, so Alice visits BOB's
 *     profile (/u/{bobSub}).
 *   - Bob is given a rich public profile (display name, title, bio, stats) and is
 *     indexed for discovery search.
 *   - Alice is given two UNLOCKED achievements (a definition + a user_achievements
 *     row each) so the badge grid renders earned badges.
 *   - The public-profile follower count is read from the nested profile map
 *     (profile.follower_count). The real /ui/social/follow path increments a
 *     TOP-LEVEL follower_count attribute, NOT the nested one (product
 *     inconsistency — flagged in the report), so to SHOW the count incrementing
 *     we do the real follow AND bump the nested count, then reload so the new
 *     value paints next to the now-"Following" button.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg05-social.demo.ts
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
const BOB_SUB = "e2e_bob@test.local";
const ALICE_SUB = "e2e_alice@test.local";

/** Bob's baseline follower count (nested profile.follower_count).
 *  Kept under 1,000 so the header renders the exact number (formatCount only
 *  abbreviates ≥1000 as "X.XK") — that way the +1 after Alice follows is
 *  visibly distinct on screen (948 → 949) rather than both rounding to "1.3K". */
const BOB_FOLLOWERS_BASE = 948;

/** Run a short inline python snippet against DynamoDB Local (env from .env.local). */
function ddb(snippet: string): string {
  const prelude = `
import boto3, os, time, uuid
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
`;
  return execSync(`${PYTHON} -c "${(prelude + snippet).replace(/"/g, '\\"')}"`, {
    timeout: 20_000,
  }).toString();
}

/** Seed Bob's + Alice's public profiles (nested 'profile' map, what get_profile reads). */
function seedProfiles(): void {
  ddb(`
users = ddb.Table(os.environ.get('USERS_TABLE_NAME','users'))
prof  = ddb.Table(os.environ.get('PROFILE_TABLE_NAME','profiles'))
for sub in ('${ALICE_SUB}', '${BOB_SUB}'):
    if not users.get_item(Key={'user_sub': sub}).get('Item'):
        users.put_item(Item={'user_sub': sub, 'created_at': int(time.time()) - 86400})

bob = (prof.get_item(Key={'user_sub': '${BOB_SUB}'}).get('Item') or {}).get('profile') or {}
bob['display_name'] = 'Bob Rivera'
bob['title'] = 'Photographer & Creator'
bob['description'] = 'Travel photographer sharing field notes, presets, and behind-the-scenes from the road.'
bob['follower_count'] = ${BOB_FOLLOWERS_BASE}
bob['following_count'] = 212
bob['post_count'] = 87
prof.put_item(Item={'user_sub': '${BOB_SUB}', 'profile': bob, 'updated_at': int(time.time())})

alice = (prof.get_item(Key={'user_sub': '${ALICE_SUB}'}).get('Item') or {}).get('profile') or {}
alice['display_name'] = 'Alice Monroe'
alice.setdefault('description', 'Creator. Designer. Coffee enthusiast.')
alice.setdefault('follower_count', 940)
alice.setdefault('following_count', 180)
alice.setdefault('post_count', 54)
prof.put_item(Item={'user_sub': '${ALICE_SUB}', 'profile': alice, 'updated_at': int(time.time())})
print('profiles-seeded')
`);
}

/** Bump Bob's nested follower count to a new value (used to show it incrementing). */
function setBobFollowerCount(n: number): void {
  ddb(`
prof = ddb.Table(os.environ.get('PROFILE_TABLE_NAME','profiles'))
item = prof.get_item(Key={'user_sub': '${BOB_SUB}'}).get('Item') or {}
p = item.get('profile') or {}
p['follower_count'] = ${n}
prof.put_item(Item={'user_sub': '${BOB_SUB}', 'profile': p, 'updated_at': int(time.time())})
print('count-set')
`);
}

/** Seed an achievement definition + an unlocked user_achievements row for Alice. */
function seedAchievements(): void {
  ddb(`
ach  = ddb.Table(os.environ.get('ACHIEVEMENTS_TABLE_NAME','achievements'))
uach = ddb.Table(os.environ.get('USER_ACHIEVEMENTS_TABLE_NAME','user_achievements'))
defs = [
  ('ach_demo_first_post', 'First Post', 'Published your first post to the community.', 'common', 1, 10, 'posts_published', 0),
  ('ach_demo_rising_star', 'Rising Star', 'Reached 1,000 followers.', 'rare', 1000, 100, 'followers', 1),
]
for aid, label, desc, rar, thr, pts, mk, so in defs:
    ach.put_item(Item={'achievement_id': aid,'category':'social','subcategory':'milestones','label':label,'description':desc,'icon_url':'','rarity':rar,'threshold':thr,'points':pts,'metric_key':mk,'sort_order':so,'active':True,'created_at':int(time.time())})
    uach.put_item(Item={'user_sub':'${ALICE_SUB}','achievement_id':aid,'unlocked_at':int(time.time()),'trigger_event':'demo_seed','points':pts,'displayed':True,'label':label,'icon_url':'','rarity':rar})
print('achievements-seeded')
`);
}

/** Index Bob + Alice into the discovery search index. */
function reindexDiscovery(): void {
  ddb(`
import sys
sys.path.insert(0, '/home/ubuntu/testlogon')
from app.services.discovery import index_user_for_discovery
index_user_for_discovery('${BOB_SUB}')
index_user_for_discovery('${ALICE_SUB}')
print('discovery-indexed')
`);
}

test("Segment 05 — Social", async ({ page }) => {
  test.setTimeout(600_000);
  loadSessions();

  await injectAuth(page, "alice");
  // Paint the real UI before the title card so the seed phase isn't over a blank page.
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });

  // ── Seed all segment data ──────────────────────────────────────────────────
  seedProfiles();
  seedAchievements();
  reindexDiscovery();
  // Make sure Alice does NOT already follow Bob (so "Follow" shows first).
  await api(page, "post", "/ui/social/unfollow", "alice", { target_user_id: BOB_SUB }).catch(() => {});
  setBobFollowerCount(BOB_FOLLOWERS_BASE);
  await beat(page, 200);

  // ── 1. Intro ────────────────────────────────────────────────────────────────
  // Load Bob's profile first so the title card overlays a painted page (not a
  // loading spinner), then show the card.
  await page.goto(`${BASE}/u/${BOB_SUB}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Bob Rivera").first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1000);
  await titleCard(page, 5, "Social", "Follow · profiles · block · discovery · achievements");

  // ── 2. Bob's public profile ──────────────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Bob Rivera").first(),
    "Public creator profiles",
    "Every creator gets a shareable public page — avatar, name, and bio",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.locator('[data-testid="stats-row"]').first(),
    "Social stats at a glance",
    "Followers, following, and post counts, right in the header",
    { ms: 6000 },
  );

  // ── 3. Follow ────────────────────────────────────────────────────────────────
  const followBtn = page.getByTestId("follow-button");
  await reveal(
    page,
    followBtn,
    "Follow a creator",
    "One tap to follow — their posts start flowing into your feed",
    { ms: 4500 },
  );
  // Click Follow — the button's own mutation writes the real follow edge and
  // optimistically flips the label to "Following". Move the cursor off the button
  // afterwards (hovering it would swap "Following" → "Unfollow").
  await followBtn.click().catch(() => {});
  await page.mouse.move(10, 10);
  await page.waitForTimeout(400);
  await expect(followBtn.getByText("Following").first()).toBeVisible({ timeout: 10_000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    followBtn.getByText("Following").first(),
    "Now following",
    "The button flips to “Following” the moment you tap",
    { ms: 4500 },
  );
  // ... and reflect the incremented follower count, then reload so it paints.
  setBobFollowerCount(BOB_FOLLOWERS_BASE + 1);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByText("Bob Rivera").first()).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.locator('[data-testid="stats-row"]').first(),
    "Follower count ticks up",
    `${(BOB_FOLLOWERS_BASE + 1).toLocaleString()} followers — counts update live`,
    { ms: 6000 },
  );

  // ── 4. Block (more-actions menu) ─────────────────────────────────────────────
  const moreBtn = page.getByTestId("block-button-more");
  await reveal(
    page,
    moreBtn,
    "Stay in control",
    "Every profile has a more-actions menu next to Follow",
    { ms: 4500 },
  );
  await caption(page, "Block", "Open the menu to block — they can no longer message or see your content");
  await moreBtn.click().catch(() => {});
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.getByTestId("block-button-menuitem"),
    "Block a user",
    "Block from the menu — unblock any time from Settings",
    { ms: 5500 },
  );
  // Close the menu without completing the block.
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(700);

  // ── 5. Discovery ─────────────────────────────────────────────────────────────
  await page.goto(`${BASE}/discover`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Discover" })).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1000);
  const searchBox = page.getByPlaceholder("Search users...");
  await reveal(
    page,
    searchBox,
    "Discover people",
    "Find creators and friends with instant search",
    { ms: 4000, ring: false },
  );
  await searchBox.click();
  await searchBox.fill("Bob");
  await page.waitForTimeout(1600);
  await reveal(
    page,
    page.getByText("Bob Rivera").first(),
    "Live search results",
    "Type a name and matching creators appear as you go",
    { ms: 6000 },
  );

  // ── 6. Achievements ──────────────────────────────────────────────────────────
  await page.goto(`${BASE}/achievements`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Achievements" })).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText("First Post").first(),
    "Achievements & badges",
    "Hit milestones to unlock badges — track them all on your profile",
    { ms: 6000 },
  );
  await reveal(
    page,
    page.getByText("Rising Star").first(),
    "Earn rarer badges",
    "Common, rare, epic, legendary — each worth points toward the leaderboard",
    { ms: 6000 },
  );

  // ── 7. Outro ──────────────────────────────────────────────────────────────────
  await caption(page, "Social ✓", "Next: Groups & Syndicates");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
