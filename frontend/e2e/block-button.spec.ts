/**
 * Regression test for GAP-0360 (Block/Unblock UI absent from
 * `PublicUserProfilePage`).
 *
 * A full block/unblock flow requires two seeded sessions + live backend
 * blocking endpoints. The robust, hermetic regression here is a SOURCE-LEVEL
 * assertion (mirrors the readFileSync-based specs already in this folder,
 * e.g. media-player-drm.spec.ts): read the new BlockButton component and the
 * profile page and assert the block wiring is present.
 *
 * Fails-before: BlockButton.tsx did not exist and PublicUserProfilePage.tsx
 * had no block UI / DropdownMenu / blocking-API import.
 * Passes-after: the new component exists and is wired into the profile page.
 */
import { test, expect } from "@playwright/test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const here = dirname(fileURLToPath(import.meta.url));

const BLOCK_BUTTON = readFileSync(
  resolve(here, "../src/components/shared/BlockButton.tsx"),
  "utf-8",
);
const PROFILE_PAGE = readFileSync(
  resolve(here, "../src/pages/profile/PublicUserProfilePage.tsx"),
  "utf-8",
);

test.describe("GAP-0360 — BlockButton component", () => {
  test("imports the blocking API (blockUser/unblockUser/getBlockStatus)", () => {
    expect(BLOCK_BUTTON).toContain("blockUser");
    expect(BLOCK_BUTTON).toContain("unblockUser");
    expect(BLOCK_BUTTON).toContain("getBlockStatus");
    expect(BLOCK_BUTTON).toMatch(/from\s+["']@\/api\/endpoints\/blocking["']/);
  });

  test("reads block status via React Query and toggles via mutations", () => {
    expect(BLOCK_BUTTON).toMatch(/useQuery/);
    expect(BLOCK_BUTTON).toMatch(/useMutation/);
    // block status drives the rendered state
    expect(BLOCK_BUTTON).toContain("is_blocked_by_me");
    // invalidate the status query on success
    expect(BLOCK_BUTTON).toMatch(/invalidateQueries/);
    expect(BLOCK_BUTTON).toContain("block-status");
  });

  test("confirms before blocking and renders both Block and Unblock states", () => {
    expect(BLOCK_BUTTON).toContain("AlertDialog");
    expect(BLOCK_BUTTON).toMatch(/Unblock/);
    expect(BLOCK_BUTTON).toMatch(/Block /);
    // uses a DropdownMenu for the block entry point
    expect(BLOCK_BUTTON).toContain("DropdownMenu");
    // surfaces success/error feedback
    expect(BLOCK_BUTTON).toMatch(/toast\.(success|error)/);
  });
});

test.describe("GAP-0360 — PublicUserProfilePage integration", () => {
  test("imports and renders BlockButton", () => {
    expect(PROFILE_PAGE).toMatch(/import\s+\{\s*BlockButton\s*\}\s+from\s+["']@\/components\/shared\/BlockButton["']/);
    expect(PROFILE_PAGE).toMatch(/<BlockButton\b/);
    expect(PROFILE_PAGE).toContain("targetUserId");
  });

  test("BlockButton sits alongside the existing FollowButton", () => {
    expect(PROFILE_PAGE).toContain("FollowButton");
    // both rendered inside the authenticated, non-own-profile branch
    expect(PROFILE_PAGE).toMatch(/isAuthenticated\s*&&\s*!isOwnProfile/);
  });
});
