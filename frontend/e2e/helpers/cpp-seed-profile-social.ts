/**
 * cpp-aware seeding glue for the PROFILE-SOCIAL domain (TRACK: seed).
 *
 * PROBLEM: the profile/social specs (public-profile, creator-storefront,
 * activity-feed, feed-rich-content-2, syndicate-feed, recommendations) seed
 * their fixtures by execSync-ing inline python that writes the PYTHON DDB-Local
 * at localhost:8001 — `profiles` (nested profile map), `app_single_table`
 * (POST#/META + USER#/FOLLOWING# social edges), `subscriptions` (CREATOR#/PLAN#).
 * The C++ backend reads a DIFFERENT store (moto :5005 on .82) with DIFFERENT
 * table names (tlc_profile / tlc_newsfeed / tlc_social / tlc_subscriptions) and
 * keys identities by the JWT SUB, not the email. So under E2E_USE_CPP those
 * inline seeds NEVER reach cpp and every profile/social page renders empty (404
 * / empty-array 200).
 *
 * FIX: when targeting cpp, invoke the arg-driven shims that live ON .82
 * (~/projects/testlogon-cpp/e2e/seed_shims/seed_profile-social_*.py) over ssh,
 * so ONE correctly shaped item lands in cpp's OWN moto tables with the cpp SUB.
 * The default Python path is left completely untouched (callers gate on
 * usingCpp()).
 *
 * This module owns ONLY the profile-social cpp-seed wrappers. It re-uses
 * runCppShim / usingCpp from cpp-seed.ts but does NOT edit that shared file, to
 * avoid cross-agent conflicts.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

// ── profile (tlc_profile, PK user_sub, nested `profile` map) ─────────────────
export interface CppProfileOpts {
  userSub: string; // cpp SUB (resolveIdentityId), NOT the email
  displayName?: string;
  description?: string;
  title?: string;
  location?: string;
  profilePhotoUrl?: string;
  coverPhotoUrl?: string;
  followerCount?: number;
  followingCount?: number;
  postCount?: number;
  extra?: Record<string, unknown>; // any other nested profile field
}

/** Upsert one profile row into cpp's tlc_profile (read-merge-write). */
export function cppSeedProfile(opts: CppProfileOpts): void {
  runCppShim("seed_profile-social_profile.py", {
    user_sub: opts.userSub,
    ...(opts.displayName != null ? { display_name: opts.displayName } : {}),
    ...(opts.description != null ? { description: opts.description } : {}),
    ...(opts.title != null ? { title: opts.title } : {}),
    ...(opts.location != null ? { location: opts.location } : {}),
    ...(opts.profilePhotoUrl != null
      ? { profile_photo_url: opts.profilePhotoUrl }
      : {}),
    ...(opts.coverPhotoUrl != null
      ? { cover_photo_url: opts.coverPhotoUrl }
      : {}),
    ...(opts.followerCount != null ? { follower_count: opts.followerCount } : {}),
    ...(opts.followingCount != null
      ? { following_count: opts.followingCount }
      : {}),
    ...(opts.postCount != null ? { post_count: opts.postCount } : {}),
    ...(opts.extra ? { extra: opts.extra } : {}),
  });
}

// ── posts (tlc_newsfeed, PK POST#<id>, SK META, user_id=author sub) ──────────
export interface CppPostOverride {
  post_id?: string;
  status?: string;
  visibility?: string;
  body?: string;
  locked?: boolean;
  like_count?: number;
  comment_count?: number;
  tip_total_cents?: number;
  image_urls?: string[];
  video_id?: string;
  unlock_price_cents?: number;
  lock_price_cents?: number;
  [k: string]: unknown;
}
export interface CppPostsOpts {
  authorSub: string; // cpp SUB
  count?: number;
  testRun?: string;
  bodyPrefix?: string;
  visibility?: string;
  bumpProfileCount?: boolean;
  posts?: CppPostOverride[];
}

/**
 * Seed N published post META rows into cpp's tlc_newsfeed for one author.
 * Returns the created post_ids (newest-first, ISO created_at). Mirrors the
 * inline seedAlicePosts() in the profile/feed specs.
 */
export function cppSeedPosts(opts: CppPostsOpts): string[] {
  const out = runCppShim("seed_profile-social_post.py", {
    author_sub: opts.authorSub,
    count: opts.count ?? 1,
    ...(opts.testRun != null ? { test_run: opts.testRun } : {}),
    ...(opts.bodyPrefix != null ? { body_prefix: opts.bodyPrefix } : {}),
    ...(opts.visibility != null ? { visibility: opts.visibility } : {}),
    ...(opts.bumpProfileCount != null
      ? { bump_profile_count: opts.bumpProfileCount }
      : {}),
    ...(opts.posts ? { posts: opts.posts } : {}),
  });
  // shim prints 'ok <n>' then a JSON array of ids on the last line.
  const lastLine = out.trim().split(/\r?\n/).pop() ?? "[]";
  try {
    const ids = JSON.parse(lastLine);
    return Array.isArray(ids) ? ids : [];
  } catch {
    return [];
  }
}

// ── social follow (tlc_social) ───────────────────────────────────────────────
/**
 * Seed (action="follow") or remove (action="unfollow") one follow edge in cpp's
 * tlc_social, bumping follower/following counts on both profiles. Idempotent.
 * Both subs MUST be cpp SUBs. Mirrors the inline follow seed / cleanupFollow().
 */
export function cppSeedFollow(
  followerSub: string,
  targetSub: string,
  action: "follow" | "unfollow" = "follow",
): void {
  runCppShim("seed_profile-social_follow.py", {
    follower_sub: followerSub,
    target_sub: targetSub,
    action,
  });
}

// ── creator subscription plan (tlc_subscriptions) ────────────────────────────
export interface CppSubPlanOpts {
  creatorSub: string; // cpp SUB
  planId?: string;
  name?: string;
  priceCents?: number;
  interval?: string;
}

/**
 * Seed ONE creator subscription plan (canonical PLAN#/META + CREATOR# index) in
 * cpp's tlc_subscriptions, so h_prof_public.has_subscription_plans is true and
 * the storefront shows the subscribe CTA. Mirrors seedAliceSubscriptionPlan().
 */
export function cppSeedSubPlan(opts: CppSubPlanOpts): void {
  runCppShim("seed_profile-social_subplan.py", {
    creator_sub: opts.creatorSub,
    action: "seed",
    ...(opts.planId != null ? { plan_id: opts.planId } : {}),
    ...(opts.name != null ? { name: opts.name } : {}),
    ...(opts.priceCents != null ? { price_cents: opts.priceCents } : {}),
    ...(opts.interval != null ? { interval: opts.interval } : {}),
  });
}

/** Purge ALL of a creator's subscription plans in cpp. Mirrors cleanupBobSubscriptionPlans(). */
export function cppPurgeSubPlans(creatorSub: string): void {
  runCppShim("seed_profile-social_subplan.py", {
    creator_sub: creatorSub,
    action: "purge",
  });
}

// ── recommendations (tlc_recommendations) ────────────────────────────────────
//
// Mirror the inline :8001 seeders in recommendations.spec.ts. All subs MUST be
// cpp SUBs (the spec already resolveIdentityId's ALICE_ID/BOB_ID). The FOR_YOU /
// SIMILAR video ids are hydrated from tlc_video_metadata — seed those with
// cppSeedVideo (from cpp-seed.ts).

/** RECO#<user>/FOR_YOU pre-computed video_ids. */
export function cppSeedRecoForYou(userSub: string, videoIds: string[]): void {
  runCppShim("seed_profile-social_recommendations.py", {
    op: "for_you",
    user_sub: userSub,
    video_ids: videoIds,
  });
}

/** SIMILAR#<video>/VIDEOS pre-computed similar_video_ids. */
export function cppSeedSimilarVideos(videoId: string, similarIds: string[]): void {
  runCppShim("seed_profile-social_recommendations.py", {
    op: "similar",
    video_id: videoId,
    similar_ids: similarIds,
  });
}

/** RECO#<user>/CREATOR_SUGGEST pre-computed creator_ids. */
export function cppSeedCreatorSuggest(userSub: string, creatorIds: string[]): void {
  runCppShim("seed_profile-social_recommendations.py", {
    op: "creator_suggest",
    user_sub: userSub,
    creator_ids: creatorIds,
  });
}

/** SIGNAL#<user>/VIDEO#<video> engagement signal. */
export function cppSeedRecoSignal(
  userSub: string,
  videoId: string,
  watchPct: number,
  liked: boolean,
): void {
  runCppShim("seed_profile-social_recommendations.py", {
    op: "signal",
    user_sub: userSub,
    video_id: videoId,
    watch_pct: watchPct,
    liked,
  });
}

/** Delete all reco rows under the given pks (RECO#/SIMILAR#/SIGNAL#). */
export function cppCleanupReco(pks: string[]): void {
  runCppShim("seed_profile-social_recommendations.py", { op: "cleanup", pks });
}

// ── alerts / activity-feed (tlc_alerts) ──────────────────────────────────────
export interface CppAlertSpec {
  user_sub: string; // cpp SUB
  event: string;
  ts?: number;
  outcome?: string;
  title?: string;
  details?: Record<string, unknown>;
  read?: boolean;
  priority?: string;
  category?: string;
  action_url?: string;
  source_type?: string;
  source_id?: string;
}

/**
 * Seed alert rows into cpp's tlc_alerts (correct String ts/read_at + 16-digit
 * micro-ts alert_id). Returns [{alert_id, ts}] in the SAME order, so specs that
 * assert on the returned alert_id keep working. Mirrors seedAlerts /
 * seedAlertsSimple in activity-feed.spec.ts. All user_sub MUST be cpp SUBs.
 */
export function cppSeedAlerts(
  alerts: CppAlertSpec[],
): Array<{ alert_id: string; ts: number }> {
  const out = runCppShim("seed_profile-social_alerts.py", { alerts });
  const lastLine = out.trim().split(/\r?\n/).pop() ?? "[]";
  try {
    const parsed = JSON.parse(lastLine);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Delete ALL of an author's posts in cpp's tlc_newsfeed + reset post_count.
 * Mirrors the inline GSI2 POST_AUTHOR#<sub> batch-delete cleanup. */
export function cppPurgeAuthorPosts(authorSub: string): void {
  runCppShim("seed_profile-social_post.py", {
    author_sub: authorSub,
    op: "purge_author",
  });
}
