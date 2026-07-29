/**
 * cpp-aware seeding glue for the VIDEO-VOD domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): the video/VOD specs' inline
 * seedVideo() / entitlement / rental helpers write to a Python DDB-Local at
 * localhost:8001 (PascalCase tables VideoMetadata / VodEntitlements /
 * VodRentals). The C++ backend reads a DIFFERENT store — moto :5005 on .82 —
 * with snake_case tlc_* tables and cpp item shapes. So under E2E_USE_CPP those
 * inline seeds NEVER reach cpp: the storefront renders empty, /access returns
 * "not_purchased", rentals 404, and the review queue is empty.
 *
 * FIX: when targeting cpp, invoke small arg-driven shims on .82
 * (~/projects/testlogon-cpp/e2e/seed_shims/seed_video-vod_*.py + the shared
 * seed_video.py) over ssh so ONE correctly-shaped item lands in cpp's OWN moto
 * tables. Callers gate every call on usingCpp(); the default Python path is
 * left byte-identical.
 *
 * This module is OWNED by the video-vod domain. It re-uses runCppShim/usingCpp
 * from the shared cpp-seed.ts but does NOT edit that file (to avoid cross-agent
 * conflicts). It owns its own shim files (seed_video-vod_*.py) and its own
 * wrappers here.
 *
 * IMPORTANT — cpp identity is SUB-based: owner/buyer/seller MUST be the cpp SUB
 * (resolved from a LIVE session, e.g. loadSessions()[key].user_sub — NOT the
 * fixture email and NOT a stale manifest sub). Passing an email makes the video
 * un-ownable and entitlements invisible.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

// ── video metadata (re-uses the shared seed_video.py shim) ───────────────────

export interface CppVodVideoOpts {
  videoId: string;
  ownerSub: string; // cpp SUB (owner_user_id) — NOT an email
  title?: string;
  status?: string; // "published" | "pending_review" | ...
  visibility?: string;
  priceCents?: number;
  accessMode?: string; // free | ppv | ad_supported | subscriber_only | subscriber_free
  durationSeconds?: number;
  hlsManifestUrl?: string;
  thumbnailUrl?: string;
  availablePurchaseTypes?: string[];
  viewOncePriceCents?: number;
  rentalPriceCents?: number;
  downloadPriceCents?: number;
  rentalDurationHours?: number;
  adsFreeForSubscribers?: boolean;
  adConfig?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

/**
 * Seed ONE video row into cpp's tlc_video_metadata (PK video_id) shaped for the
 * VOD/rental/ad/subtitle/review-queue/watch-party read paths. Only defined
 * fields are written; numeric fields are coerced to numbers by the shim so a
 * stringy timestamp can never poison the storefront enrichment.
 */
export function cppSeedVodVideo(opts: CppVodVideoOpts): void {
  const args: Record<string, unknown> = {
    video_id: opts.videoId,
    owner_user_id: opts.ownerSub,
    title: opts.title ?? "E2E Seed Video",
    status: opts.status ?? "published",
    visibility: opts.visibility ?? "public",
  };
  if (opts.priceCents != null) args.price_cents = opts.priceCents;
  if (opts.accessMode) args.access_mode = opts.accessMode;
  if (opts.durationSeconds != null) args.duration_seconds = opts.durationSeconds;
  if (opts.hlsManifestUrl) args.hls_manifest_url = opts.hlsManifestUrl;
  if (opts.thumbnailUrl) args.thumbnail_url = opts.thumbnailUrl;
  if (opts.availablePurchaseTypes)
    args.available_purchase_types = opts.availablePurchaseTypes;
  if (opts.viewOncePriceCents != null)
    args.view_once_price_cents = opts.viewOncePriceCents;
  if (opts.rentalPriceCents != null)
    args.rental_price_cents = opts.rentalPriceCents;
  if (opts.downloadPriceCents != null)
    args.download_price_cents = opts.downloadPriceCents;
  if (opts.rentalDurationHours != null)
    args.rental_duration_hours = opts.rentalDurationHours;
  if (opts.adsFreeForSubscribers != null)
    args.ads_free_for_subscribers = opts.adsFreeForSubscribers;
  if (opts.adConfig) args.ad_config = opts.adConfig;
  Object.assign(args, opts.extra ?? {});
  runCppShim("seed_video.py", args);
}

/** Remove a seeded video from cpp's tlc_video_metadata (cleanup). No status. */
export function cppDeleteVodVideo(videoId: string): void {
  // seed_video.py has no delete op; overwrite to an unpublishable state so it
  // no longer shows in storefront/queue reads. Callers that must fully remove
  // should rely on the Python path (this is cpp-only best-effort cleanup).
  runCppShim("seed_video.py", {
    video_id: videoId,
    owner_user_id: "deleted",
    status: "deleted",
    visibility: "private",
  });
}

// ── VOD entitlements (tlc_vod_entitlements) ──────────────────────────────────

export interface CppVodEntitlementOpts {
  buyerSub: string; // cpp SUB
  videoId: string;
  sellerSub?: string; // cpp SUB
  purchaseType?: "permanent" | "view_once" | "rental" | "download";
  grantType?: "purchase" | "subscription";
  amountCents?: number;
  viewsRemaining?: number; // -1 unlimited, 0 consumed
  expiresAt?: number; // epoch seconds, 0 = none
  downloadAllowed?: boolean;
  purchaseId?: string;
  createdAt?: number;
}

/** Seed ONE VOD entitlement grant into cpp's tlc_vod_entitlements. */
export function cppSeedVodEntitlement(opts: CppVodEntitlementOpts): void {
  runCppShim("seed_video-vod_entitlement.py", {
    op: "put",
    buyer_sub: opts.buyerSub,
    video_id: opts.videoId,
    seller_sub: opts.sellerSub ?? "",
    purchase_type: opts.purchaseType ?? "permanent",
    grant_type: opts.grantType ?? "purchase",
    amount_cents: opts.amountCents ?? 0,
    views_remaining: opts.viewsRemaining ?? -1,
    expires_at: opts.expiresAt ?? 0,
    download_allowed: opts.downloadAllowed ?? false,
    ...(opts.purchaseId ? { purchase_id: opts.purchaseId } : {}),
    ...(opts.createdAt != null ? { created_at: opts.createdAt } : {}),
  });
}

/** Delete ONE VOD entitlement (cleanup, e.g. re-run a purchase test). */
export function cppDeleteVodEntitlement(buyerSub: string, videoId: string): void {
  runCppShim("seed_video-vod_entitlement.py", {
    op: "delete",
    buyer_sub: buyerSub,
    video_id: videoId,
  });
}

// ── VOD rentals (tlc_vod_rentals) ────────────────────────────────────────────

export interface CppVodRentalOpts {
  buyerSub: string; // cpp SUB
  videoId: string;
  sellerSub?: string; // cpp SUB
  tier?: "rental" | "view_once";
  amountCents?: number;
  durationHours?: number;
  startedAt?: number; // 0 = pending (clock not launched)
  expiresAt?: number; // 0 = none; <= now => expired (when started)
  viewsRemaining?: number;
  consumedAt?: number;
  createdAt?: number;
  rentalId?: string;
}

/** Seed ONE VOD rental row into cpp's tlc_vod_rentals. */
export function cppSeedVodRental(opts: CppVodRentalOpts): void {
  runCppShim("seed_video-vod_rental.py", {
    op: "put",
    buyer_sub: opts.buyerSub,
    video_id: opts.videoId,
    seller_sub: opts.sellerSub ?? "",
    tier: opts.tier ?? "rental",
    amount_cents: opts.amountCents ?? 0,
    duration_hours: opts.durationHours ?? 48,
    ...(opts.startedAt != null ? { started_at: opts.startedAt } : {}),
    ...(opts.expiresAt != null ? { expires_at: opts.expiresAt } : {}),
    ...(opts.viewsRemaining != null ? { views_remaining: opts.viewsRemaining } : {}),
    ...(opts.consumedAt != null ? { consumed_at: opts.consumedAt } : {}),
    ...(opts.createdAt != null ? { created_at: opts.createdAt } : {}),
    ...(opts.rentalId ? { rental_id: opts.rentalId } : {}),
  });
}

/** Delete ONE VOD rental row (cleanup). */
export function cppDeleteVodRental(buyerSub: string, videoId: string): void {
  runCppShim("seed_video-vod_rental.py", {
    op: "delete",
    buyer_sub: buyerSub,
    video_id: videoId,
  });
}

// ── subscriptions (tlc_subscriptions) — subscriber-side ACTIVE row ───────────
// Needed by the VOD ads-free / subscriber-gated tests: cpp's vod_has_active_sub
// reads the SUBSCRIBER#<u> / SUB# side and matches creator_id + status.

export interface CppVodSubscriptionOpts {
  subscriberSub: string; // cpp SUB
  creatorSub: string; // cpp SUB
  subId?: string;
  status?: string; // active | trialing | past_due
}

/** Seed ONE active subscriber-side subscription row into cpp's tlc_subscriptions. */
export function cppSeedSubscription(opts: CppVodSubscriptionOpts): void {
  runCppShim("seed_video-vod_subscription.py", {
    op: "put",
    subscriber_sub: opts.subscriberSub,
    creator_sub: opts.creatorSub,
    status: opts.status ?? "active",
    ...(opts.subId ? { sub_id: opts.subId } : {}),
  });
}

/** Delete ONE subscriber-side subscription row (cleanup). */
export function cppDeleteSubscription(subscriberSub: string, subId?: string): void {
  runCppShim("seed_video-vod_subscription.py", {
    op: "delete",
    subscriber_sub: subscriberSub,
    ...(subId ? { sub_id: subId } : {}),
  });
}

// ── filemanager video node (tlc_filemanager) — VOD file-bridge source ────────
// The vod-file-bridge spec pre-creates a filemanager FILE node with a video/*
// content-type that POST /ui/vod-bridge/import reads via fm_get_node_opt. Its
// inline seedFileNode() writes to the Python :8001 'file_manager' table which
// cpp never reads; this lands the node in cpp's own tlc_filemanager (PK
// USER#<sub>, SK NODE#<path>). ownerSub MUST be the cpp SUB.

export interface CppFilemanagerNodeOpts {
  ownerSub: string; // cpp SUB
  path: string; // e.g. "/videos/foo.mp4"
  name?: string;
  contentType?: string; // MUST start with "video/" for the bridge
  s3Bucket?: string;
  s3Key?: string;
  size?: number;
  vodVideoId?: string; // pre-link to an existing VOD record
}

/** Seed ONE filemanager video FILE node into cpp's tlc_filemanager. */
export function cppSeedFilemanagerVideoNode(opts: CppFilemanagerNodeOpts): void {
  runCppShim("seed_filemanager_video_node.py", {
    owner_user_id: opts.ownerSub,
    path: opts.path,
    ...(opts.name ? { name: opts.name } : {}),
    ...(opts.contentType ? { content_type: opts.contentType } : {}),
    ...(opts.s3Bucket ? { s3_bucket: opts.s3Bucket } : {}),
    ...(opts.s3Key ? { s3_key: opts.s3Key } : {}),
    ...(opts.size != null ? { size: opts.size } : {}),
    ...(opts.vodVideoId ? { vod_video_id: opts.vodVideoId } : {}),
  });
}
