/**
 * cpp-aware seeding glue (TRACK: seed).
 *
 * PROBLEM this solves: the inline per-test seed helpers (seedVideo,
 * injectPaymentMethod, seedSubscriberCount) write to a Python DDB-Local at
 * localhost:8001 on the frontend host. The C++ backend reads a DIFFERENT store
 * (moto :5005 on .82) and keys its tables differently (SUB, not email;
 * tlc_video_metadata / tlc_billing / tlc_admin_subscription_tiers). So under
 * E2E_USE_CPP those inline seeds NEVER reach cpp and the UI renders empty.
 *
 * FIX: when targeting cpp, invoke small arg-driven shims that live ON .82
 * (~/projects/testlogon-cpp/e2e/seed_shims/*.py) over ssh, so ONE correctly
 * shaped item lands in cpp's OWN moto tables. The default Python path is left
 * completely untouched (callers gate on usingCpp()).
 *
 * This module owns only the cpp-seed path. It does NOT edit session.ts /
 * playwright.config.ts / vite.config.ts.
 */
import { execFileSync } from "child_process";

// ── cpp targeting detection (mirrors helpers/session.ts::usingCpp) ───────────
export function usingCpp(): boolean {
  if (process.env.E2E_USE_CPP === "1") return true;
  const api = process.env.E2E_API_BASE ?? "";
  return api !== "" && !/localhost:8000\/?$/.test(api);
}

// ── .82 ssh target for the shims ─────────────────────────────────────────────
const CPP_SSH_HOST = process.env.E2E_CPP_SSH_HOST ?? "sean@192.168.0.82";
const CPP_SSH_KEY =
  process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
const CPP_SHIM_DIR =
  process.env.E2E_CPP_SHIM_DIR ??
  "/home/sean/projects/testlogon-cpp/e2e/seed_shims";

/**
 * Run one seed shim on .82 with a single JSON arg. Throws on non-zero exit or
 * if the shim does not print an 'ok' line. Returns the shim's stdout (trimmed).
 */
export function runCppShim(shim: string, args: Record<string, unknown>): string {
  // base64 the JSON payload so the remote login shell never has to parse
  // quotes/spaces/apostrophes in the args (robust single-token transport).
  const b64 = Buffer.from(JSON.stringify(args), "utf8").toString("base64");
  const remote = `python3 ${CPP_SHIM_DIR}/${shim} --b64 ${b64}`;
  const out = execFileSync(
    "ssh",
    [
      "-i",
      CPP_SSH_KEY,
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=20",
      CPP_SSH_HOST,
      remote,
    ],
    { timeout: 30_000, encoding: "utf8" },
  ).trim();
  if (!/\bok\b/.test(out)) {
    throw new Error(`cpp shim ${shim} did not confirm: ${out}`);
  }
  return out;
}

// ── typed wrappers ───────────────────────────────────────────────────────────

export interface CppVideoOpts {
  videoId: string;
  ownerSub: string; // cpp SUB (owner_user_id), NOT an email
  title?: string;
  status?: string;
  visibility?: string;
  hlsManifestUrl?: string;
  thumbnailUrl?: string;
  durationSeconds?: number;
  extra?: Record<string, unknown>; // access_mode / price_cents / ...
}

/** Seed one video row into cpp's tlc_video_metadata (PK video_id). */
export function cppSeedVideo(opts: CppVideoOpts): void {
  runCppShim("seed_video.py", {
    video_id: opts.videoId,
    owner_user_id: opts.ownerSub,
    title: opts.title ?? "E2E Seed Video",
    status: opts.status ?? "published",
    visibility: opts.visibility ?? "public",
    ...(opts.hlsManifestUrl ? { hls_manifest_url: opts.hlsManifestUrl } : {}),
    ...(opts.thumbnailUrl ? { thumbnail_url: opts.thumbnailUrl } : {}),
    ...(opts.durationSeconds != null
      ? { duration_seconds: opts.durationSeconds }
      : {}),
    ...(opts.extra ?? {}),
  });
}

/** Seed one payment-method fixture (PM# + BILLING) into cpp's tlc_billing. */
export function cppSeedPaymentMethod(userSub: string, pmId: string): void {
  runCppShim("seed_payment_method.py", { user_sub: userSub, pm_id: pmId });
}

/** Set subscriber_count on one admin subscription tier in cpp's world. */
export function cppSeedSubscriberCount(
  creatorSub: string,
  tierId: string,
  count = 3,
): void {
  runCppShim("seed_subscriber_count.py", {
    creator_sub: creatorSub,
    tier_id: tierId,
    count,
  });
}

/**
 * Top up one user's billing WALLET (pk=USER#<sub>, sk=WALLET) in cpp's moto.
 * cpp's h_subscribe / wallet-funded charges debit this balance and 402 when it
 * is short — the Python path resolves a default PM instead, so a PM-only seed
 * never funds cpp. Default 100_000c ($1000) comfortably covers a first cycle.
 */
export function cppSeedWallet(userSub: string, cents = 100_000): void {
  runCppShim("seed_wallet.py", { user_sub: userSub, cents });
}
