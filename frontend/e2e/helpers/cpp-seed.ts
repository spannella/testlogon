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
      "-o", "ControlMaster=auto",
      "-o", `ControlPath=/home/sean/.ssh/cm-cppseed-w${process.env.TEST_WORKER_INDEX || "0"}-%C`,
      "-o", "ControlPersist=180",
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

/**
 * Delete PM# rows (+ BILLING pointer) for a user in cpp's tlc_billing. Empty
 * pmIds = delete ALL PMs (mirrors bug-fixes-2.spec.ts cleanupAllPaymentMethods /
 * removePaymentMethod, whose Python :8001 writes never reach cpp). Best-effort.
 */

// ── promo codes (tlc_promo_codes) ────────────────────────────────────────────

/**
 * Delete a creator's PROMO#* rows (META + REDEEM#*) in cpp's tlc_promo_codes.
 * Mirrors promo-codes.spec.ts cleanupAlicePromoCodes(), whose Python :8001
 * 'PromoCodes'/'ByCreatorCreatedAt' deletes never reach cpp. userSub MUST be the
 * cpp SUB. Run in beforeAll so the creator is below the per-creator cap.
 */
export function cppResetPromoCodes(userSub: string): void {
  runCppShim("reset_promo_codes.py", { user_sub: userSub });
}

export interface CppPromoCodeOpts {
  userSub: string; // cpp SUB (creator_user_id)
  code: string;
  codeId?: string;
  discountType?: string;
  discountValue?: number;
  appliesTo?: string | string[];
  active?: boolean;
  currentUses?: number;
  maxUses?: number;
  maxUsesPerUser?: number;
  minPurchaseCents?: number;
  freeTrialDays?: number;
  expiresAt?: number; // epoch seconds; 0 = never
}

/**
 * Seed ONE promo META row into cpp's tlc_promo_codes with the exact fields cpp's
 * create handler writes. Mirrors promo-codes.spec.ts's two direct DDB seeds
 * (B3 expired-code + D UI-seed), which otherwise write creator_scope rows into
 * the Python :8001 'PromoCodes' store cpp never reads.
 */
export function cppSeedPromoCode(opts: CppPromoCodeOpts): void {
  runCppShim("seed_promo_code.py", {
    user_sub: opts.userSub,
    code: opts.code,
    ...(opts.codeId ? { code_id: opts.codeId } : {}),
    ...(opts.discountType ? { discount_type: opts.discountType } : {}),
    ...(opts.discountValue != null ? { discount_value: opts.discountValue } : {}),
    ...(opts.appliesTo != null ? { applies_to: opts.appliesTo } : {}),
    ...(opts.active != null ? { active: opts.active } : {}),
    ...(opts.currentUses != null ? { current_uses: opts.currentUses } : {}),
    ...(opts.maxUses != null ? { max_uses: opts.maxUses } : {}),
    ...(opts.maxUsesPerUser != null ? { max_uses_per_user: opts.maxUsesPerUser } : {}),
    ...(opts.minPurchaseCents != null ? { min_purchase_cents: opts.minPurchaseCents } : {}),
    ...(opts.freeTrialDays != null ? { free_trial_days: opts.freeTrialDays } : {}),
    ...(opts.expiresAt != null ? { expires_at: opts.expiresAt } : {}),
  });
}

export function cppResetBillingPms(userSub: string, pmIds: string[] = []): void {
  if (!usingCpp()) return;
  try {
    runCppShim("reset_billing_pms.py", { user_sub: userSub, pm_ids: pmIds });
  } catch {
    /* best-effort */
  }
}

/** Delete all TOTP devices for a user in cpp's tlc_totp. Best-effort. */
export function cppDeleteTotpDevices(userSub: string): void {
  if (!usingCpp()) return;
  try {
    runCppShim("delete_totp_devices.py", { user_sub: userSub });
  } catch {
    /* best-effort */
  }
}

/** Delete all email MFA devices for a user in cpp's tlc_email. Best-effort. */
export function cppDeleteEmailDevices(userSub: string): void {
  if (!usingCpp()) return;
  try {
    runCppShim("delete_email_devices.py", { user_sub: userSub });
  } catch {
    /* best-effort */
  }
}

/** Delete all SMS MFA devices for a user in cpp's tlc_sms. Best-effort. */
export function cppDeleteSmsDevices(userSub: string): void {
  if (!usingCpp()) return;
  try {
    runCppShim("delete_sms_devices.py", { user_sub: userSub });
  } catch {
    /* best-effort */
  }
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

// ── ads-analytics fixture (TRACK: harness-seed) ──────────────────────────────
export interface CppAdAnalyticsOpts {
  accountId: string;
  campaignId: string;
  ownerSub: string; // cpp SUB (owner_sub) — NOT an email
  withLedger?: boolean; // seed tlc_ad_billing LEDGER rows (summary/ROAS source)
  withHourly?: boolean; // seed 3 hourly rollups for today
}

/**
 * Seed an advertiser account + 7d/prev-7d daily rollups (+ optional hourly +
 * billing ledger) into cpp's tlc_ad_accounts / tlc_ad_analytics_rollups /
 * tlc_ad_billing. Mirrors the inline :8001 python seeder in ads-analytics.spec
 * so /ui/ads/analytics/{breakdown,summary,timeseries,export} render non-empty
 * under cpp. owner_sub MUST be the cpp SUB (ba_require_account_owner matches
 * account.owner_sub == u.sub).
 */
export function cppSeedAdAnalytics(opts: CppAdAnalyticsOpts): void {
  runCppShim("seed_ad_analytics.py", {
    account_id: opts.accountId,
    campaign_id: opts.campaignId,
    owner_sub: opts.ownerSub,
    with_ledger: opts.withLedger ?? true,
    with_hourly: opts.withHourly ?? true,
  });
}

// ── per-content-revenue fixture (TRACK: harness-seed) ────────────────────────
export interface CppContentRevEntry {
  content_id: string;
  content_type: string;
  reason: string; // 'unlock' -> unlocks_cents, 'tip' -> tips_cents, ...
  amount_cents: number;
  day_offset?: number;
}

/**
 * Seed 'credit' LEDGER rows into cpp's tlc_billing (pk=USER#<sub>) so
 * GET /ui/analytics/content-revenue attributes per-content revenue. Mirrors the
 * inline :8001 python seeder in per-content-revenue.spec.ts. user_sub MUST be
 * the cpp SUB (bilt_accumulate queries pk=USER#<sub>).
 */
export function cppSeedContentRevenue(
  userSub: string,
  entries: CppContentRevEntry[],
  testRun = '',
): void {
  runCppShim('seed_content_revenue.py', {
    user_sub: userSub,
    test_run: testRun,
    entries,
  });
}


// ── kyc-case fixture (TRACK: harness-seed) ───────────────────────────────────
export interface CppKycFile {
  type: string; // "selfie" | "id_front" | ...
  path?: string;
  size?: number;
  mime_type?: string;
}

/**
 * Seed one KYC case (pk=KYC#<caseId>, sk=META, files array) into cpp's
 * tlc_kyc_cases so POST /v1/kyc/cases/{id}/compare-face (b11_case_get +
 * cc_face_anti_spoof) finds it. Mirrors seedKycCase() in
 * kyc-facial-comparison.spec.ts. userSub MUST be the cpp SUB (owner check).
 */
export function cppSeedKycCase(
  caseId: string,
  userSub: string,
  files: CppKycFile[],
  status = "draft",
): void {
  runCppShim("seed_kyc_case.py", {
    case_id: caseId,
    user_sub: userSub,
    status,
    files,
  });
}

// ── role-reset shim (TRACK: harness-reset) ───────────────────────────────────
/**
 * Reset ONE user's role back to a plain "user" (REMOVE admin_profile) in cpp's
 * OWN tlc_users (moto :5005), PK user_sub. Mirrors admin-roles.spec.ts's
 * resetBobToUser() cleanup — but that helper writes to the Python DDB-Local at
 * :8001, which cpp never reads, so under E2E_USE_CPP the reset must route here.
 * userSub MUST be the cpp SUB (resolveIdentityId under cpp). Idempotent.
 */
export function cppResetUserRole(userSub: string, role = "user"): void {
  runCppShim("reset_user_role.py", { user_sub: userSub, role });
}

// ── payout idempotency cleanup (TRACK: seed / 409-idempotency) ───────────────
//
// The payout specs (payouts / creator-payouts / payout-dashboard) call an
// inline cleanupActivePayouts() that mutates the PYTHON CreatorPayouts table on
// DDB-Local :8001 — which cpp never reads. Under E2E_USE_CPP a prior run's
// still-`requested` payout therefore survives, and cpp's one-active-payout
// guard returns 409 on the next POST /ui/payouts/request. This helper cancels
// every active payout for a user THROUGH THE CPP API (the only store cpp reads),
// so each test starts from a clean slate. No-op unless usingCpp(). Idempotent.
//
// email: the cpp login email for the identity (e.g. e2e_alice@test.local).
// apiBase: the base the specs hit — defaults to the vite proxy the suite uses.
export function cppCancelActivePayouts(
  email: string,
  apiBase = process.env.E2E_API_BASE ?? "http://localhost:3000",
): void {
  if (!usingCpp()) return;
  const cppDirect = process.env.E2E_CPP_LOGIN_BASE ?? "https://192.168.0.82:8443";
  const pw = process.env.E2E_PASSWORD ?? "Passw0rd!123";
  try {
    // 1) real cpp login → cookies (login must hit cpp directly for Set-Cookie).
    const loginBody = JSON.stringify({
      challenge_context: { username: email, password: pw },
    });
    const hdr = execFileSync(
      "curl",
      ["-k", "-s", "-D", "-", "-o", "/dev/null", "-X", "POST",
       `${cppDirect}/ui/session/start`, "-H", "Content-Type: application/json",
       "--data-binary", "@-"],
      { input: loginBody, timeout: 30_000, encoding: "utf8" },
    );
    const jar: Record<string, string> = {};
    for (const line of hdr.split(/\r?\n/)) {
      const m = /^set-cookie:\s*([^=]+)=([^;]+)/i.exec(line);
      if (m) jar[m[1].trim()] = m[2].trim();
    }
    const sid = jar["ui_session"], at = jar["ui_access_token"], csrf = jar["ui_csrf"];
    if (!sid || !at || !csrf) return; // login failed → leave state as-is
    const cookie = `ui_session=${sid}; ui_access_token=${at}; ui_csrf=${csrf}`;
    // 2) list this user's payouts.
    const listRaw = execFileSync(
      "curl",
      ["-k", "-s", `${apiBase}/ui/payouts`, "-H", `Cookie: ${cookie}`],
      { timeout: 30_000, encoding: "utf8" },
    );
    let payouts: Array<{ payout_id: string; status: string }> = [];
    try {
      const parsed = JSON.parse(listRaw);
      payouts = Array.isArray(parsed) ? parsed : parsed?.payouts ?? [];
    } catch {
      return;
    }
    // 3) cancel every still-active payout.
    const ACTIVE = new Set(["requested", "approved", "processing", "pending"]);
    for (const p of payouts) {
      if (!p?.payout_id || !ACTIVE.has(p.status)) continue;
      try {
        execFileSync(
          "curl",
          ["-k", "-s", "-o", "/dev/null", "-X", "POST",
           `${apiBase}/ui/payouts/${p.payout_id}/cancel`,
           "-H", `Cookie: ${cookie}`, "-H", `x-csrf-token: ${csrf}`],
          { timeout: 20_000, encoding: "utf8" },
        );
      } catch {
        /* best-effort: keep cancelling the rest */
      }
    }
  } catch {
    /* best-effort cleanup: never fail the test setup on a cleanup hiccup */
  }
}

// ── account-deletion idempotency cleanup (TRACK: seed / 409-idempotency) ─────
//
// account-deletion.spec.ts's cleanupUser() deletes rows from the PYTHON
// account_deletion_requests table on :8001, which cpp never reads. Under cpp a
// prior run's still-`pending` deletion request survives and cpp returns 409 on
// the next POST /request ("one pending deletion per user"). This cancels every
// cancellable pending/processing deletion request for the user THROUGH THE CPP
// API. No-op unless usingCpp(). Idempotent, best-effort.
export function cppCancelActiveDeletions(
  email: string,
  apiBase = process.env.E2E_API_BASE ?? "http://localhost:3000",
): void {
  if (!usingCpp()) return;
  const cppDirect = process.env.E2E_CPP_LOGIN_BASE ?? "https://192.168.0.82:8443";
  const pw = process.env.E2E_PASSWORD ?? "Passw0rd!123";
  const base = "ui/privacy/account-deletion";
  try {
    const loginBody = JSON.stringify({ challenge_context: { username: email, password: pw } });
    const hdr = execFileSync(
      "curl",
      ["-k", "-s", "-D", "-", "-o", "/dev/null", "-X", "POST",
       `${cppDirect}/ui/session/start`, "-H", "Content-Type: application/json",
       "--data-binary", "@-"],
      { input: loginBody, timeout: 30_000, encoding: "utf8" },
    );
    const jar: Record<string, string> = {};
    for (const line of hdr.split(/\r?\n/)) {
      const m = /^set-cookie:\s*([^=]+)=([^;]+)/i.exec(line);
      if (m) jar[m[1].trim()] = m[2].trim();
    }
    const sid = jar["ui_session"], at = jar["ui_access_token"], csrf = jar["ui_csrf"];
    if (!sid || !at || !csrf) return;
    const cookie = `ui_session=${sid}; ui_access_token=${at}; ui_csrf=${csrf}`;
    const listRaw = execFileSync(
      "curl",
      ["-k", "-s", `${apiBase}/${base}/requests`, "-H", `Cookie: ${cookie}`],
      { timeout: 30_000, encoding: "utf8" },
    );
    let requests: Array<{ request_id: string; status: string; can_cancel?: boolean }> = [];
    try {
      const parsed = JSON.parse(listRaw);
      requests = Array.isArray(parsed) ? parsed : parsed?.requests ?? [];
    } catch {
      return;
    }
    const ACTIVE = new Set(["pending", "processing", "scheduled"]);
    for (const r of requests) {
      if (!r?.request_id || !ACTIVE.has(r.status) || r.can_cancel === false) continue;
      try {
        execFileSync(
          "curl",
          ["-k", "-s", "-o", "/dev/null", "-X", "POST",
           `${apiBase}/${base}/requests/${r.request_id}/cancel`,
           "-H", `Cookie: ${cookie}`, "-H", `x-csrf-token: ${csrf}`],
          { timeout: 20_000, encoding: "utf8" },
        );
      } catch { /* keep going */ }
    }
  } catch { /* best-effort */ }
}

/**
 * Delete all account-deletion + data-export rows for a user in cpp's OWN moto
 * table (via the reset_account_deletion.py shim on .82). Clears BOTH a stale
 * pending deletion (409 on POST /request) AND a prior export row (429 on POST
 * /export — cpp treats a <24h export row as the rate-limit signal). Pass the
 * cpp SUB (resolveIdentityId under cpp). No-op unless usingCpp(). Idempotent.
 */
export function cppResetAccountDeletion(userSub: string): void {
  if (!usingCpp()) return;
  try {
    runCppShim("reset_account_deletion.py", { user_sub: userSub });
  } catch {
    /* best-effort: never fail setup on a cleanup hiccup */
  }
}

/**
 * Back-date a deletion request's scheduled_for in cpp's OWN moto table so admin
 * process-due finalizes it (mirrors account-deletion.spec.ts::expireGrace, whose
 * Python :8001 write never reaches cpp). Pass the cpp SUB + request_id. No-op
 * unless usingCpp().
 */
export function cppExpireAccountDeletion(userSub: string, requestId: string): void {
  if (!usingCpp()) return;
  try {
    runCppShim("expire_account_deletion.py", {
      user_sub: userSub,
      request_id: requestId,
    });
  } catch {
    /* best-effort */
  }
}
