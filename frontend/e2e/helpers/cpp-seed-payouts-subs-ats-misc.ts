/**
 * cpp-aware seeding glue for the PAYOUTS-SUBS-ATS-MISC domain (TRACK: seed).
 *
 * PROBLEM: the payout + social-follow specs seed their fixtures against the
 * PYTHON DDB-Local (:8001) — or send an EMAIL where cpp keys by SUB — so under
 * E2E_USE_CPP the data never reaches cpp's OWN store (moto :5005 on .82):
 *
 *   • creator-payouts / payouts / payout-dashboard / bulk-payout-tools seed
 *     earnings via an inline seedOldCredits() that writes the Python 'billing'
 *     table keyed by EMAIL. cpp's /ui/payouts/balance scans tlc_billing keyed by
 *     the real SUB for type=credit/state!=reversed rows -> reads 0 -> every
 *     downstream request/list/cancel/approve test 400/403/409s.
 *   • follow-system / social-follow POST /ui/social/follow with the target's
 *     EMAIL as target_user_id. cpp requires the target's real SUB AND a profile
 *     row in tlc_profile (else 404 "User not found") -> every follow test fails.
 *
 * FIX: when targeting cpp, (a) seed settled credits into cpp's tlc_billing via a
 * small arg-driven shim on .82, and (b) ensure the follow endpoints see real
 * profiles (reuse the profile shim) + resolve email->SUB for target ids. The
 * default Python path is left completely untouched (callers gate on usingCpp()).
 *
 * This module owns ONLY the payouts-subs-ats-misc cpp-seed wrappers. It re-uses
 * runCppShim / usingCpp from cpp-seed.ts but does NOT edit that shared file, to
 * avoid cross-agent conflicts.
 */
import { runCppShim, usingCpp } from "./cpp-seed";
import { resolveIdentityId } from "./session";

export { usingCpp, resolveIdentityId };

// ── payout credits (tlc_billing settled credit ledger) ───────────────────────

export interface CppPayoutCreditsOpts {
  /** email/alias on the spec side; resolved to the real cpp SUB here. */
  userSub: string;
  /** number of ledger rows to write. */
  count?: number;
  /** cents per row. */
  amountEach?: number;
  /** age of each credit in seconds (default ~8 days, past any dev hold). */
  ageSeconds?: number;
  reason?: string;
}

/**
 * Seed `count` settled CREDIT rows (amountEach cents each) into cpp's
 * tlc_billing so /ui/payouts/balance counts them as available_cents. Returns
 * the total cents seeded (mirrors the inline seedOldCredits return value).
 * No-op-safe: only meaningful under usingCpp().
 */
export function cppSeedPayoutCredits(opts: CppPayoutCreditsOpts): number {
  const count = opts.count ?? 1;
  const amountEach = opts.amountEach ?? 5000;
  runCppShim("seed_payouts-subs-ats-misc_credits.py", {
    user_sub: resolveIdentityId(opts.userSub),
    count,
    amount_each: amountEach,
    ...(opts.ageSeconds != null ? { age_seconds: opts.ageSeconds } : {}),
    ...(opts.reason != null ? { reason: opts.reason } : {}),
  });
  return count * amountEach;
}

// ── social profiles (tlc_profile) — reuse the profile-social shim ────────────

/**
 * Ensure a profile row exists in cpp's tlc_profile for `userSub` so the follow
 * endpoints (which db_get the target profile and 404 when absent) succeed.
 * Accepts an email/alias and resolves it to the cpp SUB. No-op-safe.
 */
export function cppSeedSocialProfile(userSub: string, displayName?: string): void {
  runCppShim("seed_profile-social_profile.py", {
    user_sub: resolveIdentityId(userSub),
    ...(displayName != null ? { display_name: displayName } : {}),
  });
}

/**
 * Resolve an identity's id for use as a follow `target_user_id` / URL segment /
 * assertion value. Under cpp this is the real SUB; on the Python path it is the
 * email verbatim (byte-identical behavior preserved).
 */
export function cppFollowTargetId(keyOrEmail: string): string {
  return usingCpp() ? resolveIdentityId(keyOrEmail) : keyOrEmail;
}

// ── read-back shims (sponsorship_deals / billing WALLET+ledger) ──────────────

/**
 * Read ONE item from a cpp moto table by key so a spec's ddbGet() after a cpp
 * mutation observes what cpp actually wrote (not the empty Python DDB-Local).
 * Table name is the spec's logical name (sponsorship_deals / billing /
 * AdAccounts); mapped to the cpp tlc_* table inside the shim. Returns the parsed
 * item or null. Caller is responsible for using cpp SUBs in USER#<..> keys.
 */
export function cppReadItem(
  table: string,
  key: Record<string, string>,
): Record<string, unknown> | null {
  const out = runCppShim("read_payouts-subs-ats-misc.py", { op: "get", table, key });
  const lines = out.trim().split(/\r?\n/).filter((l) => l.trim() !== "");
  // runCppShim requires an 'ok' token; the shim prints the JSON item/null on the
  // line(s) — the last non-empty line is the payload.
  const last = lines[lines.length - 1] ?? "null";
  if (last === "null") return null;
  try {
    return JSON.parse(last) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Read a user's billing ledger (pk=USER#<sub>, begins_with LEDGER#) from cpp's
 * own tlc_billing. `userSub` MUST be the cpp SUB. Returns the ledger rows array.
 */
export function cppReadLedger(userSub: string): Array<Record<string, unknown>> {
  const out = runCppShim("read_payouts-subs-ats-misc.py", { op: "ledger", user_sub: userSub });
  const lines = out.trim().split(/\r?\n/).filter((l) => l.trim() !== "");
  const last = lines[lines.length - 1] ?? "[]";
  try {
    return JSON.parse(last) as Array<Record<string, unknown>>;
  } catch {
    return [];
  }
}

// ── active-payout cleanup (tlc_creator_payouts) ──────────────────────────────

/**
 * Cancel every ACTIVE payout for a user DIRECTLY in cpp's moto so the
 * one-active-payout guard (409 "already pending") is cleared before a
 * deterministic payout test. This replaces the API-based cppCancelActivePayouts
 * for the current cpp build, whose POST /ui/session/start login flow returns no
 * Set-Cookie (so the API helper silently no-ops and the stale payout survives).
 * The email/alias is resolved to the cpp SUB inside the shim wrapper. Idempotent;
 * only meaningful under usingCpp().
 */
export function cppCancelActivePayoutsDirect(userIdOrEmail: string): void {
  if (!usingCpp()) return;
  runCppShim("cancel_active_payouts.py", {
    user_sub: resolveIdentityId(userIdOrEmail),
  });
}

// ── bulk pending payout/refund rows (tlc_creator_payouts / tlc_refund_requests) ─

/**
 * Seed ONE pending payout OR refund row into cpp's own moto so the admin
 * bulk-payout tools endpoints see it as eligible. Returns the ref_id (payout_id
 * / refund_request_id) — same contract as the inline seedPending(). The
 * user/email is resolved to the cpp SUB inside the shim wrapper. Only meaningful
 * under usingCpp().
 */
export function cppSeedBulkPending(
  kind: "payout" | "refund",
  userIdOrEmail: string,
  amountCents: number,
): string {
  const out = runCppShim("seed_bulk_pending.py", {
    kind,
    user_sub: resolveIdentityId(userIdOrEmail),
    amount_cents: amountCents,
  });
  // shim prints "ok <ref_id>\n<ref_id>"; the last non-empty line is the ref_id.
  const lines = out.trim().split(/\r?\n/).filter((l) => l.trim() !== "");
  const last = lines[lines.length - 1] ?? "";
  return last.trim();
}
