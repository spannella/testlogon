/**
 * cpp-aware seeding glue for the groups-treasury domain (TRACK: seed).
 *
 * OWNS ONLY this domain's cpp-seed wrappers so it never conflicts with the
 * shared helpers/cpp-seed.ts (or other domains' cpp-seed-*.ts). Re-uses
 * runCppShim / cppSeedWallet / usingCpp from the shared module so every seed
 * call inherits the per-worker ssh ControlMaster multiplexing (no new raw ssh).
 *
 * PROBLEM this solves under E2E_USE_CPP:
 *  1. syndicates / syndicate-treasury / syndicate-feed all start by having Alice
 *     CREATE a syndicate (POST /ui/syndicates). cpp enforces SY_MAX_PER_USER=10
 *     via the per-user index (pk=USER_SYND#<sub>). Across repeated runs that
 *     index in cpp's moto (tlc_syndicates) grows past 10, so every create 400s
 *     ("User already in 10 syndicates") and the whole file cascades red. The
 *     Python path recreates DDB-Local fresh each run so it never sees this.
 *     cppResetUserSyndicates() clears the stale index (and the caller's ghost
 *     memberships) so create returns 201 again.
 *  2. group-treasury seeds a GROUP (META + MEMBER#) into Python 'user_groups'
 *     and personal/treasury WALLETs into Python 'billing'; the C++ backend reads
 *     its OWN tlc_user_groups + tlc_billing on moto :5005. cppSeedTreasuryGroup
 *     (delegating to the shared group shim) + cppSeedWallet land the same rows
 *     in cpp's tables so ug_require_role passes and gtr_balance reads funded.
 *
 * The default Python path is untouched: callers gate every wrapper on usingCpp().
 */
import { execFileSync } from "child_process";
import { runCppShim, usingCpp, cppSeedWallet } from "./cpp-seed";

export { usingCpp, cppSeedWallet };

// -- .82 ssh target (mirrors helpers/cpp-seed.ts constants) -------------------
const CPP_SSH_HOST = process.env.E2E_CPP_SSH_HOST ?? "sean@192.168.0.82";
const CPP_SSH_KEY =
  process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
const CPP_SHIM_DIR =
  process.env.E2E_CPP_SHIM_DIR ??
  "/home/sean/projects/testlogon-cpp/e2e/seed_shims";

/**
 * Run a READ shim on .82 that prints a raw value (no 'ok' contract). Reuses the
 * SAME per-worker ControlMaster ControlPath keying as runCppShim so it inherits
 * the ssh multiplexing (no MaxStartups storm). Returns trimmed stdout.
 */
function runCppReadShim(shim: string, args: Record<string, unknown>): string {
  const b64 = Buffer.from(JSON.stringify(args), "utf8").toString("base64");
  return execFileSync(
    "ssh",
    [
      "-i", CPP_SSH_KEY,
      "-o", "IdentitiesOnly=yes",
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=20",
      "-o", "ControlMaster=auto",
      "-o", `ControlPath=/home/sean/.ssh/cm-cppseed-w${process.env.TEST_WORKER_INDEX || "0"}-%C`,
      "-o", "ControlPersist=180",
      CPP_SSH_HOST,
      `python3 ${CPP_SHIM_DIR}/${shim} --b64 ${b64}`,
    ],
    { timeout: 30_000, encoding: "utf8" },
  ).trim();
}

/**
 * Read one user's personal WALLET balance (cents) from cpp's tlc_billing.
 * Mirrors the Python-path getWalletBalance() for the cpp store.
 */
export function cppReadUserWallet(userSub: string): number {
  const raw = runCppReadShim("read_user_wallet.py", { user_sub: userSub });
  return parseInt(raw, 10) || 0;
}

// -- syndicate index reset (SY_MAX_PER_USER de-flake) -------------------------

/**
 * Clear the given cpp SUBs' syndicate index rows (pk=USER_SYND#<sub>) plus their
 * membership rows in cpp's tlc_syndicates. Run in a spec's top-level beforeAll
 * BEFORE any POST /ui/syndicates so the caller is below SY_MAX_PER_USER (10) and
 * the create returns 201. Idempotent; no-op when the index is already empty.
 *
 * subs MUST be cpp SUBs (the sid the JWT carries), NOT emails.
 * Verified live: after reset, POST /ui/syndicates -> 201 (was 400).
 */
export function cppResetUserSyndicates(subs: string[]): void {
  const clean = subs.filter(Boolean);
  if (clean.length === 0) return;
  runCppShim("reset_syndicates.py", { subs: clean });
}

// -- syndicate-advertising treasury (syndicate-advertising.spec.ts) -----------

/** Seed a syndicate treasury BALANCE (additive) into cpp's tlc_syndicate_treasury (moto :5005). */
export function cppSeedSyndicateTreasury(syndicateId: string, cents: number): void {
  runCppShim("seed_syndicate_treasury.py", { syndicate_id: syndicateId, amount_cents: cents });
}
/** Read a syndicate treasury BALANCE (cents) from cpp's tlc_syndicate_treasury. */
export function cppReadSyndicateTreasury(syndicateId: string): number {
  const raw = runCppReadShim("seed_syndicate_treasury.py", { syndicate_id: syndicateId, mode: "read" });
  return parseInt(raw, 10) || 0;
}

// -- group + treasury fixture (group-treasury.spec.ts) ------------------------

export interface CppTreasuryGroupMember {
  sub: string; // cpp SUB (NOT an email)
  role?: "admin" | "moderator" | "member";
  displayName?: string;
}

export interface CppTreasuryGroupOpts {
  groupId: string;
  adminSub: string;
  name?: string;
  description?: string;
  visibility?: "public" | "private";
  members?: CppTreasuryGroupMember[];
  /** treasury WALLET balance in cents. omit => no WALLET row (empty treasury). */
  treasuryCents?: number;
  currency?: string;
  totalContributedCents?: number;
  totalDonatedCents?: number;
  totalSpentCents?: number;
  fundraisingGoalCents?: number;
}

/**
 * Seed one user-group (GROUP#/META + MEMBER# + USERGROUPS# index) into cpp's
 * tlc_user_groups plus an optional treasury WALLET (GROUP#/WALLET) into
 * tlc_billing. Reuses the shared seed_messaging-crm-misc_group.py shim (which
 * writes exactly the rows cpp's ug_require_role + gtr_balance read).
 *
 * adminSub + every member.sub MUST be cpp SUBs.
 */
export function cppSeedTreasuryGroup(opts: CppTreasuryGroupOpts): void {
  const members =
    opts.members && opts.members.length > 0
      ? opts.members.map((m) => ({
          sub: m.sub,
          role: m.role ?? "member",
          display_name: m.displayName ?? "",
        }))
      : [{ sub: opts.adminSub, role: "admin", display_name: opts.name ?? "" }];

  runCppShim("seed_messaging-crm-misc_group.py", {
    group_id: opts.groupId,
    admin_sub: opts.adminSub,
    name: opts.name ?? "E2E Treasury Group",
    description: opts.description ?? "",
    visibility: opts.visibility ?? "public",
    members,
    ...(opts.treasuryCents != null ? { treasury_cents: opts.treasuryCents } : {}),
    ...(opts.currency ? { currency: opts.currency } : {}),
    ...(opts.totalContributedCents != null
      ? { total_contributed_cents: opts.totalContributedCents }
      : {}),
    ...(opts.totalDonatedCents != null
      ? { total_donated_cents: opts.totalDonatedCents }
      : {}),
    ...(opts.totalSpentCents != null
      ? { total_spent_cents: opts.totalSpentCents }
      : {}),
    ...(opts.fundraisingGoalCents != null
      ? { fundraising_goal_cents: opts.fundraisingGoalCents }
      : {}),
  });
}
