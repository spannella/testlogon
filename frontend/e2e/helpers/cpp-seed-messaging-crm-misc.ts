/**
 * cpp-aware seeding glue for the messaging-crm-misc domain (TRACK: seed).
 *
 * OWNS ONLY this domain's cpp-seed wrappers so it never conflicts with the
 * shared helpers/cpp-seed.ts. Re-uses runCppShim / usingCpp from that module.
 *
 * PROBLEM this solves: several specs in this domain seed fixtures into the
 * Python DDB-Local at :8001 (user_groups + billing treasury for group
 * fundraising; billing WALLET / AdAccounts / post for sponsorship deals). The
 * C++ backend reads its OWN moto (:5005) with tlc_* tables + cpp item shapes,
 * so under E2E_USE_CPP those seeds are invisible and the group is not found /
 * the caller is "Not a member" / the treasury reads $0. These wrappers invoke
 * arg-driven shims on .82 so ONE correctly-shaped row lands in cpp's tables.
 *
 * The default Python path is untouched: callers gate every wrapper on
 * usingCpp().
 *
 * WHICH SEEDS ACTUALLY MATTER UNDER CPP (verified against live handlers):
 *  - group-fundraising: the GROUP (META + MEMBER# for the caller) AND the
 *    treasury WALLET are BOTH required — cpp's ug_require_role/gtr_balance read
 *    them. cppSeedGroup() covers both. (HIGH reclaim.)
 *  - sponsorship-deals: cpp's propose only needs the ADVERTISER WALLET funded
 *    (escrow debit); it does NOT read the AdAccount, and submit-content does
 *    NOT verify post ownership. So only cppSeedWallet (re-exported) is
 *    load-bearing; the AdAccount/post seeds are cpp no-ops (kept Python-only).
 */
import { execFileSync } from "child_process";
import { runCppShim, usingCpp, cppSeedWallet } from "./cpp-seed";

export { usingCpp, cppSeedWallet };

// ── .82 ssh target (mirrors helpers/cpp-seed.ts constants) ────────────────────
const CPP_SSH_HOST = process.env.E2E_CPP_SSH_HOST ?? "sean@192.168.0.82";
const CPP_SSH_KEY =
  process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
const CPP_SHIM_DIR =
  process.env.E2E_CPP_SHIM_DIR ??
  "/home/sean/projects/testlogon-cpp/e2e/seed_shims";

/**
 * Run a READ shim on .82 that prints a raw value (no 'ok' contract). Returns the
 * trimmed stdout. Used by cppReadTreasuryBalance where the caller needs the
 * numeric result, not a confirmation line.
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
 * Read one group's treasury WALLET balance (cents) from cpp's tlc_billing.
 * Mirrors group-fundraising.spec.ts getTreasuryBalance() for the cpp store.
 */
export function cppReadTreasuryBalance(groupId: string): number {
  const raw = runCppReadShim("read_group_treasury.py", { group_id: groupId });
  return parseInt(raw, 10) || 0;
}

// ── group + treasury fixture ─────────────────────────────────────────────────
export interface CppGroupMember {
  sub: string; // cpp SUB (NOT an email)
  role?: "admin" | "moderator" | "member";
  status?: string; // default "active"
  displayName?: string;
}

export interface CppGroupOpts {
  groupId: string;
  adminSub: string; // cpp SUB of the group admin
  name?: string;
  description?: string;
  visibility?: "public" | "private";
  status?: string; // default "active"
  topic?: string;
  members?: CppGroupMember[]; // defaults to [admin as admin]
  /** treasury WALLET balance in cents. omit/undefined => no WALLET row. */
  treasuryCents?: number;
  currency?: string;
  fundraisingGoalCents?: number;
}

/**
 * Seed one user-group (GROUP#/META + MEMBER# + USERGROUPS# index) into cpp's
 * tlc_user_groups, plus an optional treasury WALLET (GROUP#/WALLET) into
 * tlc_billing. adminSub + every member.sub MUST be cpp SUBs.
 *
 * Verified live: after this seed, GET /ui/groups/{id}/treasury returns the
 * funded balance and POST /ui/groups/fundraising/{id}/campaigns succeeds
 * (member gate passes, budget reserved).
 */
export function cppSeedGroup(opts: CppGroupOpts): void {
  const members =
    opts.members && opts.members.length > 0
      ? opts.members.map((m) => ({
          sub: m.sub,
          role: m.role ?? "member",
          ...(m.status ? { status: m.status } : {}),
          display_name: m.displayName ?? "",
        }))
      : [
          {
            sub: opts.adminSub,
            role: "admin",
            display_name: opts.name ?? "",
          },
        ];

  runCppShim("seed_messaging-crm-misc_group.py", {
    group_id: opts.groupId,
    admin_sub: opts.adminSub,
    name: opts.name ?? "E2E Group",
    description: opts.description ?? "",
    visibility: opts.visibility ?? "public",
    ...(opts.status ? { status: opts.status } : {}),
    ...(opts.topic ? { topic: opts.topic } : {}),
    members,
    ...(opts.treasuryCents != null ? { treasury_cents: opts.treasuryCents } : {}),
    ...(opts.currency ? { currency: opts.currency } : {}),
    ...(opts.fundraisingGoalCents != null
      ? { fundraising_goal_cents: opts.fundraisingGoalCents }
      : {}),
  });
}
