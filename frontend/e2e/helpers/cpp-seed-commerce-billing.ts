/**
 * cpp-aware seeding glue for the COMMERCE-BILLING domain (TRACK: seed).
 *
 * Owns the cpp-seed path for ads/billing/catalog/orders specs. Does NOT edit the
 * shared helpers/cpp-seed.ts (to avoid cross-agent conflicts) — it only reuses
 * that module's `runCppShim` / `usingCpp` primitives.
 *
 * PROBLEM: the inline per-test seeders in the ads specs write to the Python
 * DDB-Local at :8001 (PascalCase tables AdAccounts / AdCampaigns, owner_sub =
 * EMAIL). The C++ backend reads its OWN moto on .82 (tlc_ad_accounts /
 * tlc_ad_campaigns, owner_sub = SUB). So under E2E_USE_CPP those seeds never
 * reach cpp, and — worse — non-terminal ad accounts accumulate across runs and
 * trip the "at most 5 ad accounts" 422 cap (GAP-0039), breaking every ads spec's
 * beforeAll account-create. These wrappers invoke arg-driven shims on .82 so the
 * correctly shaped rows land in cpp's tables (and stale accounts get wiped).
 *
 * The default Python path is untouched: every caller gates on usingCpp().
 */
import { execFileSync } from "child_process";
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

// ── .82 ssh target (mirrors helpers/cpp-seed.ts constants) ───────────────────
const CPP_SSH_HOST = process.env.E2E_CPP_SSH_HOST ?? "sean@192.168.0.82";
const CPP_SSH_KEY =
  process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
const CPP_SHIM_DIR =
  process.env.E2E_CPP_SHIM_DIR ??
  "/home/sean/projects/testlogon-cpp/e2e/seed_shims";

/**
 * Run a READ shim on .82 that prints raw JSON on stdout (not an "ok" line, so
 * runCppShim's ok-check does not apply). base64 the arg for robust transport.
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
      CPP_SSH_HOST,
      `python3 ${CPP_SHIM_DIR}/${shim} --b64 ${b64}`,
    ],
    { timeout: 30_000, encoding: "utf8" },
  ).trim();
}

// ── cpp DDB get_item read-back (TRACK: seed / readback) ──────────────────────
/**
 * Read ONE item from cpp's OWN moto by (PascalCase) table + key. Mirrors the
 * inline ddbGet() in ads-billing.spec but against the tlc_* table cpp actually
 * writes, so post-charge state readbacks (balance_cents / lifetime_spent_cents)
 * reflect cpp's mutation instead of the stale Python DDB-Local row. Returns the
 * parsed item or null. Only meaningful under usingCpp().
 */
export function cppDdbGet(
  table: string,
  key: Record<string, string>,
): Record<string, unknown> | null {
  const raw = runCppReadShim("seed_commerce-billing_get_item.py", { table, key });
  const last = raw.split(/\r?\n/).filter(Boolean).pop() ?? "null";
  return last === "null" ? null : (JSON.parse(last) as Record<string, unknown>);
}

// ── ad-account quota reset (TRACK: harness-reset / GAP-0039) ─────────────────
/**
 * Wipe ALL of one-or-more owners' ad accounts (+ their campaigns + billing
 * ledger rows) in cpp's tlc_ad_accounts / tlc_ad_campaigns / tlc_ad_billing.
 * Mirrors ads-accounts-campaigns.spec's ddbDeleteOwnerAccounts() and ad-fraud's
 * inline cleanup — but keyed by the cpp SUB (NOT the email), against the store
 * cpp actually reads. Call in beforeAll so the account-create paths always have
 * headroom under the 5-account cap. No-op unless usingCpp(). Idempotent.
 *
 * ownerSubs MUST be cpp SUBs (getSession(id).user_sub under cpp), not emails.
 */
export function cppResetOwnerAdAccounts(ownerSubs: string[]): void {
  if (!usingCpp()) return;
  const subs = ownerSubs.filter(Boolean);
  if (subs.length === 0) return;
  runCppShim("seed_commerce-billing_reset_accounts.py", { owner_subs: subs });
}

// ── ad account (+ optional campaign) seed (TRACK: seed) ──────────────────────
export interface CppAdCampaignOpts {
  campaignId: string;
  name?: string;
  objective?: string;
  budgetCents?: number;
  budgetType?: string; // "lifetime" | "daily"
  dailyBudgetCents?: number;
  status?: string; // "active" | "draft" | ...
}

export interface CppAdAccountOpts {
  accountId: string;
  ownerSub: string; // cpp SUB (owner_sub) — NOT an email
  companyName?: string;
  billingEmail?: string;
  status?: string; // "active" | "pending_review" | ...
  balanceCents?: number;
  campaign?: CppAdCampaignOpts;
}

/**
 * Seed ONE advertiser account (+ optional campaign) into cpp's tlc_ad_accounts /
 * tlc_ad_campaigns with the exact item shape cpp's ad_get_account /
 * ad_require_account_owner / ad_get_campaign read. Mirrors ads-billing.spec's
 * ddbPut('AdAccounts'/'AdCampaigns', ...) so /ui/ads/accounts/<id>/{deposit,
 * billing,campaigns} resolve under cpp. owner_sub MUST be the cpp SUB.
 */
export function cppSeedAdAccount(opts: CppAdAccountOpts): void {
  runCppShim("seed_commerce-billing_ad_account.py", {
    account_id: opts.accountId,
    owner_sub: opts.ownerSub,
    ...(opts.companyName ? { company_name: opts.companyName } : {}),
    ...(opts.billingEmail ? { billing_email: opts.billingEmail } : {}),
    status: opts.status ?? "active",
    ...(opts.balanceCents != null ? { balance_cents: opts.balanceCents } : {}),
    ...(opts.campaign
      ? {
          campaign: {
            campaign_id: opts.campaign.campaignId,
            ...(opts.campaign.name ? { name: opts.campaign.name } : {}),
            ...(opts.campaign.objective
              ? { objective: opts.campaign.objective }
              : {}),
            ...(opts.campaign.budgetCents != null
              ? { budget_cents: opts.campaign.budgetCents }
              : {}),
            ...(opts.campaign.budgetType
              ? { budget_type: opts.campaign.budgetType }
              : {}),
            ...(opts.campaign.dailyBudgetCents != null
              ? { daily_budget_cents: opts.campaign.dailyBudgetCents }
              : {}),
            status: opts.campaign.status ?? "active",
          },
        }
      : {}),
  });
}
