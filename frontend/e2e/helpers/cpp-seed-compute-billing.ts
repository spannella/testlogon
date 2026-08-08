/**
 * cpp-aware seeding glue for the compute-billing domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): compute-billing.spec.ts's
 * seedBillingTick()/seedMonthlyTotal()/seedWalletBalance() write TICK#/MONTH#/
 * WALLET rows into the Python DDB-Local :8001 tables cpp never reads. cpp reads
 * its OWN tlc_compute_billing (moto :5005) and — critically — the
 * /ui/remote/billing/{resources,history} reads use the ByMonth/ByResource GSIs
 * (gsi_month_pk/gsi_resource_pk) which the Python seed never sets. So under
 * E2E_USE_CPP the per-resource breakdown + history come back empty.
 *
 * FIX: when targeting cpp, invoke seed_compute_billing.py on .82 to write the
 * FULL cpp tick shape (incl. the GSI keys) + the MONTH# total, and reuse
 * seed_wallet.py for the wallet. userSub MUST be the cpp SUB. The default Python
 * path is left byte-identical (callers gate on usingCpp()).
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

export interface CppBillingTickOpts {
  resourceType: string;
  resourceId: string;
  resourceLabel: string;
  instanceType: string;
  amountCents: number;
  durationMinutes: number;
  rateCentsPerMin: number;
  createdAt: number;
  monthKey: string;
  entryId: string;
}

/** Seed ONE compute-billing TICK# row (with GSI keys) into cpp. */
export function cppSeedBillingTick(userSub: string, o: CppBillingTickOpts): void {
  runCppShim("seed_compute_billing.py", {
    op: "tick",
    user_sub: userSub,
    resource_type: o.resourceType,
    resource_id: o.resourceId,
    resource_label: o.resourceLabel,
    instance_type_or_preset: o.instanceType,
    amount_cents: o.amountCents,
    duration_minutes: o.durationMinutes,
    rate_cents_per_min: o.rateCentsPerMin,
    created_at: o.createdAt,
    month_key: o.monthKey,
    entry_id: o.entryId,
  });
}

/** Seed the MONTH# running total for a user into cpp. */
export function cppSeedMonthlyTotal(userSub: string, monthKey: string, totalCents: number): void {
  runCppShim("seed_compute_billing.py", {
    op: "month",
    user_sub: userSub,
    month_key: monthKey,
    total_cents: totalCents,
  });
}

/** Top up the WALLET row for a user in cpp (reuses seed_wallet.py). */
export function cppSeedComputeWallet(userSub: string, balanceCents: number): void {
  runCppShim("seed_wallet.py", { user_sub: userSub, cents: balanceCents });
}
