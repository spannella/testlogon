/**
 * cpp-aware seeding glue for the platform-financial-dashboard domain
 * (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): platform-financial-dashboard.spec's
 * seedLedger() writes billing-ledger rows into a Python DDB-Local at :8001
 * (table 'billing'). The C++ backend reads its OWN store — moto :5005 on .82,
 * table tlc_billing — so under E2E_USE_CPP the seeded rows are invisible and the
 * /ui/admin/financial-dashboard/{kpis,trends,providers,types,top-creators,
 * export/csv} aggregates come back empty.
 *
 * FIX: when targeting cpp, invoke seed_platform_financial_ledger.py on .82 over
 * ssh so the SAME 7-row FIN-013 fixture lands in cpp's tlc_billing. The default
 * Python path is left byte-identical (callers gate on usingCpp()).
 *
 * The ledger rows are keyed by fixed payer ids (payer1/payer2/…) and the
 * dashboard is admin-global, so no per-user SUB resolution is needed.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

/**
 * Seed the canonical FIN-013 billing-ledger fixture into cpp's tlc_billing.
 * seedDate/reason mirror the spec's SEED_DATE / RUN_TAG so ledger_date lands in
 * the [RANGE_START, RANGE_END] window.
 */
export function cppSeedFinancialLedger(seedDate: string, reason: string): void {
  runCppShim("seed_platform_financial_ledger.py", {
    seed_date: seedDate,
    reason,
  });
}
