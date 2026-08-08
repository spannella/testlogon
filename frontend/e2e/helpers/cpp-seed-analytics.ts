/**
 * cpp-aware seeding glue for the analytics domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): analytics.spec.ts's seedRollupRow()
 * and seedSummarySentinel() write creator rollup rows (pk=CREATOR#<sub>,
 * sk=DAILY#<date> | SUMMARY) into a Python DDB-Local :8001 'AnalyticsRollups'
 * table the C++ backend never reads. So under E2E_USE_CPP the
 * /ui/analytics/{overview,revenue,timeseries,top-content,audience,subscribers}
 * endpoints aggregate over an empty store.
 *
 * FIX: when targeting cpp, invoke the shims on .82 so the SAME rows land in
 * cpp's tlc_analytics_rollups (moto :5005), keyed by the cpp SUB. Daily rows
 * reuse the shared seed_generic-ddbRequest_analytics_rollups.py shim; the
 * SUMMARY sentinel uses seed_analytics_summary.py. The default Python path is
 * left byte-identical (callers gate on usingCpp()).
 *
 * IMPORTANT — cpp identity is SUB-based: userSub MUST be the cpp SUB
 * (sessions[key].user_sub), NOT the email.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

/** Seed ONE daily rollup row (pk=CREATOR#<sub>, sk=DAILY#<date>) into cpp. */
export function cppSeedAnalyticsRollup(
  userSub: string,
  dateStr: string,
  data: Record<string, unknown>,
): void {
  runCppShim("seed_generic-ddbRequest_analytics_rollups.py", {
    rows: [{ user_sub: userSub, date: dateStr, data }],
  });
}

/** Seed the SUMMARY sentinel (pk=CREATOR#<sub>, sk=SUMMARY) into cpp. */
export function cppSeedAnalyticsSummary(
  userSub: string,
  data: Record<string, unknown>,
): void {
  runCppShim("seed_analytics_summary.py", { user_sub: userSub, data });
}
