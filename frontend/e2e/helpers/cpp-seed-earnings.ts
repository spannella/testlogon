/**
 * cpp-aware seeding glue for the creator-earnings domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): creator-earnings.spec.ts's
 * seedLedgerCredits() / cleanupLedgerCredits() write & delete type='credit'
 * LEDGER rows keyed by pk=USER#<email> in the Python DDB-Local :8001 'billing'
 * table cpp never reads. So under E2E_USE_CPP the /ui/earnings/{summary,
 * transactions,quick-stats} endpoints (which scan cpp's tlc_billing keyed by the
 * cpp SUB) never see the seeded credits — time-range totals and pagination fail.
 *
 * FIX: when targeting cpp, invoke seed_earnings_credits.py /
 * delete_earnings_credits.py on .82 so the SAME credits land in cpp's
 * tlc_billing keyed by the cpp SUB (resolved here from loadSessions()). The
 * default Python path is left byte-identical (callers gate on usingCpp()).
 */
import { runCppShim, usingCpp } from "./cpp-seed";
import { loadSessions } from "./session";

export { usingCpp };

/** Resolve a cpp SUB from an email (or pass through if already a sub). */
function resolveSub(emailOrSub: string): string {
  const sessions = loadSessions();
  return sessions[emailOrSub]?.user_sub ?? emailOrSub;
}

/** Seed type='credit' LEDGER rows into cpp's tlc_billing under the cpp SUB. */
export function cppSeedEarningsCredits(
  emailOrSub: string,
  entries: Array<{ reason: string; amount_cents: number }>,
  testRun: string,
): void {
  runCppShim("seed_earnings_credits.py", {
    user_sub: resolveSub(emailOrSub),
    test_run: testRun,
    entries,
  });
}

/** Delete this run's seeded credits (meta.test_run==testRun) from cpp. */
export function cppCleanupEarningsCredits(emailOrSub: string, testRun: string): void {
  try {
    runCppShim("delete_earnings_credits.py", {
      user_sub: resolveSub(emailOrSub),
      test_run: testRun,
    });
  } catch {
    /* best-effort */
  }
}
