/**
 * cpp-aware seeding glue for the fraud-detection domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): fraud-detection.spec.ts's
 * seedFlag()/seedChargebackCount()/seedVelocityLedger() write FLAG#/RISK# rows
 * into the Python DDB-Local :8001 'fraud_detection' table cpp never reads. cpp
 * reads its OWN tlc_fraud_cases (moto :5005), identical key/GSI shape — so under
 * E2E_USE_CPP the seeded flags/risk are invisible and the /v1/admin/fraud/queue
 * + review + chargebacks endpoints see nothing.
 *
 * FIX: when targeting cpp, invoke seed_fraud_case.py on .82 so the SAME rows land
 * in cpp's tlc_fraud_cases. The default Python path is left byte-identical
 * (callers gate on usingCpp()).
 *
 * SCOPE NOTE: tests that drive app.services.fraud_detection in-process (velocity
 * evaluate_transaction, is_frozen hook) are Python-only and NOT convertible;
 * this shim only makes the DDB-backed seed data visible to cpp.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

/** Seed ONE FLAG#<id> row into cpp's tlc_fraud_cases (pending/approved/...). */
export function cppSeedFraudFlag(flagId: string, userId: string, status: string): void {
  runCppShim("seed_fraud_case.py", { op: "flag", flag_id: flagId, user_id: userId, status });
}

/** Seed a RISK#USER#<id> SCORE row with a prior chargeback count into cpp. */
export function cppSeedFraudChargebackCount(userId: string, count: number): void {
  runCppShim("seed_fraud_case.py", { op: "risk", user_id: userId, chargeback_count: count });
}

/** Seed a RISK#USER#<id> SCORE row with a high 24h tx velocity into cpp. */
export function cppSeedFraudVelocityRisk(userId: string): void {
  runCppShim("seed_fraud_case.py", {
    op: "risk",
    user_id: userId,
    tx_count_24h: 600,
    tx_total_24h: 60000,
  });
}

// ── ad-fraud VEL#/IP# counters (tlc_ad_fraud_events) ─────────────────────────
/**
 * Pre-seed the click-velocity + IP-clustering fraud counters ABOVE threshold in
 * cpp's tlc_ad_fraud_events so the next tracked event for (userSub, creativeId,
 * ip) trips velocity (+25) + ip clustering (+25). Mirrors ad-fraud.spec.ts's
 * seedFraudCounters(), whose Python :8001 AdFraudEvents writes never reach cpp.
 *
 * CRITICAL: cpp keys the velocity counter by the JWT sub, so userSub MUST be the
 * resolved sub (resolveIdentityId(bob)->sub), NOT the email.
 */
export function cppSeedAdFraudCounters(userSub: string, creativeId: string, ip: string): void {
  runCppShim("seed_ad_fraud_counters.py", {
    user_sub: userSub,
    creative_id: creativeId,
    ip,
    count: 99,
  });
}
