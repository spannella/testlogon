/**
 * cpp-aware seeding glue for the payment-provider-health domain (TRACK: seed).
 *
 * PROBLEM (shared with helpers/cpp-seed.ts): payment-provider-health.spec.ts's
 * seedHealthData() writes DP#/INCIDENT# rows into the Python DDB-Local :8001
 * 'payment_provider_health' table cpp never reads. cpp reads its OWN
 * tlc_payment_provider_health (moto :5005) with the identical key/GSI shape — so
 * under E2E_USE_CPP the seeded datapoints/incidents are invisible and the
 * status / timeline / errors / uptime / incidents endpoints come back
 * empty/default.
 *
 * FIX: when targeting cpp, invoke seed_payment_provider_health.py on .82 so the
 * SAME canonical fixture (stripe healthy, paypal degraded, stripe incidents)
 * lands in cpp's table. The rows are global admin data — no per-user SUB. The
 * default Python path is left byte-identical (callers gate on usingCpp()).
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

/** Seed the canonical payment-provider-health fixture into cpp. */
export function cppSeedPaymentHealth(): void {
  runCppShim("seed_payment_provider_health.py", {});
}
