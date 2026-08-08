/**
 * cpp-native rate-limit CONFIG seed helper (PLATFORM-001).
 *
 * The Python reference of rate-limiting.spec.ts writes its per-group override to
 * DDB-Local :8001 table `rate_limits`. Under E2E_USE_CPP the cpp middleware reads
 * from tlc_rate_limits in moto :5005, so we mirror the write there via the
 * seed_rate_limits.py shim on .82. Callers gate on usingCpp().
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export function cppSeedRateLimits(
  group: string,
  perUser: number,
  perIp: number,
  windowSec: number,
  bypassRoles: string[] = [],
): void {
  if (!usingCpp()) return;
  runCppShim("seed_rate_limits.py", {
    group,
    window_seconds: windowSec,
    max_requests_per_user: perUser,
    max_requests_per_ip: perIp,
    bypass_roles: bypassRoles,
  });
}

export function cppClearRateLimits(group: string): void {
  if (!usingCpp()) return;
  runCppShim("seed_rate_limits.py", { group, delete: true });
}
