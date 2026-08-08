/**
 * cpp-aware reset glue for admin-compute.spec.ts (TRACK: seed).
 *
 * PROBLEM: clearQuota() deletes from the Python 'compute_quotas' table (:8001);
 * cpp stores the quota in tlc_compute_quotas keyed by the admin URL-path value
 * (the ALICE_ID EMAIL). Under cpp a prior run's custom quota survives, so the
 * "default quota" test sees is_custom=true and the quota=0 launch test is
 * poisoned. This wrapper deletes the row from cpp's own moto.
 *
 * Reuses the shared cpp-seed.ts runCppShim primitive. No-op off the cpp path.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

const SHIM = "reset_compute_quota.py";

/** Delete a user's compute-quota row in cpp's moto. `key` MUST match the value
 *  the spec puts in the admin quota URL path (the ALICE_ID email). No-op unless
 *  usingCpp(). */
export function cppClearComputeQuota(key: string): void {
  if (!usingCpp()) return;
  runCppShim(SHIM, { user_sub: key });
}

const INSTANCES_SHIM = "reset_compute_instances.py";
const PODS_SHIM = "reset_compute_pods.py";

/** Terminate a user's active compute instances in cpp's moto so the per-user
 *  EC2 launch quota (RMT_EC2_MAX=5 active) has headroom. Prior runs accumulate
 *  running instances that otherwise 409 a fresh launch. No-op unless usingCpp(). */
export function cppResetUserInstances(userSub: string): void {
  if (!usingCpp()) return;
  runCppShim(INSTANCES_SHIM, { user_sub: userSub });
}

/** Terminate a user's active compute pods in cpp's moto so the per-user k8s
 *  launch quota (RMT_K8S_MAX=5 active) has headroom. No-op unless usingCpp(). */
export function cppResetUserPods(userSub: string): void {
  if (!usingCpp()) return;
  runCppShim(PODS_SHIM, { user_sub: userSub });
}
