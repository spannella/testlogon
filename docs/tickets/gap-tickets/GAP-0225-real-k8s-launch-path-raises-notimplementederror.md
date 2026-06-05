# GAP-0225: Real K8s launch path raises `NotImplementedError`

**Status**: Open · **Severity**: HIGH (High) · **Source ticket**: INFRA-004 · **Effort**: L
**From**: gap audit (`docs/tickets/gaps/INFRA-004.md`); see also `docs/tickets/writeups/INFRA-004.md`

## Location
`NotImplementedError`

## Problem / Impact
when `S.k8s_mock_enabled = False` (production mode), `launch_pod()` hits `raise NotImplementedError("Real K8s launch not implemented yet")`; `get_pod_logs()` also raises at line 257; no real Kubernetes Python client is integrated

## Fix
add `kubernetes` client to dependencies; implement `_real_k8s_launch()` using `kubernetes.client.CoreV1Api().create_namespaced_pod()`; implement real log fetch via `kubernetes.client.CoreV1Api().read_namespaced_pod_log()`

## Notes
This gap was identified by the second-pass as-built review of INFRA-004. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
