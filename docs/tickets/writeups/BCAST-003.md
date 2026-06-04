# BCAST-003: AWS MediaLive Start/Stop Execution — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-003 called for wiring the four stubbed `AwsBroadcastProvider` methods — `start()`, `stop()`, `status()`, `teardown()` — to real AWS MediaLive and MediaPackage API calls with polling, idempotency, and error classification. The ticket was written when those methods returned hard-coded `{"mode": "stub"}` results. All four methods have since been fully implemented.

- **Type**: Infrastructure / feature (AWS execution layer)
- **Priority**: High (business-critical: without real stop/teardown, AWS costs accumulate indefinitely)
- **Status**: Implemented — no stub code remains; all four methods are production-ready
- **Persona**: Platform infrastructure; transparent to end users
- **Cross-references**: BCAST-001 (session lifecycle drives the orchestrator), BCAST-004 (reconciler status polling uses `status()` for real drift detection), SECOPS-007 (dev/prod parity is the central concern of this ticket)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Provider architecture

`app/services/broadcast_provider.py` implements a `BroadcastProvider` Protocol at line 40 with five operations: `provision`, `start`, `stop`, `status`, `teardown`. Two concrete implementations:

- `LocalBroadcastProvider` (`broadcast_provider.py:57–82`) — instant synthetic responses; no AWS calls; used when `BROADCAST_PROVIDER=local` (the dev default)
- `AwsBroadcastProvider` (`broadcast_provider.py:200–466`) — real AWS MediaLive + MediaPackage API calls; used when `BROADCAST_PROVIDER=aws`

`get_broadcast_provider()` at `broadcast_provider.py:469–474` is the factory; the orchestrator calls it via `get_broadcast_provider()` at `broadcast_orchestrator.py:25` (and lines 133, 179). Same factory, same code path in dev and prod.

### 2.2 What is already implemented (provisioning)

`AwsBroadcastProvider.provision` at `broadcast_provider.py:203–242` delegates to:
- `provision_mediolive_input_and_channel()` in `app/services/broadcast_mediolive.py` — creates RTMP_PUSH input + MediaLive channel with `_with_retry()` exponential backoff
- `provision_mediapackage_channel_and_endpoint()` in `app/services/broadcast_mediapackage.py` — creates MediaPackage channel + HLS origin endpoint with optional SPEKE DRM

Both are idempotent (`_find_input_by_name` / `_find_channel_by_name` guards).

### 2.3 `AwsBroadcastProvider.start()` — implemented at lines 244–298

```python
def start(self, session, *, correlation_id="", idempotency_key="") -> ProviderResult:
    client = _medialive_client()
    channel_id = _resolve_channel_id(session)
    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_state = desc.get("State", "IDLE")
    if current_state == "RUNNING":
        return ProviderResult("start", self.name, "live", {"already_running": True, ...})
    if current_state not in ("IDLE", "CREATE_FAILED"):
        return ProviderResult("start", self.name, "error", {"error": f"channel in non-startable state: {current_state}", ...})
    _with_retry(lambda: client.start_channel(ChannelId=channel_id))
    timeout = int(S.broadcast_aws_start_timeout_seconds or 120)
    poll_interval = int(S.broadcast_aws_poll_interval_seconds or 5)
    state = _poll_channel_state(client, channel_id, target_states={"RUNNING"}, error_states={"CREATE_FAILED", "IDLE"}, timeout_seconds=timeout, poll_interval_seconds=poll_interval)
    if state == "RUNNING":
        return ProviderResult("start", self.name, "live", {"started_at": _now_iso(), ...})
    else:
        return ProviderResult("start", self.name, "error", {"error": f"channel did not reach RUNNING...", ...})
```

No stub code. Uses configurable timeouts from `S.broadcast_aws_start_timeout_seconds` (line 524 in `settings.py`, default 120s).

### 2.4 `AwsBroadcastProvider.stop()` — implemented at lines 301–353

Mirrors start: describes current state, short-circuits on `IDLE` (already stopped), rejects non-stoppable states (`current_state not in ("RUNNING", "RECOVERING")`), calls `stop_channel`, polls until `IDLE` using `S.broadcast_aws_stop_timeout_seconds` (settings.py:525, default 120s).

### 2.5 `AwsBroadcastProvider.status()` — implemented at lines 355–379

Calls `describe_channel`, maps AWS channel states to platform statuses via `_MEDIALIVE_STATE_MAP` at lines 101–112:

```python
_MEDIALIVE_STATE_MAP: Dict[str, str] = {
    "CREATING": "provisioning",
    "CREATE_FAILED": "error",
    "IDLE": "ready",
    "STARTING": "ready",
    "RUNNING": "live",
    "STOPPING": "stopping",
    "DELETING": "stopping",
    "DELETED": "stopped",
    "RECOVERING": "live",
    "UPDATE_FAILED": "error",
}
```

`NotFoundException` from AWS is caught and returned as `state="error"` with `error="channel_not_found"` — the reconciler treats this as drift.

### 2.6 `AwsBroadcastProvider.teardown()` — implemented at lines 381–466

Five-phase deletion in dependency order:
1. Stop channel if RUNNING/RECOVERING (stop + poll to IDLE)
2. Delete MediaLive channel
3. Wait for input to DETACH (`_poll_input_state`), then delete input
4. Delete MediaPackage origin endpoint (`broadcast-{session_id}-hls`)
5. Delete MediaPackage channel (`broadcast-{session_id}-pkg`)

Each step catches `NotFoundException` silently (already deleted = idempotent). Other `ClientError` codes are appended to `errors: list[str]`. Partial failures return `ProviderResult("teardown", "aws", "error", {"partial_errors": errors, "resources_may_remain": True})` rather than raising — the orchestrator logs the warning and proceeds with DDB cleanup.

### 2.7 Polling helpers

`_poll_channel_state` at `broadcast_provider.py:115–135`:
```python
def _poll_channel_state(client, channel_id, *, target_states, error_states, timeout_seconds=120, poll_interval_seconds=5.0) -> str:
    deadline = time.monotonic() + timeout_seconds
    last_state = "UNKNOWN"
    while time.monotonic() < deadline:
        desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
        last_state = desc.get("State", "UNKNOWN")
        if last_state in target_states or last_state in error_states:
            return last_state
        time.sleep(poll_interval_seconds)
    return last_state
```

`_poll_input_state` at `broadcast_provider.py:138–163` — similar pattern for input DETACH waiting.

### 2.8 Channel ID resolution

`_resolve_channel_id(session)` extracts the channel ID first from `output.provider_state_snapshot["details"]["channel_id"]` (set at provision time), then falls back to parsing the `aws_channel_arn` (format: `arn:aws:medialive:REGION:ACCOUNT:channel:CHANNEL_ID`). Raises HTTP 409 if neither is available.

### 2.9 Settings

`app/core/settings.py:524–526`:
```python
broadcast_aws_start_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_START_TIMEOUT_SECONDS", "120"))
broadcast_aws_stop_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_STOP_TIMEOUT_SECONDS", "120"))
broadcast_aws_poll_interval_seconds: int = int(os.environ.get("BROADCAST_AWS_POLL_INTERVAL_SECONDS", "5"))
```

Note: `broadcast_aws_teardown_timeout_seconds` is **not defined** in settings.py. The teardown stop-before-delete poll hard-codes 90 seconds (line 400). This is the only outstanding gap.

### 2.10 Orchestrator integration

`broadcast_orchestrator.py:17–122` (`start_session_with_provider`):
- Calls `provider.provision()` for `draft`/`scheduled` sessions → transitions to `ready`
- Then calls `provider.start()` → transitions to `live`
- On AWS path (`provider.name == "aws"` at line 103): calls `mint_cloudfront_signed_playback_url` and stores the CloudFront URL in `BroadcastOutputs`
- On local path: calls `mint_local_playback_url(current.id)` at line 110

`stop_session_with_provider` at lines 125–175: transitions to `stopping`, calls `provider.stop()`, transitions to `stopped`.

The reconciler at `app/services/broadcast_reconciler.py` calls `provider.status()` every `S.broadcast_reconciler_interval_seconds` (default 30s). Because `status()` now returns real MediaLive state (not an echo of DDB status), actual drift is detected.

### 2.11 Dev vs Prod parity (SECOPS-007)

This ticket is the canonical SECOPS-007 example:

| Mode | BROADCAST_PROVIDER | Provider class | AWS calls made |
|------|-------------------|---------------|----------------|
| Dev (`DEV_MODE=1`) | `local` (default) | `LocalBroadcastProvider` | None — instant synthetic responses |
| Prod | `aws` | `AwsBroadcastProvider` | Real MediaLive/MediaPackage API calls |

Selection occurs in `get_broadcast_provider()` at line 469. No `if dev:` branches in the orchestrator or router — only the provider differs. The `LocalBroadcastProvider.provision/start/stop/teardown` methods at lines 57–82 return synthetic `ProviderResult` objects with the correct state and no polling delays, making the dev stack instant (no 30–120s waits) and fully offline. All pytest and Playwright tests run with `BROADCAST_PROVIDER=local` and zero AWS credentials.

---

## 3. Gap / Threat Analysis

### 3.1 Missing `broadcast_aws_teardown_timeout_seconds` setting

The teardown hard-codes `timeout_seconds=90` at `broadcast_provider.py:400`. Per the established settings pattern (start: 120s, stop: 120s, poll: 5s all configurable), teardown should also be configurable. Omission means operators cannot tune teardown timeout for large channels or slow regions.

### 3.2 Reconciler logging gap

`broadcast_reconciler.py` detects drift when `actual_state != desired_state` but does not emit a structured log line. The ticket proposed adding `logger.warning("drift detected", extra={...})`. This is still absent; drift incidents emit a counter via `record_broadcast_drift_incident` in `metrics.py` but no log correlation ID is attached, making CloudWatch/grep debugging slow.

### 3.3 `_with_retry` transient codes coverage

The `_TRANSIENT_CODES` set in `broadcast_provider.py` covers `ThrottlingException`, `ServiceUnavailableException`, `InternalError` but not `RequestLimitExceeded` (a distinct MediaLive throttle code different from the generic `ThrottlingException`). In busy accounts, `RequestLimitExceeded` can appear during batch provision events.

### 3.4 Stop timeout discrepancy

`broadcast_aws_stop_timeout_seconds` defaults to 120s (settings.py:525), but the ticket specified 90s for stop. The hard-coded teardown stop also uses 90s. The inconsistency (120s configurable vs 90s hard-coded) should be unified behind the configurable setting.

---

## 4. Proposed Design / Fix

### 4.1 Add `broadcast_aws_teardown_timeout_seconds`

`app/core/settings.py`:
```python
broadcast_aws_teardown_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_TEARDOWN_TIMEOUT_SECONDS", "180"))
```

In `AwsBroadcastProvider.teardown` at line 400, replace hard-coded `90` with:
```python
teardown_timeout = int(S.broadcast_aws_teardown_timeout_seconds or 180)
_poll_channel_state(ml_client, channel_id, target_states={"IDLE"}, error_states=set(), timeout_seconds=teardown_timeout, poll_interval_seconds=poll_interval)
```

### 4.2 Structured reconciler drift log

In `app/services/broadcast_reconciler.py`, add a `logger` and emit on drift detection:
```python
import logging
_log = logging.getLogger("broadcast.reconciler")
# ... in drift detection block:
_log.warning(
    "broadcast_drift_detected",
    extra={"session_id": session.id, "desired": desired_state, "actual": actual_state,
           "drift_age_seconds": drift_age, "provider": provider.name}
)
```

### 4.3 `RequestLimitExceeded` in `_TRANSIENT_CODES`

In `broadcast_provider.py`, add `"RequestLimitExceeded"` to the `_TRANSIENT_CODES` set used by `_with_retry`.

### 4.4 Dev/Prod parity maintenance

No changes to SECOPS-007 parity are needed — the architecture is already correct. New settings at 4.1 get dev defaults (`BROADCAST_AWS_TEARDOWN_TIMEOUT_SECONDS=180`); `.env.local.example` should document this. Integration tests for `AwsBroadcastProvider` run with moto's MediaLive mock (not real AWS); pytest suite stays offline.

### 4.5 Alternatives considered

An alternative to synchronous polling in `start()`/`stop()` is to return immediately with `state="provisioning"` and rely on the reconciler to observe the final state. This avoids blocking the HTTP request for up to 120 seconds. However, it requires the orchestrator to be restructured as an async state machine driven by the reconciler rather than a synchronous call chain — a much larger change. The current design keeps the orchestrator simple and is acceptable given that `start()`/`stop()` are called from `202 ACCEPTED` endpoints that the frontend polls.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (offline, moto)

**File**: `tests/test_broadcast_medialive_ops.py`

| Test | Description |
|------|-------------|
| `test_start_channel_idle_to_running` | moto mock returns RUNNING after start; `result.state == "live"` |
| `test_start_channel_already_running` | `already_running=True` in details; no `start_channel` boto3 call |
| `test_start_channel_timeout` | mock always returns STARTING; result state `"error"` after timeout |
| `test_stop_channel_running_to_idle` | moto stop returns IDLE; `result.state == "stopped"` |
| `test_stop_channel_already_idle` | `already_stopped=True`; no `stop_channel` call |
| `test_status_maps_running_to_live` | `describe_channel` returns `State=RUNNING`; mapped to `"live"` |
| `test_status_maps_idle_to_ready` | `State=IDLE` → `"ready"` |
| `test_status_not_found` | `NotFoundException` → `state="error"`, `error="channel_not_found"` |
| `test_teardown_full_cleanup` | All five delete calls are made; `resources_cleaned=True` |
| `test_teardown_partial_failure` | One delete raises non-NotFound; `partial_errors` in result |
| `test_retry_on_throttling` | Mock raises `ThrottlingException` twice then succeeds; result is success |
| `test_retry_on_request_limit_exceeded` | After fix 4.3: `RequestLimitExceeded` is retried |
| `test_teardown_timeout_configurable` | Mock patch `S.broadcast_aws_teardown_timeout_seconds=10`; timeout respected |

All tests use `@mock_aws` / `moto.mock_medialive()`. No real AWS credentials.

### 5.2 Integration tests (staging AWS — nightly CI only)

1. Full lifecycle: `provision → start (poll RUNNING) → stop (poll IDLE) → teardown (verify no channel/input in MediaLive console)`
2. Drift detection: start channel, manually `stop_channel` via AWS CLI, wait 30s reconciler cycle, verify DDB transitions session to `error`
3. Idempotent teardown: call teardown twice; second call returns success (NotFoundException caught silently)

These run only in the `integration` CI profile with `AWS_ACCESS_KEY_ID` set; skipped in `just test` / `just e2e`.

### 5.3 Playwright E2E tests

`frontend/e2e/broadcast.spec.ts` section 2 (session lifecycle) already covers start/stop via `BROADCAST_PROVIDER=local`. Add:

**Section 12 (AWS error surface — `BROADCAST_PROVIDER=local` with simulated errors)**:
- `12.1` After SEC-025 fix, start failure (provider returns `state="error"`) → session card shows error badge
- `12.2` Stop timeout (mock provider hangs 2s) → session transitions to stopped via reconciler
- `12.3` Teardown with partial error → DELETE returns 200 with `partial_errors` in body

Use `/internal/broadcast/simulate-failure` dev endpoint (if it exists) or mock provider injection via Playwright `page.route`.

### 5.4 Manual QA (staging)

1. Deploy with `BROADCAST_PROVIDER=aws` in staging
2. Create profile → create session → start → verify MediaLive console shows RUNNING
3. Stop → verify MediaLive shows IDLE within 120s
4. Delete → verify channel, input, MediaPackage endpoint are removed from AWS console
5. Simulate orphan: manually `stop_channel` in AWS console, wait 30s, verify reconciler log shows `broadcast_drift_detected` warning

### 5.5 Observability

`app/metrics.py` already defines `broadcast_session_actions_total` (labels: `provider`, `action`, `result`) and `broadcast_drift_incidents_total`. After fix 4.2, reconciler warnings are emitted as structured JSON to CloudWatch. Add a CloudWatch alarm: `broadcast_drift_incidents_total > 0` → PagerDuty alert.

### 5.6 Rollout

1. Deploy with `BROADCAST_PROVIDER=local` (no behavior change, only code landed)
2. Run integration test suite against staging AWS
3. Switch staging to `BROADCAST_PROVIDER=aws`; monitor for 48h
4. Roll to production; keep `BROADCAST_PROVIDER=local` until verified
5. Rollback: set `BROADCAST_PROVIDER=local` in env → instant fallback to mock provider

### 5.7 Effort estimate

- `broadcast_aws_teardown_timeout_seconds` setting: **XS** (15 minutes)
- Reconciler drift log: **XS** (30 minutes)
- `RequestLimitExceeded` in retry codes: **XS** (5 minutes)
- Unit tests for new gaps: **S** (2 hours)
- Integration test coordination with staging: **M** (coordination overhead)

### 5.8 Open questions

1. **MediaLive input security group management**: `provision_mediolive_input_and_channel` creates an RTMP_PUSH input. MediaLive requires at least one InputSecurityGroup attached that permits the broadcaster's IP. The current code uses a static security group referenced by ARN from `S.broadcast_medialive_input_security_group_arn`. If this setting is empty in dev, provisioning silently uses a permissive catch-all. Prod deployments must have a correctly scoped ISG; document this as a prod-readiness requirement alongside the teardown timeout.

2. **Channel deletion timing and billing**: AWS MediaLive bills at second granularity while the channel is in `RUNNING` or `STARTING` state. The `teardown()` implementation stops the channel before deletion, which is correct. However, if `teardown()` is called while the channel is in `STOPPING`, the code's error-state guard (`if desc.get("State") in ("RUNNING", "RECOVERING")`) skips the stop call and proceeds to delete — but `delete_channel` on a `STOPPING` channel returns `ConflictException` (not `NotFoundException`). This `ConflictException` will be caught by the generic `ClientError` handler and added to `errors`, resulting in a partial failure. The teardown should also handle `STOPPING` by polling until `IDLE` before attempting deletion.

3. **Output model `aws_channel_id` field**: The ticket proposed adding `aws_channel_id` as a first-class field on `BroadcastOutputModel` to avoid ARN parsing in `_resolve_channel_id`. The current implementation still derives `channel_id` from `provider_state_snapshot["details"]["channel_id"]` with an ARN fallback (line 197). Adding an explicit `aws_channel_id` field to `BroadcastOutputModel` and `put_output()` would eliminate the fragile snapshot-key lookup and is a worthwhile hardening step.

4. **Reconciler and multi-session parallelism**: `broadcast_reconciler.py` processes sessions sequentially. If 100 sessions are `live` simultaneously and each `status()` call takes 1s (one `describe_channel` plus retry jitter), a single reconciler cycle takes 100+ seconds — longer than the 30s interval. The reconciler should use `asyncio.gather` or a thread pool for parallel status queries when the session count is large.
