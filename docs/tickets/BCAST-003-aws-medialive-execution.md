# BCAST-003: Wire AWS MediaLive Start/Stop to Actual API Calls

## 1. Overview & Motivation

### Problem Statement

The broadcast system implements a provider abstraction (`BroadcastProvider` protocol in
`app/services/broadcast_provider.py`) with two concrete implementations:
`LocalBroadcastProvider` (fully functional for dev) and `AwsBroadcastProvider` (partially
implemented). The AWS provider currently handles **provisioning** -- creating MediaLive
inputs, channels, and MediaPackage endpoints -- via real boto3 API calls. However, the
`start()`, `stop()`, `status()`, and `teardown()` methods remain **stubbed**, returning
hardcoded `ProviderResult` objects with `"mode": "stub"` in their details dict without
making any AWS API calls.

This means that even when `BROADCAST_PROVIDER=aws` is configured, starting a broadcast
session does not actually start the MediaLive channel (it merely transitions the DynamoDB
state to "live"), stopping does not halt the channel (leaving AWS resources running and
billing), `status()` returns whatever DynamoDB says rather than querying the channel's
actual state, and `teardown()` never deletes the provisioned AWS resources.

### Business Impact

- **Cost leakage**: Channels left running after a session "stops" continue billing at
  $0.20--$3.00/hr depending on codec and resolution. Without real stop calls, orphaned
  channels accumulate indefinitely.
- **State drift**: The reconciler (`broadcast_reconciler.py`) calls `provider.status()` to
  detect drift between desired and actual state. Since the stub always echoes back the
  DynamoDB status, drift is never detected for AWS sessions -- the SLA alarm in
  `record_broadcast_drift_incident` never fires.
- **Resource leaks**: Without `teardown()` calling `delete_channel`/`delete_input`/
  `delete_origin_endpoint`, deleted sessions leave dangling MediaLive and MediaPackage
  resources in the AWS account.
- **Broken playback**: The orchestrator mints a CloudFront-signed playback URL on start,
  but the underlying MediaPackage origin endpoint never receives media because the
  MediaLive channel is never started -- viewers see a stalled HLS manifest.

### Scope

This ticket covers wiring the four stubbed methods to real AWS MediaLive/MediaPackage API
calls with proper polling, timeout handling, error classification, and idempotency. It does
NOT cover multi-region failover, auto-scaling input security groups, or adaptive bitrate
ladder configuration (those are BCAST-004 through BCAST-006).

---

## 2. Current State Analysis

### Provider Protocol (`app/services/broadcast_provider.py`)

The `BroadcastProvider` protocol defines five operations:

```python
class BroadcastProvider(Protocol):
    name: str
    def provision(self, session, *, profile=None, correlation_id="", idempotency_key="") -> ProviderResult
    def start(self, session, *, correlation_id="", idempotency_key="") -> ProviderResult
    def stop(self, session, *, correlation_id="", idempotency_key="") -> ProviderResult
    def status(self, session) -> ProviderResult
    def teardown(self, session) -> ProviderResult
```

Each returns a `ProviderResult(operation, provider, state, details)` dataclass. The
orchestrator (`broadcast_orchestrator.py`) interprets the `state` field to decide whether
to proceed with DynamoDB status transitions.

### What Is Already Real (Provisioning)

`AwsBroadcastProvider.provision()` (lines 70-109) delegates to two fully-implemented
modules:

1. **`broadcast_mediolive.py`** -- `provision_mediolive_input_and_channel()`:
   - Creates an RTMP_PUSH input named `broadcast-{session_id}-input` (idempotent: checks
     `_find_input_by_name` first).
   - Creates a channel named `broadcast-{session_id}-channel` with the input attached, an
     archive output group pointing to S3, and appropriate tags.
   - Returns `MediaLiveProvisionResult(input_arn, channel_arn, channel_id, state_snapshot,
     archive_prefix)`.
   - Uses `_with_retry()` for transient error handling (exponential backoff on Throttling,
     InternalError, ServiceUnavailable -- up to 4 attempts).

2. **`broadcast_mediapackage.py`** -- `provision_mediapackage_channel_and_endpoint()`:
   - Creates a MediaPackage channel `broadcast-{session_id}-pkg` (idempotent: catches
     exception from `describe_channel` and falls through to `create_channel`).
   - Creates an HLS origin endpoint `broadcast-{session_id}-hls` with configurable segment
     duration, playlist window, and optional SPEKE DRM encryption.
   - Returns `MediaPackageProvisionResult(channel_id, channel_arn, endpoint_id,
     endpoint_url, endpoint_arn, packaging_metadata)`.

### What Is Stubbed

| Method | Current Implementation | Expected Behavior |
|--------|----------------------|-------------------|
| `start()` | Returns `ProviderResult("start", "aws", "live", {"mode": "stub"})` | Call `medialive.start_channel(ChannelId=...)`, poll until `RUNNING`, return `state="live"` |
| `stop()` | Returns `ProviderResult("stop", "aws", "stopped", {"mode": "stub"})` | Call `medialive.stop_channel(ChannelId=...)`, poll until `IDLE`, return `state="stopped"` |
| `status()` | Returns `ProviderResult("status", "aws", session.status, {"mode": "stub"})` | Call `medialive.describe_channel(ChannelId=...)`, map channel State to our status enum |
| `teardown()` | Returns `ProviderResult("teardown", "aws", "deleted", {"mode": "stub"})` | Delete channel, input, MediaPackage endpoint, and MediaPackage channel |

### State Machine Context (`broadcast_state_machine.py`)

The allowed transitions are:

```
draft -> provisioning | error
provisioning -> ready | error
ready -> live | stopping | error
live -> stopping | error
stopping -> stopped | error
stopped -> (terminal)
error -> provisioning | stopped
```

The orchestrator in `start_session_with_provider()` performs two consecutive transitions:
1. `draft -> provisioning -> ready` (during provision)
2. `ready -> live` (on start)

And `stop_session_with_provider()`:
1. `ready|live -> stopping` (intent)
2. `stopping -> stopped` (confirmed)

The reconciler detects drift when `provider.status()` returns a state that differs from the
DynamoDB `session.status`. If drift persists beyond `BROADCAST_DRIFT_SLA_SECONDS` (default
120s), the session is transitioned to `error`.

### Orchestrator Flow (`broadcast_orchestrator.py`)

`start_session_with_provider` (lines 17-103):
- Gets provider via `get_broadcast_provider()` (reads `S.broadcast_provider`)
- If session is `draft`: provisions (calls `provider.provision()`), stores output ARNs in
  `BroadcastOutputs` table, transitions to `ready`
- If session is `ready`: calls `provider.start()`, transitions to `live`, mints playback
  URL (CloudFront-signed for AWS, local for dev), stores in outputs

`stop_session_with_provider` (lines 106-135):
- Transitions to `stopping`, calls `provider.stop()`, then transitions to `stopped`

`delete_session_with_provider` (lines 138-147):
- Calls `provider.teardown()`, then deletes DynamoDB records

### Settings (`app/core/settings.py`, lines 437-478)

Relevant AWS broadcast settings:
- `broadcast_provider`: `"local"` or `"aws"` (env: `BROADCAST_PROVIDER`)
- `broadcast_archive_bucket`: S3 bucket for archive segments
- `broadcast_archive_prefix_root`: Key prefix for session archives
- `broadcast_archive_retention_days`: Lifecycle rule expiration (default 30)
- `broadcast_cloudfront_domain`: CDN distribution domain for playback
- `broadcast_reconciler_enabled`: Toggle for background reconciler loop
- `broadcast_reconciler_interval_seconds`: Polling interval (default 30s)
- `broadcast_drift_sla_seconds`: Max drift tolerance before error (default 120s)
- `broadcast_stale_session_seconds`: Max time in transitional state (default 300s)

### Output Model (`models_broadcast.py`)

`BroadcastOutputModel` persists per-session AWS resource references:
- `aws_input_arn`: MediaLive input ARN (populated at provision time)
- `aws_channel_arn`: MediaLive channel ARN (populated at provision time)
- `mediapackage_endpoint`: Origin endpoint URL
- `provider_state_snapshot`: Freeform dict for provider-specific metadata

The `channel_id` (needed for start/stop/describe API calls) is NOT stored as a top-level
field but IS embedded in `provider_state_snapshot.details.channel_id` during provisioning
(see `broadcast_provider.py` line 99).

---

## 3. Technical Design

### 3.1 Architecture Principles

1. **Idempotency**: All AWS calls must be safe to retry. `start_channel` on an already-
   RUNNING channel is a no-op (AWS returns success). Same for `stop_channel` on IDLE.
2. **Polling with backoff**: MediaLive channel state transitions are async (STARTING takes
   10-60s, STOPPING takes 5-30s). We must poll `describe_channel` until terminal state.
3. **Timeout budget**: The orchestrator should enforce a maximum wall-clock time for
   start/stop operations. If exceeded, return an error result and let the reconciler
   handle eventual consistency.
4. **Resource cleanup ordering**: On teardown, resources must be deleted in reverse
   dependency order: origin endpoint -> MediaPackage channel -> MediaLive channel ->
   MediaLive input.
5. **Correlation/audit**: Every AWS call should be traceable via `correlation_id` passed
   through from the HTTP request header.

### 3.2 Channel ID Resolution

The `start()`, `stop()`, `status()`, and `teardown()` methods receive a
`BroadcastSessionModel` which does NOT contain the AWS channel ID directly. Resolution
strategy:

```python
def _resolve_channel_id(session: BroadcastSessionModel) -> str:
    """Extract channel_id from the persisted output record."""
    output = get_output(session.id)
    if not output:
        raise HTTPException(status_code=409, detail="session has no provisioned output")
    # Channel ID is in provider_state_snapshot from provision step
    channel_id = output.provider_state_snapshot.get("details", {}).get("channel_id")
    if not channel_id:
        # Fallback: derive from channel ARN (format: arn:aws:medialive:REGION:ACCOUNT:channel:ID)
        arn = output.aws_channel_arn or ""
        parts = arn.split(":")
        channel_id = parts[-1] if len(parts) >= 7 else ""
    if not channel_id:
        raise HTTPException(status_code=409, detail="cannot resolve MediaLive channel ID")
    return channel_id
```

Similarly for MediaPackage resources:
```python
def _resolve_mediapackage_ids(session: BroadcastSessionModel) -> tuple[str, str]:
    """Return (pkg_channel_id, endpoint_id) from naming convention."""
    return f"broadcast-{session.id}-pkg", f"broadcast-{session.id}-hls"
```

### 3.3 Start Implementation

```python
def start(self, session, *, correlation_id="", idempotency_key="") -> ProviderResult:
    client = _medialive_client()
    channel_id = _resolve_channel_id(session)

    # 1. Describe current state -- avoid starting if already RUNNING
    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_state = desc.get("State", "IDLE")

    if current_state == "RUNNING":
        return ProviderResult("start", "aws", "live", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": "RUNNING",
            "already_running": True,
        })

    if current_state not in ("IDLE", "CREATE_FAILED"):
        # Channel is in a transitional state (STARTING, STOPPING, etc.) -- cannot start
        return ProviderResult("start", "aws", "error", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": current_state,
            "error": f"channel in non-startable state: {current_state}",
        })

    # 2. Issue start command
    _with_retry(lambda: client.start_channel(ChannelId=channel_id))

    # 3. Poll until RUNNING or timeout
    state = _poll_channel_state(
        client, channel_id,
        target_states={"RUNNING"},
        error_states={"CREATE_FAILED", "IDLE"},  # fell back = failed
        timeout_seconds=120,
        poll_interval_seconds=5,
    )

    if state == "RUNNING":
        return ProviderResult("start", "aws", "live", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": "RUNNING",
            "correlation_id": correlation_id,
        })
    else:
        return ProviderResult("start", "aws", "error", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": state,
            "error": f"channel did not reach RUNNING within timeout (last state: {state})",
            "correlation_id": correlation_id,
        })
```

### 3.4 Stop Implementation

```python
def stop(self, session, *, correlation_id="", idempotency_key="") -> ProviderResult:
    client = _medialive_client()
    channel_id = _resolve_channel_id(session)

    desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    current_state = desc.get("State", "IDLE")

    if current_state == "IDLE":
        return ProviderResult("stop", "aws", "stopped", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": "IDLE",
            "already_stopped": True,
        })

    if current_state not in ("RUNNING", "RECOVERING"):
        return ProviderResult("stop", "aws", "error", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": current_state,
            "error": f"channel in non-stoppable state: {current_state}",
        })

    _with_retry(lambda: client.stop_channel(ChannelId=channel_id))

    state = _poll_channel_state(
        client, channel_id,
        target_states={"IDLE"},
        error_states={"RUNNING"},  # if back to running = failed to stop
        timeout_seconds=90,
        poll_interval_seconds=5,
    )

    if state == "IDLE":
        return ProviderResult("stop", "aws", "stopped", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": "IDLE",
            "correlation_id": correlation_id,
        })
    else:
        return ProviderResult("stop", "aws", "error", {
            "session_id": session.id,
            "channel_id": channel_id,
            "channel_state": state,
            "error": f"channel did not reach IDLE within timeout (last state: {state})",
            "correlation_id": correlation_id,
        })
```

### 3.5 Status Implementation

```python
_MEDIALIVE_STATE_MAP = {
    "CREATING": "provisioning",
    "CREATE_FAILED": "error",
    "IDLE": "ready",        # provisioned but not streaming
    "STARTING": "ready",    # transitioning -- map to ready (not yet live)
    "RUNNING": "live",
    "STOPPING": "stopping",
    "DELETING": "stopping",
    "DELETED": "stopped",
    "RECOVERING": "live",   # transient recovery -- still logically live
    "UPDATE_FAILED": "error",
}

def status(self, session) -> ProviderResult:
    client = _medialive_client()
    channel_id = _resolve_channel_id(session)

    try:
        desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NotFoundException":
            return ProviderResult("status", "aws", "error", {
                "session_id": session.id,
                "channel_id": channel_id,
                "error": "channel_not_found",
            })
        raise

    aws_state = desc.get("State", "IDLE")
    mapped = _MEDIALIVE_STATE_MAP.get(aws_state, "error")

    return ProviderResult("status", "aws", mapped, {
        "session_id": session.id,
        "channel_id": channel_id,
        "channel_state": aws_state,
        "pipelines_running": desc.get("PipelinesRunningCount", 0),
    })
```

This mapping enables the reconciler to detect actual drift. For example, if DynamoDB says
`status=live` but MediaLive reports `IDLE` (mapped to `"ready"`), the reconciler sees
`desired=live, actual=ready` -- a drift condition that triggers the SLA countdown.

### 3.6 Teardown Implementation

```python
def teardown(self, session) -> ProviderResult:
    ml_client = _medialive_client()
    mp_client = _mediapackage_client()
    channel_id = _resolve_channel_id(session)
    pkg_channel_id, endpoint_id = _resolve_mediapackage_ids(session)
    errors = []

    # 1. Ensure channel is stopped before deletion
    try:
        desc = _with_retry(lambda: ml_client.describe_channel(ChannelId=channel_id))
        if desc.get("State") == "RUNNING":
            _with_retry(lambda: ml_client.stop_channel(ChannelId=channel_id))
            _poll_channel_state(ml_client, channel_id, target_states={"IDLE"},
                                error_states=set(), timeout_seconds=90, poll_interval_seconds=5)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            errors.append(f"stop_channel: {exc}")

    # 2. Delete MediaLive channel
    try:
        _with_retry(lambda: ml_client.delete_channel(ChannelId=channel_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            errors.append(f"delete_channel: {exc}")

    # 3. Delete MediaLive input (must wait for channel deletion to release attachment)
    input_name = f"broadcast-{session.id}-input"
    try:
        existing = _find_input_by_name(ml_client, name=input_name)
        if existing:
            input_id = existing.get("Id", "")
            # Poll until input is DETACHED (channel deletion is async)
            _poll_input_state(ml_client, input_id, target_states={"DETACHED", "IDLE"},
                              timeout_seconds=60, poll_interval_seconds=5)
            _with_retry(lambda: ml_client.delete_input(InputId=input_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            errors.append(f"delete_input: {exc}")

    # 4. Delete MediaPackage origin endpoint
    try:
        _with_retry(lambda: mp_client.delete_origin_endpoint(Id=endpoint_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            errors.append(f"delete_origin_endpoint: {exc}")

    # 5. Delete MediaPackage channel
    try:
        _with_retry(lambda: mp_client.delete_channel(Id=pkg_channel_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            errors.append(f"delete_mediapackage_channel: {exc}")

    if errors:
        return ProviderResult("teardown", "aws", "error", {
            "session_id": session.id,
            "partial_errors": errors,
            "resources_may_remain": True,
        })

    return ProviderResult("teardown", "aws", "deleted", {
        "session_id": session.id,
        "channel_id": channel_id,
        "resources_cleaned": True,
    })
```

### 3.7 Polling Helper

```python
def _poll_channel_state(
    client,
    channel_id: str,
    *,
    target_states: set[str],
    error_states: set[str],
    timeout_seconds: int = 120,
    poll_interval_seconds: float = 5.0,
) -> str:
    """Poll describe_channel until state is in target_states, error_states, or timeout."""
    deadline = time.monotonic() + timeout_seconds
    last_state = "UNKNOWN"
    while time.monotonic() < deadline:
        desc = _with_retry(lambda: client.describe_channel(ChannelId=channel_id))
        last_state = desc.get("State", "UNKNOWN")
        if last_state in target_states:
            return last_state
        if last_state in error_states:
            return last_state
        time.sleep(poll_interval_seconds)
    return last_state  # timeout -- caller decides how to handle
```

### 3.8 Error Classification and Handling

| Error Type | Detection | Response |
|------------|-----------|----------|
| Transient (Throttling, 5xx) | `_TRANSIENT_CODES` set | Retry with exponential backoff (existing `_with_retry`) |
| Not Found | `NotFoundException` code | Return error result with `channel_not_found` |
| Conflict (channel in wrong state) | Describe returns unexpected state | Return error result, let reconciler retry |
| Timeout (polling exceeded) | `time.monotonic() > deadline` | Return error result with last observed state |
| Access Denied | `AccessDeniedException` | Raise immediately (fatal misconfiguration) |

The orchestrator already wraps provider calls in try/except blocks that transition the
session to `error` state on exceptions (lines 59-67 and 74-81 in
`broadcast_orchestrator.py`). The new implementation should NOT raise exceptions for
expected AWS states (channel already running, already idle) -- instead it returns a
`ProviderResult` with appropriate state. It SHOULD raise for truly unexpected errors
(permissions, missing resources that should exist).

### 3.9 Timeout Budgets

| Operation | AWS Typical Duration | Our Timeout | Rationale |
|-----------|---------------------|-------------|-----------|
| start_channel | 10-60s | 120s | 2x worst case; allows for pipeline warm-up |
| stop_channel | 5-30s | 90s | 3x worst case; graceful drain of active streams |
| teardown (stop + delete) | 30-120s | 180s total | Sequential stop + delete + input cleanup |
| status (single describe) | <1s | 10s (via retry) | Should never poll; single call |

These align with the existing `broadcast_stale_session_seconds=300` setting -- a session
in `provisioning` or `stopping` for >5 minutes is flagged stale by the reconciler. Our
operation timeouts are well within that window.

### 3.10 Interaction with Reconciler

After wiring real `status()`, the reconciler loop (`broadcast_reconciler.py`) gains actual
drift detection:

```
Reconciler calls provider.status(session) every 30s for active sessions.
Before: always returns session.status (echo) -> drift never detected.
After:  returns mapped MediaLive state -> real drift detection works.
```

Scenarios the reconciler will now catch:
- Session DB says "live" but channel crashed to IDLE -> drift -> error after 120s
- Session DB says "ready" but channel spontaneously started RUNNING -> drift detected
- Session DB says "stopping" but channel stuck in STOPPING > 300s -> stale timeout

### 3.11 Idempotency Considerations

- `start_channel` on a RUNNING channel: AWS returns success (no-op). Our code short-
  circuits with `already_running=True` before even calling start, but both paths are safe.
- `stop_channel` on an IDLE channel: AWS returns success. We short-circuit similarly.
- `delete_channel` on a deleted channel: AWS returns `NotFoundException`. We catch and
  treat as success.
- The `x-idempotency-key` header from the HTTP layer is passed through to audit logging
  but is not used for AWS deduplication (MediaLive uses `RequestId` only on create calls).

---

## 4. Implementation Plan

### Phase 1: Core Module (`app/services/broadcast_medialive.py` extension)

**File changes**: `app/services/broadcast_mediolive.py`

Add the following functions to the existing module (which already has `_client()`,
`_with_retry()`, `_find_input_by_name()`, `_find_channel_by_name()`):

| Function | Purpose |
|----------|---------|
| `start_medialive_channel(channel_id, timeout_seconds=120)` | Start + poll to RUNNING |
| `stop_medialive_channel(channel_id, timeout_seconds=90)` | Stop + poll to IDLE |
| `describe_medialive_channel(channel_id)` | Single describe, return state dict |
| `delete_medialive_channel(channel_id)` | Delete channel (assumes stopped) |
| `delete_medialive_input(input_id)` | Delete input after channel detaches |
| `_poll_channel_state(client, channel_id, ...)` | Generic poll loop |
| `_poll_input_state(client, input_id, ...)` | Poll input until DETACHED |

Estimated effort: ~120 lines of new code.

### Phase 2: MediaPackage Teardown (`app/services/broadcast_mediapackage.py` extension)

**File changes**: `app/services/broadcast_mediapackage.py`

Add:

| Function | Purpose |
|----------|---------|
| `delete_mediapackage_endpoint(endpoint_id)` | Delete origin endpoint |
| `delete_mediapackage_channel(channel_id)` | Delete packaging channel |

These are simple `_with_retry` wrappers around boto3 delete calls with NotFoundException
handling. Estimated effort: ~30 lines.

### Phase 3: Provider Wiring (`app/services/broadcast_provider.py`)

**File changes**: `app/services/broadcast_provider.py`

Replace the four stubbed methods in `AwsBroadcastProvider` with real implementations that:
1. Resolve `channel_id` from `BroadcastOutputModel.provider_state_snapshot` or ARN parsing
2. Delegate to the new functions in Phase 1/2
3. Return structured `ProviderResult` with AWS-specific details

Add new imports and a `_resolve_channel_id()` helper. Add `_MEDIALIVE_STATE_MAP` for
status mapping.

Estimated effort: ~100 lines replacing ~20 lines of stubs.

### Phase 4: Output Model Enhancement

**File changes**: `app/services/broadcast_store.py`, `app/models_broadcast.py`

Add `aws_channel_id` as a first-class field on `BroadcastOutputModel` so that start/stop
do not need to parse ARNs or dig into the freeform snapshot dict:

```python
class BroadcastOutputModel(BaseModel):
    ...
    aws_channel_id: Optional[str] = None  # NEW
    aws_mediapackage_channel_id: Optional[str] = None  # NEW
    aws_mediapackage_endpoint_id: Optional[str] = None  # NEW
```

Update `output_to_item()` / `output_from_item()` / `put_output()` accordingly. Backfill
existing records via the reconciler's next pass (it already calls `put_output()` every
cycle).

### Phase 5: Reconciler Integration

**File changes**: `app/services/broadcast_reconciler.py`

No code changes needed -- the reconciler already calls `provider.status(session)` and
compares `actual` vs `desired`. Once `status()` returns real MediaLive state, drift
detection activates automatically. However, we should add a log line when drift is first
detected to aid debugging:

```python
import logging
logger = logging.getLogger("broadcast.reconciler")
# ... in drift detection block:
logger.warning("drift detected", extra={
    "session_id": session.id, "desired": desired, "actual": actual,
    "drift_age_seconds": now - first,
})
```

### Phase 6: Settings Additions (`app/core/settings.py`)

Add timeout configuration:

```python
broadcast_aws_start_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_START_TIMEOUT_SECONDS", "120"))
broadcast_aws_stop_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_STOP_TIMEOUT_SECONDS", "90"))
broadcast_aws_teardown_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_TEARDOWN_TIMEOUT_SECONDS", "180"))
broadcast_aws_poll_interval_seconds: int = int(os.environ.get("BROADCAST_AWS_POLL_INTERVAL_SECONDS", "5"))
```

### Implementation Order and Dependencies

```
Phase 1 (medialive functions)  ─┐
Phase 2 (mediapackage teardown) ─┼─> Phase 3 (provider wiring) ─> Phase 5 (reconciler logging)
Phase 4 (output model)         ─┘
Phase 6 (settings) ─────────────────> Phase 1
```

Phases 1, 2, 4, and 6 are independent and can be developed in parallel. Phase 3 depends
on all of them. Phase 5 is a minor enhancement after Phase 3.

### Migration / Rollout

1. Deploy with `BROADCAST_PROVIDER=local` (no behavior change).
2. Run integration test suite against a staging AWS account.
3. Switch staging to `BROADCAST_PROVIDER=aws`.
4. Monitor CloudWatch metrics for `broadcast_provision_latency`, `broadcast_session_action`
   (already instrumented in `broadcast_orchestrator.py` via `app/metrics.py`).
5. Verify reconciler detects intentional drift (manually stop a channel via AWS console,
   observe error transition after 120s).
6. Roll to production with feature flag (env var).

---

## 5. Testing Strategy

### 5.1 Unit Tests (moto-mocked)

**File**: `tests/test_broadcast_medialive_ops.py`

Use `moto` to mock MediaLive and MediaPackage. moto supports `create_channel`,
`start_channel`, `stop_channel`, `describe_channel`, `delete_channel`, `create_input`,
`delete_input` for MediaLive, and all MediaPackage CRUD operations.

| Test Case | What It Validates |
|-----------|-------------------|
| `test_start_channel_idle_to_running` | start_channel called, polling returns RUNNING |
| `test_start_channel_already_running` | Returns `already_running=True`, no start call |
| `test_start_channel_timeout` | Mocked describe always returns STARTING -> error result |
| `test_stop_channel_running_to_idle` | stop_channel called, polling returns IDLE |
| `test_stop_channel_already_idle` | Short-circuits, returns `already_stopped=True` |
| `test_status_maps_running_to_live` | describe returns RUNNING -> state="live" |
| `test_status_maps_idle_to_ready` | describe returns IDLE -> state="ready" |
| `test_status_not_found` | NotFoundException -> state="error" |
| `test_teardown_full_cleanup` | Deletes endpoint, pkg channel, ML channel, ML input |
| `test_teardown_partial_failure` | One delete fails -> partial_errors in result |
| `test_teardown_stops_running_channel` | Channel was RUNNING -> stops then deletes |
| `test_retry_on_throttling` | Inject Throttling errors -> retries succeed |
| `test_poll_respects_timeout` | Ensure no infinite loop |

**Fixture pattern**:
```python
@pytest.fixture
def medialive_resources():
    """Provision a channel via the existing provision function, return IDs."""
    with moto.mock_medialive(), moto.mock_mediapackage():
        result = provision_mediolive_input_and_channel(
            session_id="test-session-1",
            correlation_id="test-corr",
            idempotency_key="test-idem",
        )
        yield result
```

Note: moto's MediaLive mock transitions channels instantly (CREATING -> IDLE on create,
IDLE -> RUNNING on start). To test timeout behavior, we need to either:
- Patch `_poll_channel_state` to inject intermediate states
- Or use `unittest.mock.patch` on the boto3 client's `describe_channel` to return
  `"STARTING"` N times before `"RUNNING"`

### 5.2 Integration Tests (real AWS, staging account)

**File**: `tests/integration/test_broadcast_aws_live.py` (skipped in CI unless
`AWS_INTEGRATION_TESTS=1`)

These tests use a dedicated staging AWS account with:
- A MediaLive IAM role pre-created
- Service quotas sufficient for 2 concurrent channels
- Cost controls: channels auto-deleted by test teardown + a CloudWatch alarm on
  MediaLive billing > $5/day

| Test Case | Duration | What It Validates |
|-----------|----------|-------------------|
| `test_full_lifecycle` | ~3 min | provision -> start (wait RUNNING) -> stop (wait IDLE) -> teardown |
| `test_start_idempotent` | ~2 min | Start twice -> second returns already_running |
| `test_teardown_running` | ~3 min | Teardown while RUNNING -> stops then deletes |
| `test_status_reflects_real_state` | ~2 min | Start, query status, verify "live" |

### 5.3 E2E Tests (Playwright, local provider)

The existing E2E test infrastructure uses `BROADCAST_PROVIDER=local`. Wiring the AWS
provider does not change local-mode behavior. However, we should add a new E2E spec that
validates the orchestrator's error handling when the provider returns error results:

**File**: `frontend/e2e/broadcast-aws-errors.spec.ts`

These tests use the mock backend with a patched `AwsBroadcastProvider` that simulates
various failure modes (inject via a dev-mode endpoint like
`POST /internal/broadcast/simulate-failure`):

| Test | Scenario |
|------|----------|
| Start fails with timeout | UI shows error state, session transitions to "error" |
| Stop fails | UI shows error, retry button available |
| Teardown partial failure | Delete response includes warning |
| Status returns drift | After 120s, session moves to error (reconciler test) |

### 5.4 Reconciler Tests

**File**: `tests/test_broadcast_reconciler.py` (extend existing)

| Test Case | What It Validates |
|-----------|-------------------|
| `test_drift_detected_with_real_status` | Mock provider.status returns "ready" when DB says "live" -> drift counter increments |
| `test_drift_resolves_before_sla` | Provider state corrects itself within 120s -> no error transition |
| `test_stale_provisioning_session` | Session stuck in "provisioning" > 300s -> error |

### 5.5 Cost Safety Tests

To prevent accidental cost leakage in CI:

1. **Teardown fixture**: Every integration test that creates AWS resources uses a
   `pytest.fixture` with `yield` + cleanup in the `finally` block.
2. **Account-level janitor**: A scheduled Lambda (outside this codebase) scans for
   MediaLive channels tagged `retention=broadcast` older than 1 hour and force-deletes
   them.
3. **Billing alarm**: CloudWatch alarm on `AWS/MediaLive` `ActiveChannels` metric > 2
   for > 10 minutes triggers SNS notification.

### 5.6 Metrics Validation

After deployment, verify these existing metrics fire correctly:

- `record_broadcast_provision_latency(provider="aws", result="success"|"failure", elapsed_seconds=...)` -- already instrumented
- `record_broadcast_session_action(provider="aws", action="start"|"stop"|"delete", result="success"|"failure")` -- already instrumented
- `record_broadcast_drift_incident(provider="aws", incident_type="state_drift")` -- fires when reconciler detects real drift
- `record_broadcast_input_loss(provider="aws", reason=...)` -- fires when status contains "input" + "loss"
- `record_broadcast_output_error(provider="aws", reason=...)` -- fires when live channel reports error/failed

### 5.7 Test Matrix Summary

| Layer | Count | Mocking | CI Gate |
|-------|-------|---------|---------|
| Unit (moto) | ~15 tests | Full mock | Always |
| Integration (AWS) | ~4 tests | None (real AWS) | Manual/nightly |
| E2E (Playwright) | ~4 tests | Mock backend | Always |
| Reconciler | ~3 tests | Patched provider | Always |
| **Total** | **~26 tests** | | |

---

## Appendix: File Reference

| File | Role in This Ticket |
|------|-------------------|
| `app/services/broadcast_provider.py` | Primary target -- replace stubs |
| `app/services/broadcast_mediolive.py` | Add start/stop/describe/delete functions |
| `app/services/broadcast_mediapackage.py` | Add delete functions |
| `app/services/broadcast_orchestrator.py` | Consumer of provider; no changes needed |
| `app/services/broadcast_reconciler.py` | Add logging; behavior auto-activates |
| `app/services/broadcast_state_machine.py` | Defines valid transitions; no changes |
| `app/services/broadcast_store.py` | Add `aws_channel_id` field to output model |
| `app/services/broadcast_archive.py` | Existing S3 archive helpers; no changes |
| `app/services/broadcast_cloudfront.py` | Existing CloudFront signing; no changes |
| `app/models_broadcast.py` | Add new optional fields to `BroadcastOutputModel` |
| `app/core/settings.py` | Add timeout/poll settings |
| `app/routers/broadcast.py` | No changes (consumes orchestrator) |
| `tests/test_broadcast_medialive_ops.py` | New unit test file |
| `tests/integration/test_broadcast_aws_live.py` | New integration test file |
| `frontend/e2e/broadcast-aws-errors.spec.ts` | New E2E error scenario tests |

---

## Codebase References

| File | Line(s) | Status | Notes |
|------|---------|--------|-------|
| `app/services/broadcast_provider.py` | 40 | EXISTS | `BroadcastProvider` protocol |
| `app/services/broadcast_provider.py` | 57 | EXISTS | `LocalBroadcastProvider` — fully functional for dev |
| `app/services/broadcast_provider.py` | 200 | EXISTS | `AwsBroadcastProvider` |
| `app/services/broadcast_provider.py` | 244-300 | **IMPLEMENTED** | `AwsBroadcastProvider.start()` — no longer stubbed; calls `medialive.start_channel`, polls until RUNNING |
| `app/services/broadcast_provider.py` | 301-354 | **IMPLEMENTED** | `AwsBroadcastProvider.stop()` — calls `medialive.stop_channel`, polls until IDLE |
| `app/services/broadcast_provider.py` | 355-380 | **IMPLEMENTED** | `AwsBroadcastProvider.status()` — calls `describe_channel`, maps channel state |
| `app/services/broadcast_provider.py` | 381+ | **IMPLEMENTED** | `AwsBroadcastProvider.teardown()` — deletes channel, input, MediaPackage resources |
| `app/services/broadcast_provider.py` | 469 | EXISTS | `get_broadcast_provider()` factory function |
| `app/services/broadcast_mediolive.py` | — | EXISTS | MediaLive provisioning functions |
| `app/services/broadcast_mediapackage.py` | — | EXISTS | MediaPackage provisioning functions |
| `app/services/broadcast_orchestrator.py` | — | EXISTS | Orchestration layer |
| `app/services/broadcast_reconciler.py` | — | EXISTS | Drift reconciler |
| `app/services/broadcast_state_machine.py` | — | EXISTS | State transition validation |
| `app/services/broadcast_store.py` | — | EXISTS | DDB CRUD + list functions |
| `app/models_broadcast.py` | — | EXISTS | Pydantic models |
| `app/core/settings.py` | 467 | EXISTS | `broadcast_provider` setting (default "local") |
| `app/main.py` | 396, 470 | EXISTS | Router + reconciler task registration |

### Key Discrepancies
- Ticket claims start/stop/status/teardown are "stubbed" returning `{"mode": "stub"}`, but ALL FOUR methods have been fully implemented with real AWS API calls, polling, and error handling
