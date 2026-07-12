package com.testlogon.android.feature.call.domain

/**
 * AND-296 — tunable timing for the call state machine, injected so tests can shorten the ring/heartbeat
 * windows and the production values can be retuned for the unreliable dev backend.
 *
 * All values are millis. The ring timeout (45s) and the heartbeat interval (15s) match the spec; both
 * timers are bounded coroutine jobs (NO unbounded while+delay) so advanceUntilIdle never hangs.
 */
data class CallTiming(
    val ringTimeoutMs: Long = 45_000,
    val heartbeatIntervalMs: Long = 15_000,
    val signalRetryDelayMs: Long = 2_000,
    val maxConsecutiveHeartbeatFailures: Int = 3,
    /**
     * GHOST-CALL GUARD — the maximum age of an inbound `call.invite` that is still allowed to RING.
     *
     * The `/messaging/events/poll` per-user queue re-serves the newest ~100 events on every app launch,
     * including days-old `call.invite`s whose call has long since gone terminal (missed/ended). Those must
     * NEVER ring. Any invite older than this is dropped silently (see IncomingCallController.onInvite).
     *
     * Sized WELL beyond the server ring backstop (`ringTimeoutMs`, ~30-45s) so it never suppresses a
     * genuine current call, yet far below the days-old replay — the headroom also absorbs device/server
     * clock skew. A real incoming call is always only seconds old.
     */
    val staleInviteMaxAgeMs: Long = 10 * 60_000,
)
