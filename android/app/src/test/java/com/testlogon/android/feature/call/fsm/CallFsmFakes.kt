package com.testlogon.android.feature.call.fsm

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.call.CallAction
import com.testlogon.android.data.call.CallBillingStatus
import com.testlogon.android.data.call.CallDirection
import com.testlogon.android.data.call.CallHeartbeat
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.data.call.CallHistoryPage
import com.testlogon.android.data.call.CallInvited
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallRepository
import com.testlogon.android.data.call.CallStats
import com.testlogon.android.data.call.CallStatus

/**
 * AND-305 — shared test fakes for the [CallStateMachine] host tests. A recording [CallRepository] (REUSES
 * the existing interface — nothing added) and a manual-fire [CallTimerScheduler] so the time-driven timer
 * firing is deterministic without advanceUntilIdle on the host's infinite flows.
 */
class RecordingCallRepository(
    private val inviteSucceeds: Boolean = true,
) : CallRepository {

    val invited = mutableListOf<String>()
    val accepted = mutableListOf<String>()
    val declined = mutableListOf<String>()
    val ended = mutableListOf<Pair<String, String>>()
    val timedOut = mutableListOf<String>()

    override suspend fun invite(
        callId: String,
        conversationId: String,
        calleeUserId: String,
        mode: CallMode,
        idempotencyKey: String?,
        paid: Boolean,
        rateCentsPerMin: Int?,
    ): ApiResult<CallInvited> {
        invited += callId
        return if (inviteSucceeds) {
            ApiResult.Success(
                CallInvited(callId, conversationId, "self", calleeUserId, "ringing", mode, 0, false, null),
            )
        } else {
            ApiResult.NetworkError(java.io.IOException("offline"), isTimeout = false)
        }
    }

    override suspend fun accept(callId: String, idempotencyKey: String?): ApiResult<CallAction> {
        accepted += callId
        return ok(callId)
    }

    override suspend fun decline(callId: String, reason: String): ApiResult<CallAction> {
        declined += callId
        return ok(callId)
    }

    override suspend fun end(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> {
        ended += callId to reason
        return ok(callId)
    }

    override suspend fun timeout(callId: String, reason: String, idempotencyKey: String?): ApiResult<CallAction> {
        timedOut += callId
        return ok(callId)
    }

    override suspend fun heartbeat(callId: String, clientTsEpochSeconds: Long?) =
        ApiResult.Success(CallHeartbeat(callId, 0, 0, 0, 0, 0, false, 10.0, false, "ok"))

    override suspend fun billing(callId: String) =
        ApiResult.Success(CallBillingStatus(callId, false, 0, 0, 0, 0, 0, ""))

    override suspend fun history(cursor: String?, limit: Int?) =
        ApiResult.Success(CallHistoryPage(emptyList(), null))

    override suspend fun detail(callId: String) =
        ApiResult.Success(
            CallHistoryEntry(
                callId, "self", "peer", CallMode.AUDIO,
                CallDirection.OUTGOING, CallStatus.COMPLETED, 0L, 0L, "completed",
            ),
        )

    override suspend fun deleteRecord(callId: String) = ApiResult.Success(Unit)

    override suspend fun stats() = ApiResult.Success(CallStats(0, emptyMap(), emptyMap(), 0L))

    private fun ok(callId: String): ApiResult<CallAction> =
        ApiResult.Success(CallAction(callId, "conv", "ended", 0, null, null, false))
}

/** Manual-fire timer scheduler: records armed timers; [fire] invokes the latest callback for a key. */
class FakeCallTimerScheduler : CallTimerScheduler {
    private val callbacks = mutableMapOf<TimerKey, () -> Unit>()
    val started = mutableListOf<Pair<TimerKey, Long>>()
    val cancelled = mutableListOf<TimerKey>()

    override fun start(key: TimerKey, delayMs: Long, onFire: () -> Unit) {
        started += key to delayMs
        callbacks[key] = onFire
    }

    override fun cancel(key: TimerKey) {
        cancelled += key
        callbacks.remove(key)
    }

    override fun cancelAll() {
        callbacks.clear()
    }

    /** Fire the armed timer for [key], if still armed. */
    fun fire(key: TimerKey) {
        callbacks[key]?.invoke()
    }

    fun isArmed(key: TimerKey): Boolean = callbacks.containsKey(key)
}
