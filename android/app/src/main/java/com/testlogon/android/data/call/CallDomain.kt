package com.testlogon.android.data.call

/**
 * AND-295 — pure (DTO-free) domain models for the 1:1 call control plane.
 *
 * The repository maps wire DTOs -> these before returning a typed ApiResult (never leaks raw DTOs). No
 * android.* types (JVM-unit-testable on minSdk 24); epoch timestamps are Long SECONDS, money Long CENTS,
 * call duration Long SECONDS, minutes_remaining Double.
 */

/** The mode a call is placed/answered in. */
enum class CallMode(val wire: String) {
    AUDIO("audio"),
    VIDEO("video"),
    ;

    companion object {
        fun fromWire(value: String?): CallMode =
            if (value?.lowercase() == "video") VIDEO else AUDIO
    }
}

/** Result of placing a 1:1 call (POST .../invite -> CallInviteOut). */
data class CallInvited(
    val callId: String,
    val conversationId: String,
    val callerUserId: String,
    val calleeUserId: String,
    val state: String,
    val mode: CallMode,
    val startTsEpochSeconds: Long,
    val paid: Boolean,
    val rateCentsPerMinute: Int?,
)

/** Result of a lifecycle action (accept/decline/end/timeout -> CallActionOut). */
data class CallAction(
    val callId: String,
    val conversationId: String,
    val state: String,
    val eventTsEpochSeconds: Long,
    val fromState: String?,
    val reason: String?,
    val voicemailEligible: Boolean,
)

/** A billing heartbeat tick (PATCH .../heartbeat -> HeartbeatOut). */
data class CallHeartbeat(
    val callId: String,
    val elapsedSeconds: Long,
    val totalCostCents: Long,
    val balanceRemainingCents: Long,
    val rateCentsPerMinute: Long,
    val nextBillInSeconds: Long,
    val warnLowBalance: Boolean,
    val minutesRemaining: Double,
    val maxDurationWarning: Boolean,
    val action: String,
) {
    /** The server requested termination (insufficient balance / max-duration). */
    val shouldTerminate: Boolean
        get() = action.equals("terminate", ignoreCase = true) || minutesRemaining <= 0.0
}

/** Snapshot of a call's billing state (GET .../billing -> CallBillingStatusOut). */
data class CallBillingStatus(
    val callId: String,
    val paid: Boolean,
    val rateCentsPerMinute: Long,
    val totalCostCents: Long,
    val totalBilledSeconds: Long,
    val callerBalanceRemainingCents: Long,
    val elapsedSeconds: Long,
    val billingStatus: String,
)

/** Direction of a historical call relative to the local user. */
enum class CallDirection { INCOMING, OUTGOING }

/** Terminal disposition of a historical call. */
enum class CallStatus { COMPLETED, MISSED, DECLINED, NO_ANSWER, FAILED, UNKNOWN }

/** A single call-history row (CallRecordOut). */
data class CallHistoryEntry(
    val callId: String,
    val callerId: String,
    val calleeId: String,
    val mode: CallMode,
    val direction: CallDirection,
    val status: CallStatus,
    val durationSeconds: Long,
    val createdAtEpochSeconds: Long,
    val rawStatus: String,
)

/** A page of call history. */
data class CallHistoryPage(
    val entries: List<CallHistoryEntry>,
    val nextCursor: String?,
)

// ─── DTO -> domain mappers ───────────────────────────────────────────────────────────────────────

internal fun CallInviteOutDto.toDomain(): CallInvited = CallInvited(
    callId = callId,
    conversationId = conversationId,
    callerUserId = callerUserId,
    calleeUserId = calleeUserId,
    state = state,
    mode = CallMode.fromWire(initialMode),
    startTsEpochSeconds = startTsEpochSeconds,
    paid = paid,
    rateCentsPerMinute = rateCentsPerMinute,
)

internal fun CallActionOutDto.toDomain(): CallAction = CallAction(
    callId = callId,
    conversationId = conversationId,
    state = state,
    eventTsEpochSeconds = eventTsEpochSeconds,
    fromState = fromState,
    reason = reason,
    voicemailEligible = voicemailEligible,
)

internal fun HeartbeatOutDto.toDomain(): CallHeartbeat = CallHeartbeat(
    callId = callId,
    elapsedSeconds = elapsedSeconds,
    totalCostCents = totalCostCents,
    balanceRemainingCents = balanceRemainingCents,
    rateCentsPerMinute = rateCentsPerMinute,
    nextBillInSeconds = nextBillInSeconds,
    warnLowBalance = warnLowBalance,
    minutesRemaining = minutesRemaining,
    maxDurationWarning = maxDurationWarning,
    action = action,
)

internal fun CallBillingStatusOutDto.toDomain(): CallBillingStatus = CallBillingStatus(
    callId = callId,
    paid = paid,
    rateCentsPerMinute = rateCentsPerMinute,
    totalCostCents = totalCostCents,
    totalBilledSeconds = totalBilledSeconds,
    callerBalanceRemainingCents = callerBalanceRemainingCents,
    elapsedSeconds = elapsedSeconds,
    billingStatus = billingStatus,
)

internal fun CallRecordOutDto.toDomain(): CallHistoryEntry = CallHistoryEntry(
    callId = callId,
    callerId = callerId,
    calleeId = calleeId,
    mode = CallMode.fromWire(callType),
    direction = if (direction.equals("incoming", ignoreCase = true)) {
        CallDirection.INCOMING
    } else {
        CallDirection.OUTGOING
    },
    status = status.toCallStatus(),
    durationSeconds = durationSeconds,
    createdAtEpochSeconds = createdAtEpochSeconds,
    rawStatus = status,
)

internal fun CallHistoryResponseDto.toDomain(): CallHistoryPage = CallHistoryPage(
    entries = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

internal fun String?.toCallStatus(): CallStatus = when (this?.lowercase()) {
    "completed" -> CallStatus.COMPLETED
    "missed" -> CallStatus.MISSED
    "declined" -> CallStatus.DECLINED
    "no_answer" -> CallStatus.NO_ANSWER
    "failed" -> CallStatus.FAILED
    else -> CallStatus.UNKNOWN
}
