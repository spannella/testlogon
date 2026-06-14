package com.testlogon.android.feature.kyc.liveness.model

import com.testlogon.android.core.model.kyc.KycLivenessCallOutDto
import java.time.Instant

/**
 * AND-324 - feature domain model + DTO mapper for the KYC scheduled liveness (video-verification) call.
 *
 * The wire `status` / `result` tokens are mapped to lenient enums here (unknown token -> UNKNOWN, never
 * throws). The epoch-second wire `scheduled_at` becomes a [java.time.Instant]. All DTO -> domain mapping
 * happens BEFORE the typed ApiResult in the repository (mirrors AND-320 / AND-321 / AND-322 / AND-323).
 *
 * This is a REAL REST scheduling feature: the [LivenessCall.joinUrl] is an opaque URL opened EXTERNALLY
 * by the screen (ACTION_VIEW), NOT an in-app WebRTC session.
 */

/** Lenient lifecycle status of a scheduled liveness call (unknown token -> [UNKNOWN]). */
enum class LivenessCallStatus {
    SCHEDULED,
    IN_PROGRESS,
    PASSED,
    FAILED,
    CANCELLED,
    EXPIRED,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): LivenessCallStatus = when (token?.lowercase()) {
            "scheduled" -> SCHEDULED
            "in_progress" -> IN_PROGRESS
            "passed" -> PASSED
            "failed" -> FAILED
            "cancelled" -> CANCELLED
            "expired" -> EXPIRED
            else -> UNKNOWN
        }
    }
}

/** Lenient verifier verdict for a completed call (unknown token -> [UNKNOWN]). */
enum class LivenessResult {
    PASSED,
    FAILED,
    UNKNOWN,
    ;

    companion object {
        fun fromToken(token: String?): LivenessResult? = when (token?.lowercase()) {
            null -> null
            "passed" -> PASSED
            "failed" -> FAILED
            else -> UNKNOWN
        }
    }
}

/**
 * Domain model of ONE scheduled liveness (video-verification) call.
 *
 * [cancellable] is derived: a call may be cancelled only while it is still SCHEDULED or IN_PROGRESS
 * (a finished/expired/already-cancelled call cannot be cancelled).
 */
data class LivenessCall(
    val callId: String,
    val caseId: String,
    val status: LivenessCallStatus,
    val scheduledAt: Instant,
    val durationMinutes: Int,
    val result: LivenessResult?,
    val joinUrl: String?,
) {
    val cancellable: Boolean
        get() = status == LivenessCallStatus.SCHEDULED || status == LivenessCallStatus.IN_PROGRESS
}

/** Maps the call DTO to the domain [LivenessCall]. Never throws; unknown tokens -> UNKNOWN. */
fun KycLivenessCallOutDto.toDomain(): LivenessCall = LivenessCall(
    callId = call_id,
    caseId = case_id,
    status = LivenessCallStatus.fromToken(status),
    scheduledAt = Instant.ofEpochSecond(scheduled_at),
    durationMinutes = duration_minutes,
    result = LivenessResult.fromToken(result),
    joinUrl = join_url,
)
