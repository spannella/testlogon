package com.testlogon.android.data.call

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-295 — wire DTOs for the 1:1 call CONTROL PLANE under the /messaging/messages/calls endpoints plus the
 * call-history reads under /ui/calls/history*.
 *
 * Every shape VERIFIED against the staged reference (reference/openapi.index.txt L399-407 + L1298-1300;
 * reference/openapi.pretty.json components.schemas.Call*). snake_case field names via [Json]; absent
 * optionals fall back to Kotlin defaults (lenient decode). Epoch timestamps are Long SECONDS; money is
 * Long/Int CENTS; durations are Long SECONDS. minutes_remaining is a JSON number -> Double (R4).
 *
 * NOTE on naming asymmetry (verified): the invite REQUEST field is `rate_cents_per_min` while the invite
 * RESPONSE field is `rate_cents_per_minute`.
 *
 * The signaling DTOs (CallSignalingInDto / CallSignalingOutDto) + TURN DTOs (TurnCredentialsDto /
 * TurnIceServerDto) already live in data/webrtc (AND-290/291) and are reused — they are NOT redefined
 * here. This file owns only the invite/accept/decline/end/timeout/heartbeat/billing + history DTOs.
 */

// ─── Invite ──────────────────────────────────────────────────────────────────────────────────────

/** CallInviteIn — required: call_id, conversation_id, callee_user_id. */
@JsonClass(generateAdapter = true)
data class CallInviteInDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "callee_user_id") val calleeUserId: String,
    @Json(name = "initial_mode") val initialMode: String = "audio",
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
    @Json(name = "paid") val paid: Boolean = false,
    @Json(name = "rate_cents_per_min") val rateCentsPerMin: Int? = null,
)

/** CallInviteOut — the accepted invite (state typically "ringing"/"initiated"). */
@JsonClass(generateAdapter = true)
data class CallInviteOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "caller_user_id") val callerUserId: String,
    @Json(name = "callee_user_id") val calleeUserId: String,
    @Json(name = "state") val state: String,
    @Json(name = "initial_mode") val initialMode: String,
    @Json(name = "start_ts") val startTsEpochSeconds: Long,
    @Json(name = "paid") val paid: Boolean = false,
    @Json(name = "rate_cents_per_minute") val rateCentsPerMinute: Int? = null,
)

// ─── Lifecycle action requests (accept/decline/end/timeout) ────────────────────────────────────────

/** CallAcceptIn — only an optional idempotency_key. */
@JsonClass(generateAdapter = true)
data class CallAcceptInDto(
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

/** CallDeclineIn — reason default "declined" (web also sends "busy"). */
@JsonClass(generateAdapter = true)
data class CallDeclineInDto(
    @Json(name = "reason") val reason: String = "declined",
)

/** CallEndIn — reason default "ended"; optional idempotency_key. */
@JsonClass(generateAdapter = true)
data class CallEndInDto(
    @Json(name = "reason") val reason: String = "ended",
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

/** CallTimeoutIn — reason default "no_answer"; optional idempotency_key. */
@JsonClass(generateAdapter = true)
data class CallTimeoutInDto(
    @Json(name = "reason") val reason: String = "no_answer",
    @Json(name = "idempotency_key") val idempotencyKey: String? = null,
)

/** CallActionOut — shared by accept/decline/end/timeout. Required: call_id, conversation_id, state, event_ts. */
@JsonClass(generateAdapter = true)
data class CallActionOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "state") val state: String,
    @Json(name = "event_ts") val eventTsEpochSeconds: Long,
    @Json(name = "from_state") val fromState: String? = null,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "voicemail_eligible") val voicemailEligible: Boolean = false,
)

// ─── Heartbeat (billing keepalive) ─────────────────────────────────────────────────────────────────

/** HeartbeatIn — only a nullable client_ts (epoch seconds). */
@JsonClass(generateAdapter = true)
data class HeartbeatInDto(
    @Json(name = "client_ts") val clientTsEpochSeconds: Long? = null,
)

/** HeartbeatOut — only call_id is required; everything else has a server default. action default "ok". */
@JsonClass(generateAdapter = true)
data class HeartbeatOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "elapsed_seconds") val elapsedSeconds: Long = 0,
    @Json(name = "total_cost_cents") val totalCostCents: Long = 0,
    @Json(name = "balance_remaining_cents") val balanceRemainingCents: Long = 0,
    @Json(name = "rate_cents_per_minute") val rateCentsPerMinute: Long = 0,
    @Json(name = "next_bill_in_seconds") val nextBillInSeconds: Long = 0,
    @Json(name = "warn_low_balance") val warnLowBalance: Boolean = false,
    @Json(name = "minutes_remaining") val minutesRemaining: Double = 0.0,
    @Json(name = "max_duration_warning") val maxDurationWarning: Boolean = false,
    @Json(name = "action") val action: String = "ok",
)

// ─── Billing status ────────────────────────────────────────────────────────────────────────────────

/** CallBillingStatusOut — required: call_id, paid; all numeric fields default 0. */
@JsonClass(generateAdapter = true)
data class CallBillingStatusOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "paid") val paid: Boolean,
    @Json(name = "rate_cents_per_minute") val rateCentsPerMinute: Long = 0,
    @Json(name = "total_cost_cents") val totalCostCents: Long = 0,
    @Json(name = "total_billed_seconds") val totalBilledSeconds: Long = 0,
    @Json(name = "billing_cycle_count") val billingCycleCount: Long = 0,
    @Json(name = "caller_balance_remaining_cents") val callerBalanceRemainingCents: Long = 0,
    @Json(name = "platform_fee_bps") val platformFeeBps: Long = 0,
    @Json(name = "max_duration_seconds") val maxDurationSeconds: Long = 0,
    @Json(name = "elapsed_seconds") val elapsedSeconds: Long = 0,
    @Json(name = "billing_status") val billingStatus: String = "",
)

// ─── Call history (GET /ui/calls/history -> CallHistoryResponse{items:[CallRecordOut],next_cursor}) ──

/** CallRecordOut — a single call-history row. Required: call_id, caller_id, callee_id, call_type. */
@JsonClass(generateAdapter = true)
data class CallRecordOutDto(
    @Json(name = "call_id") val callId: String,
    @Json(name = "caller_id") val callerId: String,
    @Json(name = "callee_id") val calleeId: String,
    @Json(name = "call_type") val callType: String,
    @Json(name = "direction") val direction: String = "outgoing",
    @Json(name = "status") val status: String = "completed",
    @Json(name = "duration_seconds") val durationSeconds: Long = 0,
    @Json(name = "created_at") val createdAtEpochSeconds: Long = 0,
)

/** CallHistoryResponse — paged list + opaque next_cursor. */
@JsonClass(generateAdapter = true)
data class CallHistoryResponseDto(
    @Json(name = "items") val items: List<CallRecordOutDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
