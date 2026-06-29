package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-137 / AND-138 / AND-139 — wire DTOs for countdown, calendar-event/share, and tips/paid-
 * unlockable (incl. lottery) messages.
 *
 * Shapes verified (2026-06-09) against:
 *  - reference/openapi.index.txt lines 334-336 (calendar-event / calendar-share / countdown POSTs),
 *    363-364 (tip / unlock), 411-414 (lottery create / get / unlock).
 *  - reference/src/api/types.ts: CalendarEventAttachment (912-932), CalendarShareAttachment (912-919),
 *    SendTipReq (1288-1293), LotterySelectedOutcome (2905-2910), LotteryUnlockResp (2924-2929),
 *    flat MessageOut paid fields lock_price_cents/lock_description/is_unlocked/locked/tip_* (1211-1216),
 *    countdown fields countdown_title/target_datetime/associated_event_* (1157-1160), nested
 *    `lottery` sub-object {message_type, lock_state, selected_outcome} (1171-1184).
 *  - reference/src/api/endpoints/messaging.ts: sendCountdownMessage (807), unlockMessage (610),
 *    sendMessageTip (642), unlockLotteryMessage (258), getLotteryMessage (265).
 *
 * Conventions reused from the established per-kind pattern:
 *  - conversation_id / message_id are PATH params (never body fields).
 *  - created_at / unlocked_at are epoch-SECONDS integers (NOT ISO-8601).
 *  - MessageOut is a flat object discriminated by `kind`; per-kind fields are flat columns or a
 *    nested object on the shared [MessageDto].
 *  - money is integer minor units (cents); never a float/string.
 */

// ─── AND-137: countdown send request (SendCountdownMessageIn) ───

/**
 * SendCountdownMessageIn. Required: title (1..200), target_datetime (UTC unix seconds, integer).
 * associated_event_type defaults to "custom" (pattern ^(broadcast|call|calendar|custom)$);
 * associated_event_id is <=128|null. There is NO conversation_id/client_id on the wire.
 */
@JsonClass(generateAdapter = true)
data class SendCountdownMessageReq(
    @Json(name = "title") val title: String,
    // #32 — absolute target wins when set; otherwise the server resolves target_datetime_local in target_tz.
    @Json(name = "target_datetime") val targetDatetime: Long? = null,
    @Json(name = "target_datetime_local") val targetDatetimeLocal: String? = null,
    @Json(name = "target_tz") val targetTz: String? = null,
    @Json(name = "associated_event_type") val associatedEventType: String = "custom",
    @Json(name = "associated_event_id") val associatedEventId: String? = null,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    // #31 (B-COUNTDOWN) — optional reveal payload surfaced once the countdown completes.
    @Json(name = "reveal_text") val revealText: String? = null,
    @Json(name = "reveal_image") val revealImage: CountdownRevealImageReq? = null,
)

/** #31 — a single reveal image ref attached to a countdown (mirrors LotteryMessageImageReq). `key` required. */
@JsonClass(generateAdapter = true)
data class CountdownRevealImageReq(
    @Json(name = "bucket") val bucket: String? = null,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
)

// ─── AND-138: calendar-event / calendar-share attachments (nested on MessageOut) ───

/**
 * MessageOut.calendar_event (CalendarEventAttachment). start_utc/end_utc are RFC-3339 strings and
 * OPTIONAL; all_day_date is a date-only string for all-day events. There is NO title/location/rsvp;
 * the display name field is `name`.
 */
@JsonClass(generateAdapter = true)
data class CalendarEventAttachmentDto(
    @Json(name = "event_id") val eventId: String = "",
    @Json(name = "calendar_id") val calendarId: String = "",
    val name: String = "",
    @Json(name = "start_utc") val startUtc: String? = null,
    @Json(name = "end_utc") val endUtc: String? = null,
    @Json(name = "all_day") val allDay: Boolean = false,
    @Json(name = "all_day_date") val allDayDate: String? = null,
    val timezone: String? = null,
    val description: String? = null,
    val owner: String = "",
)

/**
 * MessageOut.calendar_share (CalendarShareAttachment). permission is "read"|"write" (NOT
 * viewer/editor). owner exists but the web card omits it. There is NO color field.
 */
@JsonClass(generateAdapter = true)
data class CalendarShareAttachmentDto(
    @Json(name = "calendar_id") val calendarId: String = "",
    val name: String = "",
    val owner: String = "",
    val permission: String = "read",
    @Json(name = "booking_link_id") val bookingLinkId: String? = null,
    @Json(name = "booking_public_url") val bookingPublicUrl: String? = null,
)

// ─── AND-139: tip / unlock request + receipt DTOs ───

/** UnlockMessageIn — only field is payment_method_id (nullable). No client_id on the wire. */
@JsonClass(generateAdapter = true)
data class UnlockMessageReq(
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/** UnlockOut — receipt only; does NOT carry the revealed body/media (client re-fetches). */
@JsonClass(generateAdapter = true)
data class UnlockOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "unlock_payment_id") val unlockPaymentId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long? = null,
)

/**
 * SendTipIn. amount_cents required (server min 1, max 100000). currency defaults "USD"; note max 500;
 * payment_method_id optional/nullable. No client_id on the wire.
 */
@JsonClass(generateAdapter = true)
data class SendTipReq(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "note") val note: String? = null,
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/** TipOut — tip receipt. */
@JsonClass(generateAdapter = true)
data class TipOutDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "tip_payment_id") val tipPaymentId: String? = null,
    @Json(name = "amount_cents") val amountCents: Long = 0L,
    @Json(name = "currency") val currency: String = "USD",
)

// ─── MSG: new composers (lottery create / find-datetime / calendar-event / calendar-share) ───

/** LotteryOutcomeIn — one possible draw outcome. weight_bps 1..10000 (sum to 10000 across outcomes). */
@JsonClass(generateAdapter = true)
data class LotteryOutcomeReq(
    @Json(name = "display_label") val displayLabel: String? = null,
    @Json(name = "weight_bps") val weightBps: Int,
    @Json(name = "payload_type") val payloadType: String = "text",
    @Json(name = "text_content") val textContent: String? = null,
    // #13 — per-option media: an S3 key (or "bucket:key") under {conversation_id}/{owner}/ in the
    // image bucket, required when payload_type is "image"|"video" (Backend B-LOT contract).
    @Json(name = "media_asset_id") val mediaAssetId: String? = null,
    // #24 — a single outcome may carry MULTIPLE media assets (mixed images + videos). The server
    // treats media_asset_id as the first element; media_asset_ids is the full list (B-LOTTERY2).
    @Json(name = "media_asset_ids") val mediaAssetIds: List<String>? = null,
)

/** LotteryConfigIn — {version, outcomes[]}. */
@JsonClass(generateAdapter = true)
data class LotteryConfigReq(
    val version: String = "v1",
    val outcomes: List<LotteryOutcomeReq>,
)

/**
 * CreateLotteryMessageIn. NOTE: conversation_id is in the BODY (not the path) for this endpoint.
 * message_type is the literal "lottery_dm".
 */
@JsonClass(generateAdapter = true)
data class CreateLotteryReq(
    @Json(name = "message_type") val messageType: String = "lottery_dm",
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "lottery_config") val lotteryConfig: LotteryConfigReq,
    // C10 — optional cover/header image on the lottery message (Backend B3).
    @Json(name = "image") val image: LotteryMessageImageReq? = null,
    // #23 — optional message-level cover text shown before unlock (B-LOTTERY2). EITHER this or an
    // image satisfies the server's text-or-cover requirement for media-only options.
    @Json(name = "text") val text: String? = null,
)

/** C10 — LotteryMessageImageIn (Backend B3): message-level cover image ref. `key` required. */
@JsonClass(generateAdapter = true)
data class LotteryMessageImageReq(
    @Json(name = "bucket") val bucket: String? = null,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
)

/**
 * CreateFindDateTimeMessageIn (the "custom poll"). end_hour > start_hour;
 * slot_duration_minutes ∈ {15,30,60}; deadline_hours 1..336.
 */
@JsonClass(generateAdapter = true)
data class CreateFindDateTimeReq(
    val title: String,
    @Json(name = "from_date") val fromDate: String,
    @Json(name = "to_date") val toDate: String,
    @Json(name = "start_hour") val startHour: Int,
    @Json(name = "end_hour") val endHour: Int,
    @Json(name = "slot_duration_minutes") val slotDurationMinutes: Int = 30,
    @Json(name = "deadline_hours") val deadlineHours: Int = 48,
    val text: String? = null,
)

/** MessageOut.find_datetime (nested render attachment for a kind="find_datetime" message). */
@JsonClass(generateAdapter = true)
data class FindDateTimeAttachmentDto(
    @Json(name = "poll_id") val pollId: String = "",
    @Json(name = "creator_id") val creatorId: String = "",
    val title: String = "",
    @Json(name = "from_date") val fromDate: String? = null,
    @Json(name = "to_date") val toDate: String? = null,
    @Json(name = "start_hour") val startHour: Int? = null,
    @Json(name = "end_hour") val endHour: Int? = null,
    @Json(name = "slot_duration_minutes") val slotDurationMinutes: Int? = null,
    val status: String? = null,
)

/** CreateCalendarEventMessageIn. */
@JsonClass(generateAdapter = true)
data class CreateCalendarEventReq(
    @Json(name = "calendar_id") val calendarId: String,
    @Json(name = "event_id") val eventId: String,
    val text: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

/** CreateCalendarShareMessageIn. */
@JsonClass(generateAdapter = true)
data class CreateCalendarShareReq(
    @Json(name = "calendar_id") val calendarId: String,
    val permission: String = "read",
    @Json(name = "include_booking_link") val includeBookingLink: Boolean = false,
    val text: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

// ─── AND-139: lottery (separate lottery_dm message type) ───

/** LotterySelectedOutcome — the revealed payload after a draw (text or media reference). */
@JsonClass(generateAdapter = true)
data class LotterySelectedOutcomeDto(
    @Json(name = "outcome_id") val outcomeId: String = "",
    @Json(name = "payload_type") val payloadType: String = "text",
    @Json(name = "text_content") val textContent: String? = null,
    @Json(name = "media_asset_id") val mediaAssetId: String? = null,
    // #24 — the full list of revealed media assets when the winning outcome carries >1 image/video.
    // media_asset_id stays as the first element for single-asset back-compat (B-LOTTERY2 reveal).
    @Json(name = "media_asset_ids") val mediaAssetIds: List<String>? = null,
)

/**
 * LotteryUnlockResp — single atomic draw+reveal response. lock_state is "unlocked"; unlocked_at is
 * epoch-SECONDS integer.
 */
@JsonClass(generateAdapter = true)
data class LotteryUnlockOutDto(
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "lock_state") val lockState: String = "unlocked",
    @Json(name = "selected_outcome") val selectedOutcome: LotterySelectedOutcomeDto? = null,
    @Json(name = "unlocked_at") val unlockedAt: Long = 0L,
)

/** LotteryMessageOut — hydration GET; carries lock_state + (when unlocked) the selected_outcome. */
@JsonClass(generateAdapter = true)
data class LotteryMessageOutDto(
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "sender_id") val senderId: String = "",
    @Json(name = "lock_state") val lockState: String = "locked",
    @Json(name = "selected_outcome") val selectedOutcome: LotterySelectedOutcomeDto? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
)

/**
 * MessageOut.lottery (nested sub-object on a lottery_dm message). lock_state gates the locked teaser
 * vs the revealed outcome.
 *
 * #15 (B-LOTSENDER) — the SENDER's projection of their OWN lottery is distinct: lock_state is
 * "sender_view" + is_sender=true and the object carries the FULL config (every outcome with its
 * weight/label/payload) PLUS each recipient's unlock result. The recipient still only ever sees their
 * own (post-unlock) outcome via [selectedOutcome]. All sender-only fields are nullable so a recipient
 * frame (no sender block) decodes unchanged.
 */
@JsonClass(generateAdapter = true)
data class LotteryAttachmentDto(
    @Json(name = "message_type") val messageType: String = "lottery_dm",
    @Json(name = "lock_state") val lockState: String = "locked",
    @Json(name = "selected_outcome") val selectedOutcome: LotterySelectedOutcomeDto? = null,
    // ── #15 sender-view fields (present only when lock_state == "sender_view") ──
    @Json(name = "is_sender") val isSender: Boolean? = null,
    @Json(name = "version") val version: String? = null,
    @Json(name = "total_weight_bps") val totalWeightBps: Int? = null,
    @Json(name = "outcomes") val outcomes: List<LotterySenderOutcomeDto>? = null,
    @Json(name = "unlock_count") val unlockCount: Int? = null,
    @Json(name = "unlocks") val unlocks: List<LotterySenderUnlockDto>? = null,
)

/** #15 — one configured lottery outcome as seen by the SENDER (full config, incl. weight + label). */
@JsonClass(generateAdapter = true)
data class LotterySenderOutcomeDto(
    @Json(name = "outcome_id") val outcomeId: String = "",
    @Json(name = "display_label") val displayLabel: String? = null,
    @Json(name = "weight_bps") val weightBps: Int = 0,
    @Json(name = "payload_type") val payloadType: String = "text",
    @Json(name = "text_content") val textContent: String? = null,
    @Json(name = "media_asset_id") val mediaAssetId: String? = null,
    @Json(name = "media_asset_ids") val mediaAssetIds: List<String>? = null,
)

/** #15 — one recipient's unlock record on the sender's lottery (who drew what). */
@JsonClass(generateAdapter = true)
data class LotterySenderUnlockDto(
    @Json(name = "recipient_id") val recipientId: String = "",
    @Json(name = "unlocked_at") val unlockedAt: Long? = null,
    @Json(name = "selected_outcome") val selectedOutcome: LotterySenderOutcomeDto? = null,
)
