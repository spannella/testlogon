package com.testlogon.android.data.messaging.legalhold

/**
 * AND-164 — domain models + pure mappers for legal holds (read-only). JVM-pure: no android.* and no
 * java.time API-26 (timestamps stay epoch-SECONDS Longs; the UI formats them).
 *
 * Shapes match the real LegalHoldOut schema: there is NO `label` and NO `custodian`/`requested_by` —
 * the human-facing fields are `reason` and `case_id`, and `created_at` is an integer epoch.
 */

/** Hold lifecycle status. Anything not `active` is treated as not-held. */
enum class HoldStatus {
    ACTIVE,
    RELEASED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): HoldStatus = when (value?.lowercase()) {
            "active" -> ACTIVE
            "released" -> RELEASED
            else -> UNKNOWN
        }
    }
}

/** Whether a resolved hold applies to a whole conversation or a single message. */
enum class HoldSource { CONVERSATION, MESSAGE }

/**
 * AND-164 — a single legal hold for the read-only indicator + detail sheet. There is no account/
 * workspace-level hold source (no backend field), so [HoldSource] is CONVERSATION or MESSAGE only.
 */
data class LegalHold(
    val holdId: String,
    val caseId: String,
    val reason: String,
    val status: HoldStatus,
    val createdAtEpochSeconds: Long?,
    val createdByUserId: String?,
    val messageId: String?,
    val source: HoldSource,
)

/** AND-164 — anything that may carry a hold; null == not held. */
interface Holdable {
    val legalHold: LegalHold?
}

val Holdable.isOnHold: Boolean get() = legalHold != null

// ---- pure mappers ----

/** AND-164 — wire hold -> domain (source derived from `message_id`: null => conversation, set => message). */
internal fun LegalHoldDto.toDomain(): LegalHold = LegalHold(
    holdId = holdId,
    caseId = caseId,
    reason = reason,
    status = HoldStatus.fromWire(status),
    createdAtEpochSeconds = createdAt,
    createdByUserId = createdByUserId,
    messageId = messageId,
    source = if (messageId == null) HoldSource.CONVERSATION else HoldSource.MESSAGE,
)

/**
 * AND-164 — pick the first ACTIVE hold matching the entity's (conversationId, messageId):
 *  - a conversation is held when an active hold with `message_id == null` exists for its id,
 *  - a message is held when an active hold with that exact `message_id` exists.
 *
 * `released` holds (and an empty list) yield null. A message-scoped hold does NOT mark the whole
 * conversation held, and vice-versa.
 */
internal fun resolveHold(
    holds: List<LegalHoldDto>,
    conversationId: String,
    messageId: String?,
): LegalHold? =
    holds.firstOrNull {
        HoldStatus.fromWire(it.status) == HoldStatus.ACTIVE &&
            it.conversationId == conversationId &&
            it.messageId == messageId
    }?.toDomain()
