package com.testlogon.android.data.messaging.realtime

/**
 * AND-147 — pure, JVM-testable read-receipt reducer.
 *
 * Derives the per-message delivery/seen state shown on the LOCAL user's own outbound messages, and
 * folds live `message:viewed` SSE events into a viewer roster. No Android / network / Room types — so
 * the receipt mapping is fully unit-tested without a device (spec §11 / TC-AND-147-03/04/07).
 *
 * State precedence on an outbound message (verified against the web DeliveryStatus + the Message
 * payload fields read_by_count / delivered_to_count — AND-147 §3 FR-2/FR-3):
 *   SEEN     when at least one DISTINCT non-self viewer is known (read_by_count>0 or a roster entry),
 *   DELIVERED when delivered_to_count>0 (or a delivered_to_user_ids entry exists) but not yet seen,
 *   else the message keeps its send state (SENDING/SENT/FAILED) — receipts never downgrade a send.
 */
enum class ReceiptStatus { SENDING, SENT, DELIVERED, SEEN, FAILED }

/** A single viewer of a message, sorted most-recent-first for the roster sheet. Identity-free. */
data class MessageViewer(
    val userId: String,
    val viewedAtEpochSeconds: Long,
    val viewCount: Int,
)

/** Aggregate receipt state for one outbound message. [seenCount] excludes the local user (FR-6). */
data class MessageReceipt(
    val status: ReceiptStatus,
    val deliveredCount: Int,
    val seenCount: Int,
    val firstSeenAtEpochSeconds: Long?,
    val viewers: List<MessageViewer>,
)

object ReceiptReducer {

    /**
     * Derive the receipt state for an OWN outbound message from the authoritative payload counts plus
     * any locally-known viewers. [selfUserId] is filtered out of seen everywhere (FR-6).
     *
     * @param sendStatus the base send state ("SENDING"|"SENT"|"FAILED").
     */
    fun derive(
        sendStatus: ReceiptStatus,
        deliveredToCount: Int?,
        deliveredToUserIds: List<String>?,
        readByCount: Int?,
        readByUserIds: List<String>?,
        viewers: List<MessageViewer> = emptyList(),
        selfUserId: String? = null,
    ): MessageReceipt {
        val rosterSeen = viewers.filter { it.userId != selfUserId }
        // Distinct non-self readers: union of the payload ids and the live roster (idempotent).
        val payloadReaders = (readByUserIds ?: emptyList()).filter { it != selfUserId }
        val distinctSeen = (payloadReaders + rosterSeen.map { it.userId }).toSet()
        val seenCount = maxOf(
            distinctSeen.size,
            // read_by_count is authoritative when it exceeds what we have locally; the server already
            // excludes self (web parity), so use it as a floor but never below the distinct set.
            (readByCount ?: 0).coerceAtLeast(0),
        )
        val delivered = maxOf(deliveredToCount ?: 0, (deliveredToUserIds ?: emptyList()).size)
        val status = when {
            sendStatus == ReceiptStatus.FAILED -> ReceiptStatus.FAILED
            sendStatus == ReceiptStatus.SENDING -> ReceiptStatus.SENDING
            seenCount > 0 -> ReceiptStatus.SEEN
            delivered > 0 -> ReceiptStatus.DELIVERED
            else -> ReceiptStatus.SENT
        }
        return MessageReceipt(
            status = status,
            deliveredCount = delivered,
            seenCount = if (status == ReceiptStatus.SEEN) seenCount.coerceAtLeast(1) else seenCount,
            firstSeenAtEpochSeconds = rosterSeen.minByOrNull { it.viewedAtEpochSeconds }?.viewedAtEpochSeconds,
            viewers = rosterSeen.sortedByDescending { it.viewedAtEpochSeconds },
        )
    }

    /**
     * Fold a live [MessagingEvent.MessageViewed] into a current viewer roster, idempotently. A
     * repeated event for the same viewer updates that viewer's timestamp/count in place rather than
     * adding a duplicate row (AC-3 / TC-AND-147-04). The local user is never added (FR-6).
     */
    fun applyViewed(
        current: List<MessageViewer>,
        event: MessagingEvent.MessageViewed,
        selfUserId: String? = null,
    ): List<MessageViewer> {
        if (event.viewerId == selfUserId) return current
        val existing = current.firstOrNull { it.userId == event.viewerId }
        val updated = MessageViewer(
            userId = event.viewerId,
            viewedAtEpochSeconds = maxOf(event.viewedAtEpochSeconds, existing?.viewedAtEpochSeconds ?: 0L),
            viewCount = (existing?.viewCount ?: 0) + 1,
        )
        val rest = current.filterNot { it.userId == event.viewerId }
        return (rest + updated).sortedByDescending { it.viewedAtEpochSeconds }
    }

    /** Map a network roster page (MessageViewOut-shaped triples) to domain viewers, self excluded. */
    fun fromRoster(
        rows: List<MessageViewer>,
        selfUserId: String? = null,
    ): List<MessageViewer> =
        rows.filter { it.userId != selfUserId }.sortedByDescending { it.viewedAtEpochSeconds }
}
