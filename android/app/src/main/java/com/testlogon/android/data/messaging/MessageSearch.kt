package com.testlogon.android.data.messaging

import com.testlogon.android.core.ui.text.searchMatchRanges

/**
 * AND-151 / AND-152 — pure domain models + mappers for message search.
 *
 * The backend (see [MessagingApi.searchInConversation] / [MessagingApi.searchAllMessages]) returns a
 * bare array of MessageOut with NO per-occurrence highlight offsets, so all match offsets are computed
 * locally here from `text` + `query`. Matching is case-insensitive, literal (NOT regex — no ReDoS),
 * and Unicode-NFC-normalized to align with backend behaviour. Everything in this file is pure /
 * JVM-testable (no Android types).
 */

/**
 * AND-151 — one addressable match (a single occurrence inside one message's text). A message with
 * multiple occurrences flattens to multiple [MessageSearchMatch] rows so prev/next can step through
 * every hit. Offsets index into the ORIGINAL (non-normalized) text so the UI can highlight directly.
 */
data class MessageSearchMatch(
    val messageId: String,
    /** nth hit (0-based) inside this message's text. */
    val occurrenceIndex: Int,
    /** char offset of the hit start in the message text. */
    val start: Int,
    /** char offset (exclusive) of the hit end. */
    val end: Int,
    /** epoch SECONDS, from MessageOut.created_at. Drives MOST-RECENT-first ordering (#11). */
    val createdAtEpochSeconds: Long,
    /** the message body (for snippet rendering). */
    val text: String,
)

/**
 * AND-152 — one cross-conversation result row. Carries only what MessageOut provides; sender display
 * name / conversation title are resolved separately (client-side enrichment, not on the wire).
 */
data class MessageSearchResultItem(
    val messageId: String,
    val conversationId: String,
    val senderId: String,
    val kind: String,
    /** nullable on the wire; null for media kinds with no textual body. */
    val text: String?,
    val createdAtEpochSeconds: Long,
)

/**
 * AND-151 — flattens search hits (MessageOut[]) into an ordered list of [MessageSearchMatch]. Each
 * returned message is expanded into one row per local occurrence of [query] in its `text`. Messages
 * with null/blank text, or whose local matcher finds no occurrence (server tokenization may diverge),
 * are dropped. Sorted MOST-RECENT first (created_at descending), then by occurrenceIndex (stable cursor order).
 */
internal fun List<MessageDto>.toSearchMatches(query: String): List<MessageSearchMatch> =
    asSequence()
        .flatMap { dto ->
            val body = dto.text
            if (body.isNullOrEmpty()) {
                emptySequence()
            } else {
                searchMatchRanges(body, query).asSequence().mapIndexed { occurrence, range ->
                    MessageSearchMatch(
                        messageId = dto.messageId,
                        occurrenceIndex = occurrence,
                        start = range.first,
                        end = range.last + 1,
                        createdAtEpochSeconds = dto.createdAt,
                        text = body,
                    )
                }
            }
        }
        .sortedWith(
            // #11 — results ordered MOST-RECENT first down to oldest (descending created_at);
            // ties (same timestamp) stay stable by messageId, occurrences within a message ascending.
            compareByDescending<MessageSearchMatch> { it.createdAtEpochSeconds }
                .thenBy { it.messageId }
                .thenBy { it.occurrenceIndex },
        )
        .toList()

/** AND-152 — maps a wire MessageOut to a cross-conversation result item (tolerates null text). */
internal fun MessageDto.toSearchResultItem(): MessageSearchResultItem = MessageSearchResultItem(
    messageId = messageId,
    conversationId = conversationId,
    senderId = senderId,
    kind = kind,
    text = text,
    createdAtEpochSeconds = createdAt,
)
