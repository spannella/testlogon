package com.testlogon.android.data.messaging

import com.testlogon.android.core.data.messaging.MeetingPollWithSlots

/**
 * AND-136 — domain model for the meeting (availability) poll, mapped from [MeetingPollStateDto].
 *
 * The poll is a yes/maybe/no availability poll over datetime slots. Each slot carries its three
 * counts and the caller's own response independently. Timestamps are kept as the raw ISO-8601 UTC
 * strings on the wire and parsed/formatted only in a @Composable / pure helper (never here, to keep
 * this JVM-unit-testable without java.time API-26 concerns).
 */
enum class MeetingPollStatus { OPEN, CONFIRMED, CANCELLED }

/** The caller's per-slot availability response. */
enum class SlotVote { YES, MAYBE, NO }

data class MeetingPoll(
    val pollId: String,
    val title: String,
    val durationMinutes: Int,
    val creatorId: String,
    val status: MeetingPollStatus,
    val confirmedSlotId: String?,
    val slots: List<MeetingPollSlot>,
)

data class MeetingPollSlot(
    val slotId: String,
    val startUtc: String,
    val endUtc: String,
    val yesCount: Int,
    val maybeCount: Int,
    val noCount: Int,
    val myVote: SlotVote?,
) {
    /** Denominator for an optional proportion bar (per-slot sum; there is no server total_voters). */
    val totalResponses: Int get() = yesCount + maybeCount + noCount
}

// ---- enum <-> wire mappers (pure / JVM-testable) ----

internal fun String?.toSlotVote(): SlotVote? = when (this) {
    "yes" -> SlotVote.YES
    "maybe" -> SlotVote.MAYBE
    "no" -> SlotVote.NO
    else -> null
}

internal fun SlotVote.wire(): String = when (this) {
    SlotVote.YES -> "yes"
    SlotVote.MAYBE -> "maybe"
    SlotVote.NO -> "no"
}

internal fun String?.toPollStatus(): MeetingPollStatus = when (this) {
    "confirmed" -> MeetingPollStatus.CONFIRMED
    "cancelled" -> MeetingPollStatus.CANCELLED
    else -> MeetingPollStatus.OPEN
}

internal fun MeetingPollStateDto.toDomain(): MeetingPoll = MeetingPoll(
    pollId = pollId,
    title = title,
    durationMinutes = durationMinutes,
    creatorId = creatorId,
    status = status.toPollStatus(),
    confirmedSlotId = confirmedSlotId,
    slots = slots.map { it.toDomain() },
)

internal fun MeetingPollSlotStateDto.toDomain(): MeetingPollSlot = MeetingPollSlot(
    slotId = slotId,
    startUtc = startUtc,
    endUtc = endUtc,
    yesCount = yesCount,
    maybeCount = maybeCount,
    noCount = noCount,
    myVote = myVote.toSlotVote(),
)

/**
 * Cycle the per-slot response on tap: none -> yes -> maybe -> no -> none. Pure, JVM-testable.
 * Returns null to clear (which omits the slot from the `votes` map sent to the backend).
 */
internal fun SlotVote?.cycle(): SlotVote? = when (this) {
    null -> SlotVote.YES
    SlotVote.YES -> SlotVote.MAYBE
    SlotVote.MAYBE -> SlotVote.NO
    SlotVote.NO -> null
}

/**
 * AND-136 — apply an optimistic per-slot vote to a poll snapshot before the network round-trip:
 * removes the caller's previous response from its tally, applies the new one, and updates my_vote.
 * Pure, so it can be unit-tested without Room/network. [newVote] = null clears the response.
 */
/** AND-136 — Room relation -> domain mapper (slots ordered by their stored position). */
internal fun MeetingPollWithSlots.toDomain(): MeetingPoll = MeetingPoll(
    pollId = poll.pollId,
    title = poll.title,
    durationMinutes = poll.durationMinutes,
    creatorId = poll.creatorId,
    status = poll.status.toPollStatus(),
    confirmedSlotId = poll.confirmedSlotId,
    slots = slots.sortedBy { it.position }.map { s ->
        MeetingPollSlot(
            slotId = s.slotId,
            startUtc = s.startUtc,
            endUtc = s.endUtc,
            yesCount = s.yesCount,
            maybeCount = s.maybeCount,
            noCount = s.noCount,
            myVote = s.myVote.toSlotVote(),
        )
    },
)

/**
 * AND-136 — build the `votes` map for a [PollVoteReq]: every slot the caller has already responded
 * to, with [slotId] updated to [newVote] (or omitted entirely when [newVote] is null = clear).
 * Pure / JVM-testable.
 */
internal fun buildVotesMap(
    current: MeetingPoll?,
    slotId: String,
    newVote: SlotVote?,
): Map<String, String> {
    val map = LinkedHashMap<String, String>()
    current?.slots?.forEach { slot ->
        slot.myVote?.let { map[slot.slotId] = it.wire() }
    }
    if (newVote == null) map.remove(slotId) else map[slotId] = newVote.wire()
    return map
}

/** AND-135 — infer GIF/WebP animation from a content_type (no `animated` boolean on the wire). */
internal fun isAnimatedContentType(contentType: String?): Boolean {
    val ct = contentType?.lowercase(java.util.Locale.ROOT) ?: return false
    return ct == "image/gif" || ct == "image/webp"
}

internal fun MeetingPoll.applyOptimisticVote(slotId: String, newVote: SlotVote?): MeetingPoll =
    copy(
        slots = slots.map { slot ->
            if (slot.slotId != slotId) return@map slot
            // Undo the prior response.
            var yes = slot.yesCount
            var maybe = slot.maybeCount
            var no = slot.noCount
            when (slot.myVote) {
                SlotVote.YES -> yes = (yes - 1).coerceAtLeast(0)
                SlotVote.MAYBE -> maybe = (maybe - 1).coerceAtLeast(0)
                SlotVote.NO -> no = (no - 1).coerceAtLeast(0)
                null -> Unit
            }
            // Apply the new response.
            when (newVote) {
                SlotVote.YES -> yes += 1
                SlotVote.MAYBE -> maybe += 1
                SlotVote.NO -> no += 1
                null -> Unit
            }
            slot.copy(yesCount = yes, maybeCount = maybe, noCount = no, myVote = newVote)
        },
    )
