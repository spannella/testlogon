package com.testlogon.android.data.poll

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.poll.ArbitraryPoll
import com.testlogon.android.core.model.poll.ArbitraryPollOption
import com.testlogon.android.core.model.poll.ArbitraryPollQuestion
import com.testlogon.android.core.network.poll.PollSnapshotDto

/**
 * ARBITRARY TEXT-OPTION POLL request DTOs (:app) + the snapshot -> domain mapping. The wire snapshot
 * DTO ([PollSnapshotDto]) + create input are canonical in core-network; the [ArbitraryPoll] domain is
 * in core-model. Distinct from the messaging meeting-time / find-a-time pickers.
 */

/** Vote body for POST /ui/polls/{poll_id}/vote. */
@JsonClass(generateAdapter = true)
data class ArbitraryPollVoteReq(
    @Json(name = "option_id") val optionId: String,
    @Json(name = "question_id") val questionId: String? = null,
)

/**
 * Shared create body used by the GROUP / SYNDICATE / MESSAGING composers (options are plain strings).
 * The newsfeed composer uses its own richer `poll_data` shape (data.feed CreatePostReq).
 */
@JsonClass(generateAdapter = true)
data class PollComposeBody(
    @Json(name = "question") val question: String,
    @Json(name = "options") val options: List<String>,
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "max_selections") val maxSelections: Int? = null,
    @Json(name = "closes_at") val closesAt: Long? = null,
)

fun PollSnapshotDto.toDomain(): ArbitraryPoll {
    val my = myVotes.orEmpty()
    return ArbitraryPoll(
        pollId = pollId,
        question = question ?: questions.firstOrNull()?.text.orEmpty(),
        questions = questions.map { q ->
            val counts = voteCounts[q.questionId].orEmpty()
            ArbitraryPollQuestion(
                id = q.questionId,
                text = q.text,
                multiSelect = q.choiceMode == "multi",
                maxSelections = q.maxSelections,
                options = q.options.map { o ->
                    ArbitraryPollOption(id = o.optionId, text = o.text, count = counts[o.optionId] ?: 0)
                },
                myVoteOptionIds = my[q.questionId].orEmpty(),
            )
        },
        closed = closed,
        closesAtEpochSeconds = closesAt,
        totalVotes = totalVotes,
        owner = owner,
    )
}
