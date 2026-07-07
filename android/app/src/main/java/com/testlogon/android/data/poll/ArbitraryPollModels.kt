package com.testlogon.android.data.poll

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.poll.ArbitraryPoll
import com.testlogon.android.core.model.poll.ArbitraryPollOption
import com.testlogon.android.core.model.poll.ArbitraryPollPage
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

/** Write-in body for POST /ui/polls/{poll_id}/write-in. */
@JsonClass(generateAdapter = true)
data class ArbitraryPollWriteInReq(
    @Json(name = "text") val text: String,
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
    /** Sender-controlled: allow voters to add their own write-in options. */
    @Json(name = "allow_write_in") val allowWriteIn: Boolean = false,
)

/**
 * Paginated results for a single question (GET /ui/polls/{id}/results). Options are sorted by count
 * desc with write-in flags; used to page the "show more" reveal in the poll card.
 */
@JsonClass(generateAdapter = true)
data class PollResultsDto(
    @Json(name = "question_id") val questionId: String = "",
    @Json(name = "options") val options: List<PollResultOptionDto> = emptyList(),
    @Json(name = "total_options") val totalOptions: Int = 0,
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "offset") val offset: Int = 0,
    @Json(name = "top_n") val topN: Int? = null,
    @Json(name = "next_offset") val nextOffset: Int? = null,
    @Json(name = "total_votes") val totalVotes: Int = 0,
    @Json(name = "allow_write_in") val allowWriteIn: Boolean = false,
    @Json(name = "closed") val closed: Boolean = false,
    @Json(name = "my_vote") val myVote: String? = null,
    @Json(name = "my_votes") val myVotes: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class PollResultOptionDto(
    @Json(name = "option_id") val optionId: String = "",
    @Json(name = "text") val text: String = "",
    @Json(name = "count") val count: Int = 0,
    @Json(name = "percentage") val percentage: Double = 0.0,
    @Json(name = "is_write_in") val isWriteIn: Boolean = false,
    @Json(name = "author") val author: String? = null,
)

fun PollResultsDto.toPage(): ArbitraryPollPage = ArbitraryPollPage(
    questionId = questionId,
    options = options.map {
        ArbitraryPollOption(
            id = it.optionId,
            text = it.text,
            count = it.count,
            isWriteIn = it.isWriteIn,
            author = it.author,
        )
    },
    totalOptions = totalOptions,
    hasMore = hasMore,
    nextOffset = nextOffset,
    totalVotes = totalVotes,
    myVoteOptionIds = myVotes ?: listOfNotNull(myVote),
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
                    ArbitraryPollOption(
                        id = o.optionId,
                        text = o.text,
                        count = counts[o.optionId] ?: 0,
                        isWriteIn = o.isWriteIn,
                        author = o.author,
                    )
                },
                myVoteOptionIds = my[q.questionId].orEmpty(),
                allowWriteIn = allowWriteIn || q.allowWriteIn,
            )
        },
        closed = closed,
        closesAtEpochSeconds = closesAt,
        totalVotes = totalVotes,
        owner = owner,
        allowWriteIn = allowWriteIn || questions.any { it.allowWriteIn },
    )
}
