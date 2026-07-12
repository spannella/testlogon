package com.testlogon.android.data.feed

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-179 — wire DTOs for the embedded feed poll + the vote endpoints.
 *
 * Verified against reference/src/api/types.ts (PollData/PollQuestion/PollOption/PollVoteCounts/
 * PollMyVotes/VoteResponse) and src/api/endpoints/polls.ts:
 *  - a poll is a LIST of questions, each with its own options + choice_mode ("single"|"multi") +
 *    optional max_selections. Option field is "text" (NOT "label").
 *  - vote counts + the viewer's own votes travel beside poll_data on the post via poll_vote_counts
 *    ({questionId: {optionId: count}}) and poll_my_votes ({questionId: [optionId]}).
 *  - closes_at is epoch SECONDS (number), not an ISO string.
 *  - vote: POST /posts/{post_id}/vote, body VoteIn {question_id, option_id} -> VoteResponse
 *    (per-question counts), NOT the full poll.
 *  - remove vote: DELETE /posts/{post_id}/vote, body {question_id} -> VoteResponse.
 *
 * Lenient: all fields defaulted so unknown/missing keys never crash the page (Moshi ignores unknown
 * keys); an unknown choice_mode is tolerated and degrades to single at the domain layer (FR-9).
 */
@JsonClass(generateAdapter = true)
data class PollDataDto(
    @Json(name = "questions") val questions: List<PollQuestionDto> = emptyList(),
    @Json(name = "closes_at") val closesAt: Long? = null,
    @Json(name = "closed") val closed: Boolean = false,
    @Json(name = "anonymous") val anonymous: Boolean = false,
    @Json(name = "allow_vote_change") val allowVoteChange: Boolean = false,
    @Json(name = "total_votes") val totalVotes: Int = 0,
    /** Sender-controlled: at least one question accepts voter write-in options. */
    @Json(name = "allow_write_in") val allowWriteIn: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class PollQuestionDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "text") val text: String = "",
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "options") val options: List<PollOptionDto> = emptyList(),
    @Json(name = "max_selections") val maxSelections: Int? = null,
    @Json(name = "allow_write_in") val allowWriteIn: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class PollOptionDto(
    @Json(name = "option_id") val optionId: String,
    @Json(name = "text") val text: String = "",
    @Json(name = "is_write_in") val isWriteIn: Boolean = false,
    @Json(name = "author") val author: String? = null,
)

/** VoteResponse — per-question result of a cast/remove. */
@JsonClass(generateAdapter = true)
data class PollVoteResponseDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "question_id") val questionId: String,
    @Json(name = "option_id") val optionId: String? = null,
    @Json(name = "vote_counts") val voteCounts: Map<String, Int> = emptyMap(),
    @Json(name = "total_votes") val totalVotes: Int = 0,
    @Json(name = "my_vote") val myVote: String? = null,
    @Json(name = "my_votes") val myVotes: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class PollVoteRequestDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "option_id") val optionId: String,
)

@JsonClass(generateAdapter = true)
data class PollRemoveVoteRequestDto(
    @Json(name = "question_id") val questionId: String,
)

/** Write-in body for POST /posts/{post_id}/write-in. */
@JsonClass(generateAdapter = true)
data class PollWriteInRequestDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "text") val text: String,
)

/**
 * Paginated results for a question (GET /posts/{post_id}/poll-results). Options sorted by count desc
 * with write-in flags; also embedded under `results` in the write-in response.
 */
@JsonClass(generateAdapter = true)
data class PollResultsResponseDto(
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

/** Response of POST /posts/{post_id}/write-in (the cast result + the fresh paginated results). */
@JsonClass(generateAdapter = true)
data class PollWriteInResponseDto(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "question_id") val questionId: String = "",
    @Json(name = "option_id") val optionId: String = "",
    @Json(name = "created") val created: Boolean = false,
    @Json(name = "text") val text: String = "",
    @Json(name = "vote_counts") val voteCounts: Map<String, Int> = emptyMap(),
    @Json(name = "results") val results: PollResultsResponseDto? = null,
)
