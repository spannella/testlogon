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
)

@JsonClass(generateAdapter = true)
data class PollQuestionDto(
    @Json(name = "question_id") val questionId: String,
    @Json(name = "text") val text: String = "",
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "options") val options: List<PollOptionDto> = emptyList(),
    @Json(name = "max_selections") val maxSelections: Int? = null,
)

@JsonClass(generateAdapter = true)
data class PollOptionDto(
    @Json(name = "option_id") val optionId: String,
    @Json(name = "text") val text: String = "",
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
