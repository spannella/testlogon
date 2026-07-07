package com.testlogon.android.core.network.poll

import com.squareup.moshi.Json

/**
 * Canonical wire DTOs for ARBITRARY text-option polls, shared by the group + syndicate feed DTOs
 * (core-network) and the :app messaging + vote client. Reflective (decoded via the shared Moshi's
 * KotlinJsonAdapterFactory) — every snake_case key is pinned with @Json.
 */

/** Create input embedded on a group/syndicate poll post (matches backend arbitrary_polls.PollCreateIn). */
data class PollInputDto(
    @Json(name = "question") val question: String,
    @Json(name = "options") val options: List<String>,
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "max_selections") val maxSelections: Int? = null,
    @Json(name = "closes_at") val closesAt: Long? = null,
)

/** Live poll snapshot embedded on a post/message (arbitrary_polls._snapshot shape). */
data class PollSnapshotDto(
    @Json(name = "poll_id") val pollId: String = "",
    @Json(name = "owner") val owner: String? = null,
    @Json(name = "question") val question: String? = null,
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "questions") val questions: List<PollSnapshotQuestionDto> = emptyList(),
    @Json(name = "closed") val closed: Boolean = false,
    @Json(name = "closes_at") val closesAt: Long? = null,
    @Json(name = "total_votes") val totalVotes: Int = 0,
    @Json(name = "vote_counts") val voteCounts: Map<String, Map<String, Int>> = emptyMap(),
    @Json(name = "my_votes") val myVotes: Map<String, List<String>>? = null,
)

data class PollSnapshotQuestionDto(
    @Json(name = "question_id") val questionId: String = "",
    @Json(name = "text") val text: String = "",
    @Json(name = "choice_mode") val choiceMode: String = "single",
    @Json(name = "options") val options: List<PollSnapshotOptionDto> = emptyList(),
    @Json(name = "max_selections") val maxSelections: Int? = null,
)

data class PollSnapshotOptionDto(
    @Json(name = "option_id") val optionId: String = "",
    @Json(name = "text") val text: String = "",
)
