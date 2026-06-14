package com.testlogon.android.data.feed

/**
 * AND-179 — domain model + mapping for the embedded feed poll (framework-free, JVM-unit-test safe).
 *
 * Per the verified contract a poll is a LIST of questions, each carrying its own options, choice mode,
 * per-question vote counts, and the viewer's own votes. Counts/myVotes are merged from the post's
 * separate poll_vote_counts / poll_my_votes maps. Percentages are computed against the QUESTION total
 * (web parity: count / questionTotal). closes_at is epoch seconds.
 */
data class Poll(
    val postId: String,
    val questions: List<PollQuestion>,
    val totalVotes: Int,
    val closed: Boolean,
    val closesAtEpochSeconds: Long?,
    val anonymous: Boolean,
    val allowVoteChange: Boolean,
) {
    val isInteractive: Boolean get() = !closed
}

data class PollQuestion(
    val id: String,
    val text: String,
    val choiceMode: ChoiceMode,
    val maxSelections: Int?,
    val options: List<PollOption>,
    /** optionId -> count. */
    val counts: Map<String, Int>,
    /** the viewer's selected option ids for this question. */
    val myVoteOptionIds: List<String>,
) {
    val questionTotal: Int get() = counts.values.sum()
    val hasVoted: Boolean get() = myVoteOptionIds.isNotEmpty()
    fun isOptionSelected(optionId: String): Boolean = optionId in myVoteOptionIds
    fun countFor(optionId: String): Int = counts[optionId] ?: 0

    /** Percentage of [optionId] against the question total (0 when total is 0). */
    fun percentFor(optionId: String): Int {
        val total = questionTotal
        if (total <= 0) return 0
        return Math.round(countFor(optionId) * 100f / total)
    }
}

enum class ChoiceMode { SINGLE, MULTI }

data class PollOption(
    val id: String,
    val text: String,
)

// ---- Mapping (pure, side-effect free) ----

internal fun String?.toChoiceMode(): ChoiceMode = when (this) {
    "multi" -> ChoiceMode.MULTI
    else -> ChoiceMode.SINGLE // unknown / "single" -> SINGLE (FR-9)
}

/**
 * Builds a [Poll] from the post's embedded poll fields. Returns null when there is no poll_data.
 * [voteCounts] = poll_vote_counts ({questionId: {optionId: count}});
 * [myVotes] = poll_my_votes ({questionId: [optionId]}).
 */
internal fun PostDto.toPoll(): Poll? {
    val data = pollData ?: return null
    val countsByQuestion = pollVoteCounts.orEmpty()
    val myVotesByQuestion = pollMyVotes.orEmpty()
    return Poll(
        postId = postId,
        questions = data.questions.map { q ->
            PollQuestion(
                id = q.questionId,
                text = q.text,
                choiceMode = q.choiceMode.toChoiceMode(),
                maxSelections = q.maxSelections,
                options = q.options.map { PollOption(id = it.optionId, text = it.text) },
                counts = countsByQuestion[q.questionId].orEmpty(),
                myVoteOptionIds = myVotesByQuestion[q.questionId].orEmpty(),
            )
        },
        totalVotes = data.totalVotes,
        closed = data.closed,
        closesAtEpochSeconds = data.closesAt,
        anonymous = data.anonymous,
        allowVoteChange = data.allowVoteChange,
    )
}

/** Domain projection of a VoteResponse (per-question cast/remove result). */
data class PollVoteResult(
    val questionId: String,
    val voteCounts: Map<String, Int>,
    val totalVotes: Int,
    val myVoteOptionIds: List<String>,
)

internal fun PollVoteResponseDto.toDomain(): PollVoteResult = PollVoteResult(
    questionId = questionId,
    voteCounts = voteCounts,
    totalVotes = totalVotes,
    // single mode returns my_vote; multi returns my_votes.
    myVoteOptionIds = myVotes ?: listOfNotNull(myVote),
)

/**
 * Merges a per-question [PollVoteResult] into this poll: replaces the matching question's counts +
 * myVotes and updates the poll-wide total from the response. Pure / JVM-testable.
 */
internal fun Poll.applyVote(result: PollVoteResult): Poll = copy(
    totalVotes = result.totalVotes,
    questions = questions.map { q ->
        if (q.id != result.questionId) {
            q
        } else {
            q.copy(counts = result.voteCounts, myVoteOptionIds = result.myVoteOptionIds)
        }
    },
)
