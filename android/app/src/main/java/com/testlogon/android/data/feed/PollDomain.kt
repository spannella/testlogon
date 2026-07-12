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
    /** Sender-controlled: at least one question accepts voter write-in options. */
    val allowWriteIn: Boolean = false,
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
    /** Sender-controlled: voters may add their own write-in options to this question. */
    val allowWriteIn: Boolean = false,
) {
    val questionTotal: Int get() = counts.values.sum()
    val hasVoted: Boolean get() = myVoteOptionIds.isNotEmpty()
    val isMulti: Boolean get() = choiceMode == ChoiceMode.MULTI
    fun isOptionSelected(optionId: String): Boolean = optionId in myVoteOptionIds
    fun countFor(optionId: String): Int = counts[optionId] ?: 0

    /** Options ordered by count desc (stable on ties) — the order write-in polls display + paginate. */
    val optionsByCount: List<PollOption> get() = options.sortedByDescending { countFor(it.id) }

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
    /** True when a voter added this option as a write-in. */
    val isWriteIn: Boolean = false,
    /** The user_sub that authored a write-in option (null for seed / anonymous). */
    val author: String? = null,
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
                options = q.options.map {
                    PollOption(id = it.optionId, text = it.text, isWriteIn = it.isWriteIn, author = it.author)
                },
                counts = countsByQuestion[q.questionId].orEmpty(),
                myVoteOptionIds = myVotesByQuestion[q.questionId].orEmpty(),
                allowWriteIn = data.allowWriteIn || q.allowWriteIn,
            )
        },
        totalVotes = data.totalVotes,
        closed = data.closed,
        closesAtEpochSeconds = data.closesAt,
        anonymous = data.anonymous,
        allowVoteChange = data.allowVoteChange,
        allowWriteIn = data.allowWriteIn || data.questions.any { it.allowWriteIn },
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

// ---- Write-in + paginated results ----

/** Domain projection of one page of a question's options (sorted by count desc). */
data class PollResultsPage(
    val questionId: String,
    val options: List<PollOption>,
    val counts: Map<String, Int>,
    val totalOptions: Int,
    val hasMore: Boolean,
    val nextOffset: Int?,
    val totalVotes: Int,
    val myVoteOptionIds: List<String>,
)

internal fun PollResultsResponseDto.toPage(): PollResultsPage = PollResultsPage(
    questionId = questionId,
    options = options.map { PollOption(id = it.optionId, text = it.text, isWriteIn = it.isWriteIn, author = it.author) },
    counts = options.associate { it.optionId to it.count },
    totalOptions = totalOptions,
    hasMore = hasMore,
    nextOffset = nextOffset,
    totalVotes = totalVotes,
    myVoteOptionIds = myVotes ?: listOfNotNull(myVote),
)

/**
 * Upsert a fetched [page] into the matching question: merge in the page's options (fresh write-in flags),
 * update their counts, refresh myVotes + the poll total. Pure / JVM-testable.
 */
internal fun Poll.applyResultsPage(page: PollResultsPage): Poll = copy(
    totalVotes = page.totalVotes,
    questions = questions.map { q ->
        if (q.id != page.questionId) {
            q
        } else {
            val byId = q.options.associateBy { it.id }.toMutableMap()
            page.options.forEach { byId[it.id] = it }
            q.copy(
                options = byId.values.toList(),
                counts = q.counts + page.counts,
                myVoteOptionIds = page.myVoteOptionIds,
            )
        }
    },
)

/**
 * Apply a write-in response to the poll: ensure the (new or consolidated) option is present, adopt the
 * authoritative full vote_counts, refresh myVotes to include the write-in, and update the poll total.
 * [selfAuthor] marks a freshly-created option as authored by the current voter.
 */
internal fun Poll.applyWriteIn(
    questionId: String,
    response: PollWriteInResponseDto,
    selfAuthor: String?,
): Poll {
    val results = response.results
    return copy(
        totalVotes = results?.totalVotes ?: totalVotes,
        questions = questions.map { q ->
            if (q.id != questionId) {
                q
            } else {
                val byId = q.options.associateBy { it.id }.toMutableMap()
                results?.options?.forEach {
                    byId[it.optionId] = PollOption(it.optionId, it.text, it.isWriteIn, it.author)
                }
                if (response.optionId.isNotEmpty() && response.optionId !in byId) {
                    byId[response.optionId] =
                        PollOption(response.optionId, response.text, isWriteIn = true, author = selfAuthor)
                }
                val my = results?.let { it.myVotes ?: listOfNotNull(it.myVote) }
                    ?: (q.myVoteOptionIds + response.optionId).distinct()
                q.copy(
                    options = byId.values.toList(),
                    counts = response.voteCounts.ifEmpty { q.counts },
                    myVoteOptionIds = my.distinct(),
                )
            }
        },
    )
}
