package com.testlogon.android.core.model.poll

/**
 * ARBITRARY text-option poll domain (framework-free). Carried on group/syndicate feed posts and
 * messaging poll messages so those core-model types can reference it. DTO parsing + the vote client
 * live in :app (data.poll).
 */
data class ArbitraryPoll(
    val pollId: String,
    val question: String,
    val questions: List<ArbitraryPollQuestion>,
    val closed: Boolean,
    val closesAtEpochSeconds: Long?,
    val totalVotes: Int,
    val owner: String?,
    /** Sender-controlled: at least one question accepts voter-submitted write-in options. */
    val allowWriteIn: Boolean = false,
) {
    val isInteractive: Boolean get() = !closed
}

data class ArbitraryPollQuestion(
    val id: String,
    val text: String,
    val multiSelect: Boolean,
    val maxSelections: Int?,
    val options: List<ArbitraryPollOption>,
    val myVoteOptionIds: List<String>,
    /** Sender-controlled: voters may add their own write-in options to this question. */
    val allowWriteIn: Boolean = false,
) {
    val total: Int get() = options.sumOf { it.count }
    fun isSelected(optionId: String): Boolean = optionId in myVoteOptionIds
    fun percentFor(optionId: String): Int {
        val t = total
        if (t <= 0) return 0
        val c = options.firstOrNull { it.id == optionId }?.count ?: 0
        return Math.round(c * 100f / t)
    }

    /** Options ordered by count desc (stable on ties) — the order write-in polls display + paginate. */
    val optionsByCount: List<ArbitraryPollOption> get() = options.sortedByDescending { it.count }
}

data class ArbitraryPollOption(
    val id: String,
    val text: String,
    val count: Int,
    /** True when a voter added this option as a write-in. */
    val isWriteIn: Boolean = false,
    /** The user_sub that authored a write-in option (null for seed / anonymous). */
    val author: String? = null,
)

/**
 * A page of an arbitrary poll question's options from the paginated results endpoint (sorted by count
 * desc). Drives the write-in card's "show more" reveal.
 */
data class ArbitraryPollPage(
    val questionId: String,
    val options: List<ArbitraryPollOption>,
    val totalOptions: Int,
    val hasMore: Boolean,
    val nextOffset: Int?,
    val totalVotes: Int,
    val myVoteOptionIds: List<String>,
)
