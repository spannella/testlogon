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
) {
    val total: Int get() = options.sumOf { it.count }
    fun isSelected(optionId: String): Boolean = optionId in myVoteOptionIds
    fun percentFor(optionId: String): Int {
        val t = total
        if (t <= 0) return 0
        val c = options.firstOrNull { it.id == optionId }?.count ?: 0
        return Math.round(c * 100f / t)
    }
}

data class ArbitraryPollOption(
    val id: String,
    val text: String,
    val count: Int,
)
