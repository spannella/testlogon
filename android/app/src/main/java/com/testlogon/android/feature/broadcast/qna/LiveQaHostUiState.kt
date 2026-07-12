package com.testlogon.android.feature.broadcast.qna

import com.testlogon.android.data.broadcast.qna.QaHostQuestion
import com.testlogon.android.data.broadcast.qna.QaStats

/** Stable testTags for the live-QA host console (web LiveQaPage host view). */
object LiveQaHostTestTags {
    const val SCREEN = "live_qa_host_screen"
    const val MODE_SWITCH = "live_qa_host_mode_switch"
    const val QUEUE = "live_qa_host_queue"
    const val ERROR_RETRY = "live_qa_host_error_retry"

    fun row(id: String) = "live_qa_host_row_$id"
    fun feature(id: String) = "live_qa_host_feature_$id"
    fun answer(id: String) = "live_qa_host_answer_$id"
    fun dismiss(id: String) = "live_qa_host_dismiss_$id"
}

/** Which moderation queue the host is viewing. Maps to the backend `status` filter. */
enum class QaQueueFilter(val status: String) {
    PENDING("pending"),
    FEATURED("featured"),
    ANSWERED("answered"),
}

/**
 * Exhaustive host-console state (web LiveQaPage host view): a mode toggle, an engagement-stats summary, and
 * the moderation queue (filterable by status) with per-row feature / answer / dismiss / pin / remove actions.
 * [Loading] first load; [Content] the console; [Error] the retry surface.
 */
sealed interface LiveQaHostUiState {

    data object Loading : LiveQaHostUiState

    data class Content(
        val qaModeEnabled: Boolean,
        val togglingMode: Boolean = false,
        val filter: QaQueueFilter = QaQueueFilter.PENDING,
        val questions: List<QaHostQuestion> = emptyList(),
        val stats: QaStats? = null,
        val loadingQueue: Boolean = false,
        val actingOnId: String? = null,
        val message: String? = null,
    ) : LiveQaHostUiState

    data class Error(val message: String) : LiveQaHostUiState
}
