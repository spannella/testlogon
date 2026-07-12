package com.testlogon.android.feature.moderation

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.moderation.ModerationCase
import com.testlogon.android.data.moderation.ModerationReviewRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * MOD-D2 — drives the "My content under review" screen: loads the caller's open moderation cases and
 * runs the two hold actions (respond / close). CLOSE deletes the content immediately, so the screen
 * gates it behind a confirm dialog before calling [close].
 */
@HiltViewModel
class MyContentReviewViewModel @Inject constructor(
    private val repository: ModerationReviewRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MyContentReviewUiState())
    val uiState: StateFlow<MyContentReviewUiState> = _uiState.asStateFlow()

    private val _effects = Channel<ReviewEffect>(Channel.BUFFERED)
    val effects: Flow<ReviewEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        _uiState.update {
            if (it.phase == MyContentReviewUiState.Phase.Content) {
                it.copy(isRefreshing = fromUser)
            } else {
                it.copy(phase = MyContentReviewUiState.Phase.Loading)
            }
        }
        viewModelScope.launch {
            when (val result = repository.listMyCases()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = if (result.data.isEmpty()) {
                            MyContentReviewUiState.Phase.Empty
                        } else {
                            MyContentReviewUiState.Phase.Content
                        },
                        cases = result.data,
                        isRefreshing = false,
                    )
                }

                is ApiResult.Failure ->
                    reduceError(result.error.status == 401, hadContent = _uiState.value.cases.isNotEmpty())

                is ApiResult.NetworkError ->
                    reduceError(sessionExpired = false, hadContent = _uiState.value.cases.isNotEmpty())
            }
        }
    }

    private suspend fun reduceError(sessionExpired: Boolean, hadContent: Boolean) {
        if (sessionExpired) {
            _uiState.update { it.copy(phase = MyContentReviewUiState.Phase.SessionExpired, isRefreshing = false) }
            return
        }
        if (hadContent) {
            _uiState.update { it.copy(isRefreshing = false) }
            _effects.send(ReviewEffect.ShowMessage(R.string.moderation_review_load_failed))
        } else {
            _uiState.update { it.copy(phase = MyContentReviewUiState.Phase.Error, isRefreshing = false) }
        }
    }

    /** Submit the poster's statement on a held case. On success reloads so the state flips. */
    fun onSubmitResponse(caseId: String, statement: String) {
        if (statement.isBlank()) return
        _uiState.update { it.copy(inFlightCaseId = caseId) }
        viewModelScope.launch {
            when (repository.respond(caseId, statement)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(inFlightCaseId = null) }
                    _effects.send(ReviewEffect.ShowMessage(R.string.moderation_review_response_sent))
                    load(fromUser = false)
                }
                else -> {
                    _uiState.update { it.copy(inFlightCaseId = null) }
                    _effects.send(ReviewEffect.ShowMessage(R.string.moderation_review_action_failed))
                }
            }
        }
    }

    /** Close & DELETE the content. Callers MUST have shown the confirm dialog first. */
    fun onConfirmClose(caseId: String) {
        _uiState.update { it.copy(inFlightCaseId = caseId) }
        viewModelScope.launch {
            when (repository.close(caseId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(inFlightCaseId = null) }
                    _effects.send(ReviewEffect.ShowMessage(R.string.moderation_review_content_deleted))
                    load(fromUser = false)
                }
                else -> {
                    _uiState.update { it.copy(inFlightCaseId = null) }
                    _effects.send(ReviewEffect.ShowMessage(R.string.moderation_review_action_failed))
                }
            }
        }
    }
}

/** One-shot UI effects (snackbars). Channel-backed so they are not replayed on config change. */
sealed interface ReviewEffect {
    data class ShowMessage(@StringRes val resId: Int) : ReviewEffect
}

/** Single immutable render state for the review screen. */
data class MyContentReviewUiState(
    val phase: Phase = Phase.Loading,
    val cases: List<ModerationCase> = emptyList(),
    val isRefreshing: Boolean = false,
    /** The case with an action currently in flight (respond/close), for per-card spinners. */
    val inFlightCaseId: String? = null,
) {
    enum class Phase { Loading, Content, Empty, Error, SessionExpired }
}
