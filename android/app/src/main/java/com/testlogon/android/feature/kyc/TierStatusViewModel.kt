package com.testlogon.android.feature.kyc

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.kyc.data.KycTierRepository
import com.testlogon.android.feature.kyc.model.TierEvaluation
import com.testlogon.android.feature.kyc.model.TierStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-320 — presentation logic for the KYC Tier Status screen.
 *
 * [uiState] is a plain (synchronous) [MutableStateFlow] reduced from the repository:
 *  - init does a SINGLE one-shot refresh (NO delay/poll loop) and starts observing the DataStore cache so
 *    a warm snapshot renders instantly while the refresh is in flight.
 *  - [onEvaluate] keeps Content visible (evaluating = true) while POSTing; on success it swaps in the new
 *    tier/target/requirements (the repo already re-fetched requirements) and emits [TierEvent.Promoted]
 *    when the tier advanced.
 *  - Stale-while-error: a refresh failure with a warm cache keeps Content (stale = true + inlineError)
 *    rather than dropping to [TierUiState.Error]; only a COLD failure (no content) becomes Error.
 */
@HiltViewModel
class TierStatusViewModel @Inject constructor(
    private val repository: KycTierRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<TierUiState>(TierUiState.Loading)
    val state: StateFlow<TierUiState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<TierEvent>(extraBufferCapacity = 8)
    val events: SharedFlow<TierEvent> = _events.asSharedFlow()

    init {
        observeCache()
        refresh()
    }

    /** Streams the cached snapshot into Content (only while we are not already showing fresher content). */
    private fun observeCache() {
        viewModelScope.launch {
            repository.observeTierStatus().collect { cached ->
                if (cached != null && _state.value is TierUiState.Loading) {
                    _state.value = cached.toContent()
                }
            }
        }
    }

    /** One-shot refresh (NOT looping). Used by init, pull-to-refresh, and cold-error retry. */
    fun refresh() {
        val warm = currentContent()
        _state.value = warm?.copy(refreshing = true) ?: TierUiState.Loading
        viewModelScope.launch {
            when (val result = repository.refreshTierStatus()) {
                is ApiResult.Success -> _state.value = result.data.toContent()
                is ApiResult.Failure -> onRefreshFailed(result.error.message, canRetry = true, warm = warm)
                is ApiResult.NetworkError -> onRefreshFailed(OFFLINE, canRetry = true, warm = warm)
            }
        }
    }

    /** Cold-error retry is just a one-shot refresh. */
    fun onRetry() = refresh()

    /**
     * Evaluate eligibility. Keeps the current Content visible with evaluating = true; on success replaces
     * the tier/target/requirements and (if promoted) emits [TierEvent.Promoted]. On failure the content is
     * kept and a snackbar is emitted (the action is idempotent enough to retry).
     */
    fun onEvaluate() {
        val content = currentContent() ?: return
        if (content.evaluating) return
        _state.value = content.copy(evaluating = true, inlineError = null)
        viewModelScope.launch {
            when (val result = repository.evaluate()) {
                is ApiResult.Success -> applyEvaluation(result.data)
                is ApiResult.Failure -> onEvaluateFailed(result.error.message)
                is ApiResult.NetworkError -> onEvaluateFailed(OFFLINE)
            }
        }
    }

    private fun applyEvaluation(evaluation: TierEvaluation) {
        _state.value = evaluation.tierStatus.toContent()
        if (evaluation.promoted) {
            _events.tryEmit(TierEvent.Promoted(evaluation.tierStatus.current.level))
        }
    }

    private fun onEvaluateFailed(message: String) {
        currentContent()?.let { _state.value = it.copy(evaluating = false) }
        _events.tryEmit(TierEvent.Snackbar(message))
    }

    private fun onRefreshFailed(message: String, canRetry: Boolean, warm: TierUiState.Content?) {
        _state.value = if (warm != null) {
            warm.copy(refreshing = false, stale = true, inlineError = message)
        } else {
            TierUiState.Error(message, canRetry)
        }
    }

    private fun currentContent(): TierUiState.Content? = _state.value as? TierUiState.Content

    private fun TierStatus.toContent(): TierUiState.Content = TierUiState.Content(
        current = current,
        updatedAt = updatedAt,
        target = target,
        requirements = requirements,
        eligibleForTarget = eligibleForTarget,
        history = history,
    )

    private companion object {
        // Non-resource fallback (the screen prefers stringResource where it has a Context).
        const val OFFLINE = "Couldn't reach the server. Try again."
    }
}
