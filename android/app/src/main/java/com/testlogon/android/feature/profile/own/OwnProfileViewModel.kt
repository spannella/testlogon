package com.testlogon.android.feature.profile.own

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.profile.ProfileRepository
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
 * AND-071 / AND-075 — drives [OwnProfileUiState] from [ProfileRepository].
 *
 * Loads on init, supports pull-to-refresh and retry, and keeps the last content behind a stale flag
 * when a refresh fails but cached content exists. One-shot messages / nav requests go on a
 * [Channel]-backed [effects] flow so they are not replayed on rotation.
 */
@HiltViewModel
class OwnProfileViewModel @Inject constructor(
    private val repository: ProfileRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(OwnProfileUiState())
    val uiState: StateFlow<OwnProfileUiState> = _uiState.asStateFlow()

    private val _effects = Channel<OwnProfileEffect>(Channel.BUFFERED)
    val effects: Flow<OwnProfileEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    fun onEditClicked() {
        _effects.trySend(OwnProfileEffect.NavigateToEdit)
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return // de-dup overlapping refreshes
        val hasContent = state.profile != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else OwnProfileUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.getOwnProfile(forceRefresh = fromUser)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = OwnProfileUiState.Phase.Content,
                        profile = result.data,
                        isRefreshing = false,
                        isStale = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> reduceFailure(result.error.message)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK)
            }
        }
    }

    private suspend fun reduceFailure(message: String) {
        val cached = repository.cachedOwnProfile()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = OwnProfileUiState.Phase.Content,
                    profile = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(OwnProfileEffect.ShowMessage(R.string.profile_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = OwnProfileUiState.Phase.Error,
                    profile = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
