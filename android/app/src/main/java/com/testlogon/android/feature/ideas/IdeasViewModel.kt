package com.testlogon.android.feature.ideas

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.ideas.IdeasPage
import com.testlogon.android.data.ideas.IdeasRepository
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
 * Drives [IdeasUiState] from [IdeasRepository].
 *
 * Loads the member's submitted ideas on first composition / pull-to-refresh. The app-bar "+" (and the
 * empty-state action) open a submit form (Title + Description); a successful submit reloads the list and
 * shows a snackbar. A hard 401 (after the network layer refresh+retry) maps to SessionExpired; a failed
 * refresh with a cached page shows a stale banner, else Error/Offline. Effects are Channel-backed so
 * they are not replayed.
 */
@HiltViewModel
class IdeasViewModel @Inject constructor(
    private val repository: IdeasRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(IdeasUiState())
    val uiState: StateFlow<IdeasUiState> = _uiState.asStateFlow()

    private val _effects = Channel<IdeasEffect>(Channel.BUFFERED)
    val effects: Flow<IdeasEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    // ---- Submit form ----

    fun onOpenSubmit() {
        _uiState.update { it.copy(submit = SubmitFormState(isOpen = true)) }
    }

    fun onDismissSubmit() {
        if (_uiState.value.submit.isSubmitting) return
        _uiState.update { it.copy(submit = SubmitFormState(isOpen = false)) }
    }

    fun onTitleChange(value: String) {
        _uiState.update { it.copy(submit = it.submit.copy(title = value)) }
    }

    fun onDescriptionChange(value: String) {
        _uiState.update { it.copy(submit = it.submit.copy(description = value)) }
    }

    fun onSubmit() {
        val form = _uiState.value.submit
        if (!form.canSubmit) return
        _uiState.update { it.copy(submit = it.submit.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val result = repository.submitIdea(form.title, form.description)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(submit = SubmitFormState(isOpen = false)) }
                    _effects.send(IdeasEffect.ShowMessage(R.string.ideas_submit_success))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(submit = it.submit.copy(isSubmitting = false)) }
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = IdeasUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(IdeasEffect.ShowMessage(R.string.ideas_submit_failed))
                    }
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(submit = it.submit.copy(isSubmitting = false)) }
                    _effects.send(IdeasEffect.ShowMessage(R.string.ideas_submit_failed))
                }
            }
        }
    }

    // ---- Load ----

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.page != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else IdeasUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadIdeas()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = IdeasUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: IdeasPage) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) IdeasUiState.Phase.Empty else IdeasUiState.Phase.Content,
                page = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cached()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) IdeasUiState.Phase.Empty else IdeasUiState.Phase.Content,
                    page = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(IdeasEffect.ShowMessage(R.string.ideas_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) IdeasUiState.Phase.Offline else IdeasUiState.Phase.Error,
                    page = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
