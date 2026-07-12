package com.testlogon.android.feature.bots

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bots.Bot
import com.testlogon.android.data.bots.BotStatus
import com.testlogon.android.data.bots.BotsRepository
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
 * Drives [BotsListUiState] from [BotsRepository].
 *
 * Loads the bots list on first composition / pull-to-refresh. The app-bar "+" opens a create form
 * (name + optional description / personality); a successful create reloads and snackbars. Each row can
 * pause/activate the bot (PATCH status) or delete it (confirmed) -- both reload on success. A hard 401
 * maps to SessionExpired; a failed refresh with a cached list shows a stale banner, else Error/Offline.
 */
@HiltViewModel
class BotsListViewModel @Inject constructor(
    private val repository: BotsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(BotsListUiState())
    val uiState: StateFlow<BotsListUiState> = _uiState.asStateFlow()

    private val _effects = Channel<BotsListEffect>(Channel.BUFFERED)
    val effects: Flow<BotsListEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    // ---- Create form ----

    fun onOpenCreate() {
        _uiState.update { it.copy(create = CreateBotFormState(isOpen = true)) }
    }

    fun onDismissCreate() {
        if (_uiState.value.create.isSubmitting) return
        _uiState.update { it.copy(create = CreateBotFormState(isOpen = false)) }
    }

    fun onNameChange(value: String) {
        _uiState.update { it.copy(create = it.create.copy(name = value)) }
    }

    fun onDescriptionChange(value: String) {
        _uiState.update { it.copy(create = it.create.copy(description = value)) }
    }

    fun onPersonalityChange(value: String) {
        _uiState.update { it.copy(create = it.create.copy(personality = value)) }
    }

    fun onSubmitCreate() {
        val form = _uiState.value.create
        if (!form.canSubmit) return
        _uiState.update { it.copy(create = it.create.copy(isSubmitting = true)) }
        viewModelScope.launch {
            val result = repository.createBot(form.name, form.description, form.personality)
            handleMutation(
                result = result,
                successMsg = R.string.bots_create_success,
                failureMsg = R.string.bots_create_failed,
                onSuccess = { _uiState.update { st -> st.copy(create = CreateBotFormState(isOpen = false)) } },
                onError = { _uiState.update { st -> st.copy(create = st.create.copy(isSubmitting = false)) } },
            )
        }
    }

    // ---- Status toggle ----

    fun onToggleStatus(botId: String) {
        val bot = _uiState.value.bots.firstOrNull { it.id == botId } ?: return
        if (_uiState.value.isMutating) return
        val target = if (bot.isActive) BotStatus.PAUSED else BotStatus.ACTIVE
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            val result = repository.updateBotStatus(botId, target)
            handleMutation(
                result = result,
                successMsg = R.string.bots_status_success,
                failureMsg = R.string.bots_status_failed,
                onSuccess = { _uiState.update { st -> st.copy(isMutating = false) } },
                onError = { _uiState.update { st -> st.copy(isMutating = false) } },
            )
        }
    }

    // ---- Delete ----

    fun onDelete(botId: String) {
        if (_uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            val result = repository.deleteBot(botId)
            handleMutation(
                result = result,
                successMsg = R.string.bots_delete_success,
                failureMsg = R.string.bots_delete_failed,
                onSuccess = { _uiState.update { st -> st.copy(isMutating = false) } },
                onError = { _uiState.update { st -> st.copy(isMutating = false) } },
            )
        }
    }

    private suspend fun handleMutation(
        result: ApiResult<Unit>,
        successMsg: Int,
        failureMsg: Int,
        onSuccess: () -> Unit,
        onError: () -> Unit,
    ) {
        when (result) {
            is ApiResult.Success -> {
                onSuccess()
                _effects.send(BotsListEffect.ShowMessage(successMsg))
                load(fromUser = true)
            }
            is ApiResult.Failure -> {
                onError()
                if (result.error.status == HTTP_UNAUTHORIZED) {
                    _uiState.update { it.copy(phase = BotsPhase.SessionExpired) }
                } else {
                    _effects.send(BotsListEffect.ShowMessage(failureMsg))
                }
            }
            is ApiResult.NetworkError -> {
                onError()
                _effects.send(BotsListEffect.ShowMessage(failureMsg))
            }
        }
    }

    // ---- Load ----

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.bots.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else BotsPhase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadBots()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = BotsPhase.SessionExpired, isRefreshing = false) }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: List<Bot>) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty()) BotsPhase.Empty else BotsPhase.Content,
                bots = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cachedBots()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty()) BotsPhase.Empty else BotsPhase.Content,
                    bots = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(BotsListEffect.ShowMessage(R.string.bots_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) BotsPhase.Offline else BotsPhase.Error,
                    bots = emptyList(),
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
