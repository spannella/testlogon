package com.testlogon.android.feature.bots

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bots.AutoReplyMatchType
import com.testlogon.android.data.bots.AutoReplyRule
import com.testlogon.android.data.bots.BotsRepository
import com.testlogon.android.navigation.BotsDest
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
 * Drives [AutoReplyUiState] for a single bot's auto-reply rules. The bot id arrives as a nav arg via
 * [SavedStateHandle]. Loads the rules on first composition / refresh; the "+" opens a create form, a
 * row's "Edit" opens the same form pre-filled, and both POST/PUT then reload. "Delete" removes a rule.
 * A hard 401 maps to SessionExpired. Mirrors the web bots/{botId}/auto-reply page.
 */
@HiltViewModel
class BotAutoReplyViewModel @Inject constructor(
    private val repository: BotsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val botId: String = checkNotNull(savedStateHandle[BotsDest.ARG_BOT_ID]) {
        "BotAutoReplyViewModel requires a '${BotsDest.ARG_BOT_ID}' nav argument"
    }

    private val _uiState = MutableStateFlow(AutoReplyUiState())
    val uiState: StateFlow<AutoReplyUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AutoReplyEffect>(Channel.BUFFERED)
    val effects: Flow<AutoReplyEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    // ---- Form ----

    fun onOpenCreate() {
        _uiState.update { it.copy(form = AutoReplyFormState(isOpen = true)) }
    }

    fun onOpenEdit(ruleId: String) {
        val rule = _uiState.value.rules.firstOrNull { it.id == ruleId } ?: return
        _uiState.update {
            it.copy(
                form = AutoReplyFormState(
                    isOpen = true,
                    editingRuleId = rule.id,
                    triggerPattern = rule.triggerPattern,
                    responseTemplate = rule.responseTemplate,
                    matchType = rule.matchType,
                    priority = rule.priority.toString(),
                    enabled = rule.enabled,
                ),
            )
        }
    }

    fun onDismissForm() {
        if (_uiState.value.form.isSubmitting) return
        _uiState.update { it.copy(form = AutoReplyFormState(isOpen = false)) }
    }

    fun onTriggerChange(value: String) {
        _uiState.update { it.copy(form = it.form.copy(triggerPattern = value)) }
    }

    fun onResponseChange(value: String) {
        _uiState.update { it.copy(form = it.form.copy(responseTemplate = value)) }
    }

    fun onMatchTypeChange(value: AutoReplyMatchType) {
        _uiState.update { it.copy(form = it.form.copy(matchType = value)) }
    }

    fun onPriorityChange(value: String) {
        _uiState.update { it.copy(form = it.form.copy(priority = value.filter { c -> c.isDigit() })) }
    }

    fun onEnabledChange(value: Boolean) {
        _uiState.update { it.copy(form = it.form.copy(enabled = value)) }
    }

    fun onSubmitForm() {
        val form = _uiState.value.form
        if (!form.canSubmit) return
        _uiState.update { it.copy(form = it.form.copy(isSubmitting = true)) }
        viewModelScope.launch {
            val result = if (form.isEditing) {
                repository.updateAutoReplyRule(
                    botId = botId,
                    ruleId = form.editingRuleId!!,
                    triggerPattern = form.triggerPattern,
                    responseTemplate = form.responseTemplate,
                    matchType = form.matchType,
                    priority = form.priorityValue,
                    enabled = form.enabled,
                )
            } else {
                repository.createAutoReplyRule(
                    botId = botId,
                    triggerPattern = form.triggerPattern,
                    responseTemplate = form.responseTemplate,
                    matchType = form.matchType,
                    priority = form.priorityValue,
                    enabled = form.enabled,
                )
            }
            handleMutation(
                result = result,
                successMsg = if (form.isEditing) R.string.bots_rule_update_success else R.string.bots_rule_create_success,
                failureMsg = R.string.bots_rule_save_failed,
                onSuccess = { _uiState.update { st -> st.copy(form = AutoReplyFormState(isOpen = false)) } },
                onError = { _uiState.update { st -> st.copy(form = st.form.copy(isSubmitting = false)) } },
            )
        }
    }

    // ---- Delete ----

    fun onDelete(ruleId: String) {
        if (_uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            val result = repository.deleteAutoReplyRule(botId, ruleId)
            handleMutation(
                result = result,
                successMsg = R.string.bots_rule_delete_success,
                failureMsg = R.string.bots_rule_delete_failed,
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
                _effects.send(AutoReplyEffect.ShowMessage(successMsg))
                load(fromUser = true)
            }
            is ApiResult.Failure -> {
                onError()
                if (result.error.status == HTTP_UNAUTHORIZED) {
                    _uiState.update { it.copy(phase = BotsPhase.SessionExpired) }
                } else {
                    _effects.send(AutoReplyEffect.ShowMessage(failureMsg))
                }
            }
            is ApiResult.NetworkError -> {
                onError()
                _effects.send(AutoReplyEffect.ShowMessage(failureMsg))
            }
        }
    }

    // ---- Load ----

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.rules.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else BotsPhase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadAutoReplyRules(botId)) {
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

    private fun reduceSuccess(data: List<AutoReplyRule>) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty()) BotsPhase.Empty else BotsPhase.Content,
                rules = data,
                isRefreshing = false,
                errorMessage = null,
            )
        }
    }

    private fun reduceFailure(message: String, offline: Boolean) {
        _uiState.update {
            it.copy(
                phase = if (offline) BotsPhase.Offline else BotsPhase.Error,
                isRefreshing = false,
                errorMessage = message,
            )
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
