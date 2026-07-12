package com.testlogon.android.feature.stylist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.stylist.DesignRule
import com.testlogon.android.data.stylist.StylistRepository
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
 * Drives [StylistRulesUiState] from [StylistRepository]. Loads the design rules on first composition /
 * refresh; the add-rule dialog POSTs a new rule; per-row toggle PUTs enabled; delete removes a rule.
 * Each mutation reloads the list.
 */
@HiltViewModel
class StylistRulesViewModel @Inject constructor(
    private val repository: StylistRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(StylistRulesUiState())
    val uiState: StateFlow<StylistRulesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<StylistEffect>(Channel.BUFFERED)
    val effects: Flow<StylistEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    // ---- Add-rule dialog ----
    fun onOpenCreate() = _uiState.update { it.copy(create = RuleFormState(isOpen = true)) }
    fun onDismissCreate() {
        if (_uiState.value.create.isSubmitting) return
        _uiState.update { it.copy(create = RuleFormState(isOpen = false)) }
    }
    fun onNameChange(v: String) = _uiState.update { it.copy(create = it.create.copy(name = v)) }
    fun onCategoryChange(v: String) = _uiState.update { it.copy(create = it.create.copy(category = v)) }
    fun onDescriptionChange(v: String) = _uiState.update { it.copy(create = it.create.copy(description = v)) }
    fun onSeverityChange(v: String) = _uiState.update { it.copy(create = it.create.copy(severity = v)) }

    fun onSubmitRule() {
        val form = _uiState.value.create
        if (!form.canSubmit) return
        _uiState.update { it.copy(create = it.create.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createRule(form.name, form.category, form.description, form.severity)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(create = RuleFormState(isOpen = false)) }
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_rule_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(create = it.create.copy(isSubmitting = false)) }
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = StylistRulesUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(StylistEffect.ShowMessage(R.string.stylist_rule_action_failed))
                    }
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(create = it.create.copy(isSubmitting = false)) }
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_rule_action_failed))
                }
            }
        }
    }

    fun onToggleRule(rule: DesignRule) {
        viewModelScope.launch {
            when (repository.setRuleEnabled(rule.id, !rule.enabled)) {
                is ApiResult.Success -> load(fromUser = true)
                else -> _effects.send(StylistEffect.ShowMessage(R.string.stylist_rule_action_failed))
            }
        }
    }

    fun onDeleteRule(rule: DesignRule) {
        viewModelScope.launch {
            when (repository.deleteRule(rule.id)) {
                is ApiResult.Success -> {
                    _effects.send(StylistEffect.ShowMessage(R.string.stylist_rule_deleted))
                    load(fromUser = true)
                }
                else -> _effects.send(StylistEffect.ShowMessage(R.string.stylist_rule_action_failed))
            }
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.rules.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else StylistRulesUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadRules()) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(
                            phase = if (result.data.isEmpty()) StylistRulesUiState.Phase.Empty else StylistRulesUiState.Phase.Content,
                            rules = result.data,
                            isRefreshing = false,
                            errorMessage = null,
                        )
                    }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = StylistRulesUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        _uiState.update {
                            it.copy(
                                phase = StylistRulesUiState.Phase.Error,
                                isRefreshing = false,
                                errorMessage = result.error.message,
                            )
                        }
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(
                            phase = StylistRulesUiState.Phase.Offline,
                            isRefreshing = false,
                            errorMessage = OFFLINE_FALLBACK,
                        )
                    }
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
