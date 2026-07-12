package com.testlogon.android.feature.bots

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bots.BotTemplate
import com.testlogon.android.data.bots.BotsRepository
import com.testlogon.android.data.bots.TemplateCategory
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
 * Drives [TemplatesUiState] for a single bot's message templates. The bot id arrives as a nav arg via
 * [SavedStateHandle]. Loads the templates on first composition / refresh; the "+" opens a create form
 * (name + text + category, body_format defaults to plain) that POSTs then reloads. "Delete" removes a
 * template. A hard 401 maps to SessionExpired. Mirrors the web bots/{botId}/templates page. Editing
 * existing templates is deferred (see RETURN note) -- create + delete cover the v1 surface.
 */
@HiltViewModel
class BotTemplatesViewModel @Inject constructor(
    private val repository: BotsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val botId: String = checkNotNull(savedStateHandle[BotsDest.ARG_BOT_ID]) {
        "BotTemplatesViewModel requires a '${BotsDest.ARG_BOT_ID}' nav argument"
    }

    private val _uiState = MutableStateFlow(TemplatesUiState())
    val uiState: StateFlow<TemplatesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<TemplatesEffect>(Channel.BUFFERED)
    val effects: Flow<TemplatesEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    // ---- Form ----

    fun onOpenCreate() {
        _uiState.update { it.copy(form = TemplateFormState(isOpen = true)) }
    }

    fun onDismissForm() {
        if (_uiState.value.form.isSubmitting) return
        _uiState.update { it.copy(form = TemplateFormState(isOpen = false)) }
    }

    fun onNameChange(value: String) {
        _uiState.update { it.copy(form = it.form.copy(name = value)) }
    }

    fun onTextChange(value: String) {
        _uiState.update { it.copy(form = it.form.copy(text = value)) }
    }

    fun onCategoryChange(value: TemplateCategory) {
        _uiState.update { it.copy(form = it.form.copy(category = value)) }
    }

    fun onSubmitForm() {
        val form = _uiState.value.form
        if (!form.canSubmit) return
        _uiState.update { it.copy(form = it.form.copy(isSubmitting = true)) }
        viewModelScope.launch {
            val result = repository.createTemplate(
                botId = botId,
                name = form.name,
                text = form.text,
                category = form.category,
                bodyFormat = DEFAULT_BODY_FORMAT,
            )
            handleMutation(
                result = result,
                successMsg = R.string.bots_template_create_success,
                failureMsg = R.string.bots_template_create_failed,
                onSuccess = { _uiState.update { st -> st.copy(form = TemplateFormState(isOpen = false)) } },
                onError = { _uiState.update { st -> st.copy(form = st.form.copy(isSubmitting = false)) } },
            )
        }
    }

    // ---- Delete ----

    fun onDelete(templateId: String) {
        if (_uiState.value.isMutating) return
        _uiState.update { it.copy(isMutating = true) }
        viewModelScope.launch {
            val result = repository.deleteTemplate(botId, templateId)
            handleMutation(
                result = result,
                successMsg = R.string.bots_template_delete_success,
                failureMsg = R.string.bots_template_delete_failed,
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
                _effects.send(TemplatesEffect.ShowMessage(successMsg))
                load(fromUser = true)
            }
            is ApiResult.Failure -> {
                onError()
                if (result.error.status == HTTP_UNAUTHORIZED) {
                    _uiState.update { it.copy(phase = BotsPhase.SessionExpired) }
                } else {
                    _effects.send(TemplatesEffect.ShowMessage(failureMsg))
                }
            }
            is ApiResult.NetworkError -> {
                onError()
                _effects.send(TemplatesEffect.ShowMessage(failureMsg))
            }
        }
    }

    // ---- Load ----

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.templates.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else BotsPhase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadTemplates(botId)) {
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

    private fun reduceSuccess(data: List<BotTemplate>) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty()) BotsPhase.Empty else BotsPhase.Content,
                templates = data,
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
        private const val DEFAULT_BODY_FORMAT = "plain"
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
