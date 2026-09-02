package com.testlogon.android.feature.adminemail

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.admin.email.AdminEmailMath
import com.testlogon.android.data.admin.email.AdminEmailRepository
import com.testlogon.android.data.admin.email.CampaignTemplate
import com.testlogon.android.data.admin.email.SuppressedEmail
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
 * Drives [AdminEmailUiState] from [AdminEmailRepository]. Loads stats + campaign templates + the
 * suppressed list on first composition + pull-to-refresh. Templates support create + deactivate;
 * suppressed entries support admin unsuppress. Gating: a verified non-admin -> Forbidden with NO
 * network calls (client pre-check); the backend 403 is authoritative. Degrade-on-404: template reads
 * fold to honest-empty when the flag is off, mutations surface errors.
 */
@HiltViewModel
class AdminEmailViewModel @Inject constructor(
    private val repository: AdminEmailRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(AdminEmailUiState())
    val uiState: StateFlow<AdminEmailUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AdminEmailEffect>(Channel.BUFFERED)
    val effects: Flow<AdminEmailEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onResumed() = load(fromUser = false, force = true)
    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onSelectTab(tab: AdminEmailTab) {
        if (_uiState.value.tab == tab) return
        _uiState.update { it.copy(tab = tab) }
    }

    // ---- create template ----
    fun onOpenCreateTemplate() =
        _uiState.update { it.copy(createTemplate = CreateTemplateFormState(isOpen = true)) }

    fun onDismissCreateTemplate() {
        if (_uiState.value.createTemplate.isSubmitting) return
        _uiState.update { it.copy(createTemplate = CreateTemplateFormState(isOpen = false)) }
    }

    fun onTemplateNameChange(v: String) =
        _uiState.update { it.copy(createTemplate = it.createTemplate.copy(name = v)) }
    fun onTemplateSubjectChange(v: String) =
        _uiState.update { it.copy(createTemplate = it.createTemplate.copy(subject = v)) }
    fun onTemplateBodyChange(v: String) =
        _uiState.update { it.copy(createTemplate = it.createTemplate.copy(body = v)) }
    fun onTemplateMergeFieldsChange(v: String) =
        _uiState.update { it.copy(createTemplate = it.createTemplate.copy(mergeFields = v)) }

    fun onSubmitCreateTemplate() {
        val form = _uiState.value.createTemplate
        val merge = AdminEmailMath.parseMergeFields(form.mergeFields)
        if (!form.canSubmit || merge == null) return
        _uiState.update { it.copy(createTemplate = it.createTemplate.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createTemplate(form.name, form.subject, form.body, merge)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createTemplate = CreateTemplateFormState(isOpen = false)) }
                    _effects.send(AdminEmailEffect.ShowMessage(R.string.admin_email_template_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(createTemplate = it.createTemplate.copy(isSubmitting = false)) }
                    handleMutationFailure(r.error.status, r.error.message)
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(createTemplate = it.createTemplate.copy(isSubmitting = false)) }
                    _effects.send(AdminEmailEffect.ShowMessage(R.string.admin_email_action_failed))
                }
            }
        }
    }

    fun onDeactivateTemplate(template: CampaignTemplate) {
        if (_uiState.value.busyId != null) return
        _uiState.update { it.copy(busyId = template.id) }
        viewModelScope.launch {
            val r = repository.deleteTemplate(template.id)
            _uiState.update { it.copy(busyId = null) }
            when (r) {
                is ApiResult.Success -> {
                    _effects.send(AdminEmailEffect.ShowMessage(R.string.admin_email_template_deactivated))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> handleMutationFailure(r.error.status, r.error.message)
                is ApiResult.NetworkError ->
                    _effects.send(AdminEmailEffect.ShowMessage(R.string.admin_email_action_failed))
            }
        }
    }

    // ---- unsuppress ----
    fun onUnsuppress(entry: SuppressedEmail) {
        if (_uiState.value.busyId != null) return
        _uiState.update { it.copy(busyId = entry.email) }
        viewModelScope.launch {
            val r = repository.unsuppress(entry.email)
            _uiState.update { it.copy(busyId = null) }
            when (r) {
                is ApiResult.Success -> {
                    _effects.send(AdminEmailEffect.ShowMessage(R.string.admin_email_unsuppressed))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> handleMutationFailure(r.error.status, r.error.message)
                is ApiResult.NetworkError ->
                    _effects.send(AdminEmailEffect.ShowMessage(R.string.admin_email_action_failed))
            }
        }
    }

    private suspend fun handleMutationFailure(status: Int, message: String) {
        when (status) {
            HTTP_UNAUTHORIZED -> _uiState.update { it.copy(phase = AdminEmailUiState.Phase.SessionExpired) }
            HTTP_FORBIDDEN -> _uiState.update { it.copy(phase = AdminEmailUiState.Phase.Forbidden) }
            else -> _effects.send(AdminEmailEffect.ShowText(message))
        }
    }

    // ---- load ----
    private fun load(fromUser: Boolean, force: Boolean = false) {
        val hasContent = _uiState.value.phase == AdminEmailUiState.Phase.Content
        if (_uiState.value.isRefreshing && !force) return
        _uiState.update {
            it.copy(
                phase = if (hasContent && !force) it.phase else AdminEmailUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            // Client-side role pre-check: a verified non-admin emits Forbidden with ZERO network calls.
            if (!repository.isAdmin()) {
                _uiState.update { it.copy(phase = AdminEmailUiState.Phase.Forbidden, isRefreshing = false) }
                return@launch
            }

            val statsR = repository.loadStats()
            val templatesR = repository.loadTemplates()
            val suppressedR = repository.loadSuppressed()
            val results = listOf(statsR, templatesR, suppressedR)

            if (results.any { it is ApiResult.Failure && it.error.status == HTTP_FORBIDDEN }) {
                _uiState.update { it.copy(phase = AdminEmailUiState.Phase.Forbidden, isRefreshing = false) }
                return@launch
            }
            if (results.any { it is ApiResult.Failure && it.error.status == HTTP_UNAUTHORIZED }) {
                _uiState.update { it.copy(phase = AdminEmailUiState.Phase.SessionExpired, isRefreshing = false) }
                return@launch
            }

            val anyNetworkError = results.any { it is ApiResult.NetworkError }
            val stats = (statsR as? ApiResult.Success)?.data
            val templates = (templatesR as? ApiResult.Success)?.data.orEmpty()
            val suppressed = (suppressedR as? ApiResult.Success)?.data.orEmpty()
            val allFailed = results.none { it is ApiResult.Success }
            val phase = when {
                allFailed && anyNetworkError -> AdminEmailUiState.Phase.Offline
                allFailed -> AdminEmailUiState.Phase.Error
                else -> AdminEmailUiState.Phase.Content
            }

            _uiState.update {
                it.copy(
                    phase = phase,
                    stats = stats ?: it.stats,
                    templates = templates,
                    suppressed = suppressed,
                    isRefreshing = false,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val HTTP_FORBIDDEN = 403
    }
}
