package com.testlogon.android.feature.crm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.CampaignMath
import com.testlogon.android.data.crm.CrmCampaignCreateInDto
import com.testlogon.android.data.crm.CrmCampaignFull
import com.testlogon.android.data.crm.CrmCampaignSendResult
import com.testlogon.android.data.crm.CrmCampaignUpdateInDto
import com.testlogon.android.data.crm.CrmCampaignsRepository
import com.testlogon.android.data.crm.CrmEmailPreview
import com.testlogon.android.data.crm.CrmEmailTemplate
import com.testlogon.android.data.crm.CrmEmailTemplateUpdateInDto
import com.testlogon.android.data.crm.CrmEmailTemplatesRepository
import com.testlogon.android.data.crm.CrmMarketingAdminRepository
import com.testlogon.android.data.crm.CrmWebLead
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

// ─────────────────────  Campaign editor (create / edit + send + preview)  ─────────────────────

data class CrmCampaignEditorUiState(
    val phase: Phase = Phase.Loading,
    val isNew: Boolean = true,
    val campaign: CrmCampaignFull? = null,
    // form fields
    val name: String = "",
    val objective: String = "",
    val budget: String = "",
    val campaignType: String = "email",
    val contactListIdsRaw: String = "",
    val segmentIdsRaw: String = "",
    val trackingCode: String = "",
    val emailTemplateId: String = "",
    // actions
    val saving: Boolean = false,
    val sending: Boolean = false,
    val formError: String? = null,
    val savedCampaignId: String? = null,
    val sendResult: CrmCampaignSendResult? = null,
    val preview: CrmEmailPreview? = null,
    val previewLoading: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val contactListIds: List<String>
        get() = contactListIdsRaw.split(',', '\n').map { it.trim() }.filter { it.isNotBlank() }
    val segmentIds: List<String>
        get() = segmentIdsRaw.split(',', '\n').map { it.trim() }.filter { it.isNotBlank() }

    val canSend: Boolean
        get() = campaign != null && CampaignMath.canSend(campaign.status, contactListIds, segmentIds)
    val sendBlockedReason: String?
        get() = if (campaign == null) "Save the campaign first." else
            CampaignMath.sendBlockedReason(campaign.status, contactListIds, segmentIds)
}

/**
 * CMP-001..CMP-008 — campaign editor. Create (POST) or load+edit (GET/PATCH) a campaign, run a
 * dry-run/real send, and fetch a merge-tag email preview. A 404 degrades to a clean error page.
 * The nav arg is optional: absent → create mode.
 */
@HiltViewModel
class CrmCampaignEditorViewModel @Inject constructor(
    private val repository: CrmCampaignsRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val campaignId: String? =
        savedStateHandle.get<String>(ARG_CAMPAIGN_ID)?.takeIf { it.isNotBlank() && it != NEW_SENTINEL }

    private val _uiState = MutableStateFlow(CrmCampaignEditorUiState(isNew = campaignId == null))
    val uiState: StateFlow<CrmCampaignEditorUiState> = _uiState.asStateFlow()

    init {
        if (campaignId == null) {
            _uiState.update { it.copy(phase = CrmCampaignEditorUiState.Phase.Content) }
        } else {
            load()
        }
    }

    fun onRetry() = load()

    private fun load() {
        val id = campaignId ?: return
        _uiState.update { it.copy(phase = if (it.campaign == null) CrmCampaignEditorUiState.Phase.Loading else it.phase) }
        viewModelScope.launch {
            when (val r = repository.campaignFull(id)) {
                is ApiResult.Success -> _uiState.update { it.prefill(r.data) }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = CrmCampaignEditorUiState.Phase.Error, isOffline = false, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = CrmCampaignEditorUiState.Phase.Error, isOffline = true, errorMessage = "You're offline. Try again.")
                }
            }
        }
    }

    private fun CrmCampaignEditorUiState.prefill(c: CrmCampaignFull): CrmCampaignEditorUiState = copy(
        phase = CrmCampaignEditorUiState.Phase.Content,
        isNew = false,
        campaign = c,
        name = c.name,
        objective = c.objective.orEmpty(),
        budget = if (c.budgetCents > 0) (c.budgetCents / 100.0).toString() else "",
        campaignType = c.campaignType,
        contactListIdsRaw = c.contactListIds.joinToString(", "),
        segmentIdsRaw = c.segmentIds.joinToString(", "),
        trackingCode = c.trackingCode.orEmpty(),
        emailTemplateId = c.emailTemplateId.orEmpty(),
        errorMessage = null,
        isOffline = false,
    )

    fun onName(v: String) = _uiState.update { it.copy(name = v, formError = null) }
    fun onObjective(v: String) = _uiState.update { it.copy(objective = v, formError = null) }
    fun onBudget(v: String) = _uiState.update { it.copy(budget = v, formError = null) }
    fun onCampaignType(v: String) = _uiState.update { it.copy(campaignType = v) }
    fun onContactLists(v: String) = _uiState.update { it.copy(contactListIdsRaw = v) }
    fun onSegments(v: String) = _uiState.update { it.copy(segmentIdsRaw = v) }
    fun onTrackingCode(v: String) = _uiState.update { it.copy(trackingCode = v) }
    fun onEmailTemplateId(v: String) = _uiState.update { it.copy(emailTemplateId = v) }
    fun clearFormError() = _uiState.update { it.copy(formError = null) }
    fun consumeSaved() = _uiState.update { it.copy(savedCampaignId = null) }
    fun dismissSendResult() = _uiState.update { it.copy(sendResult = null) }
    fun dismissPreview() = _uiState.update { it.copy(preview = null) }

    fun save() {
        val s = _uiState.value
        val cents = CampaignMath.parseBudgetToCents(s.budget)
        if (cents == null) {
            _uiState.update { it.copy(formError = "Enter a valid budget amount.") }
            return
        }
        val err = CampaignMath.validateCampaignInput(s.name, s.objective.ifBlank { null }, cents)
        if (err != null) {
            _uiState.update { it.copy(formError = err) }
            return
        }
        _uiState.update { it.copy(saving = true, formError = null) }
        viewModelScope.launch {
            val result = if (s.isNew || s.campaign == null) {
                repository.create(
                    CrmCampaignCreateInDto(
                        name = s.name.trim(),
                        objective = s.objective.ifBlank { null },
                        budgetCents = cents,
                        contactListIds = s.contactListIds.ifEmpty { null },
                        segmentIds = s.segmentIds.ifEmpty { null },
                        trackingCode = s.trackingCode.ifBlank { null },
                        campaignType = s.campaignType,
                        emailTemplateId = s.emailTemplateId.ifBlank { null },
                    ),
                )
            } else {
                repository.update(
                    s.campaign.campaignId,
                    CrmCampaignUpdateInDto(
                        name = s.name.trim(),
                        objective = s.objective.ifBlank { null },
                        budgetCents = cents,
                        contactListIds = s.contactListIds,
                        segmentIds = s.segmentIds,
                        trackingCode = s.trackingCode.ifBlank { null },
                        campaignType = s.campaignType,
                        emailTemplateId = s.emailTemplateId.ifBlank { null },
                    ),
                )
            }
            when (result) {
                is ApiResult.Success -> _uiState.update {
                    it.prefill(result.data).copy(saving = false, savedCampaignId = result.data.campaignId)
                }
                is ApiResult.Failure -> _uiState.update { it.copy(saving = false, formError = result.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(saving = false, formError = "You're offline. Try again.") }
            }
        }
    }

    fun send(dryRun: Boolean) {
        val id = _uiState.value.campaign?.campaignId ?: return
        _uiState.update { it.copy(sending = true, formError = null) }
        viewModelScope.launch {
            when (val r = repository.send(id, dryRun)) {
                is ApiResult.Success -> _uiState.update { it.copy(sending = false, sendResult = r.data) }
                is ApiResult.Failure -> _uiState.update { it.copy(sending = false, formError = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(sending = false, formError = "You're offline. Try again.") }
            }
        }
    }

    fun loadPreview() {
        val id = _uiState.value.campaign?.campaignId ?: return
        _uiState.update { it.copy(previewLoading = true) }
        viewModelScope.launch {
            when (val r = repository.previewEmail(id, samplePartyId = null, sampleVars = emptyMap())) {
                is ApiResult.Success -> _uiState.update { it.copy(previewLoading = false, preview = r.data) }
                is ApiResult.Failure -> _uiState.update { it.copy(previewLoading = false, formError = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(previewLoading = false, formError = "You're offline. Try again.") }
            }
        }
    }

    companion object {
        const val ARG_CAMPAIGN_ID: String = "campaignId"
        const val NEW_SENTINEL: String = "new"
    }
}

// ─────────────────────────  Email templates (list + editor)  ─────────────────────────

data class CrmEmailTemplatesUiState(
    val phase: Phase = Phase.Loading,
    val templates: List<CrmEmailTemplate> = emptyList(),
    val moduleDisabled: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    // editor dialog
    val editorOpen: Boolean = false,
    val editing: CrmEmailTemplate? = null,
    val editName: String = "",
    val editSubject: String = "",
    val editBody: String = "",
    val saving: Boolean = false,
    val formError: String? = null,
    val busyDeleteId: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

@HiltViewModel
class CrmEmailTemplatesViewModel @Inject constructor(
    private val repository: CrmEmailTemplatesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CrmEmailTemplatesUiState())
    val uiState: StateFlow<CrmEmailTemplatesUiState> = _uiState.asStateFlow()

    init { load(fromUser = false) }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.templates.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CrmEmailTemplatesUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.list()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CrmEmailTemplatesUiState.Phase.Content,
                        templates = r.data.templates,
                        moduleDisabled = r.data.moduleDisabled,
                        isRefreshing = false, isOffline = false, errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.templates.isNotEmpty()) CrmEmailTemplatesUiState.Phase.Content else CrmEmailTemplatesUiState.Phase.Error,
                        isRefreshing = false, isOffline = false, errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.templates.isNotEmpty()) CrmEmailTemplatesUiState.Phase.Content else CrmEmailTemplatesUiState.Phase.Error,
                        isRefreshing = false, isOffline = true, errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    fun openCreate() = _uiState.update {
        it.copy(editorOpen = true, editing = null, editName = "", editSubject = "", editBody = "", formError = null)
    }

    fun openEdit(t: CrmEmailTemplate) = _uiState.update {
        it.copy(
            editorOpen = true, editing = t,
            editName = t.name, editSubject = t.subjectTemplate, editBody = t.bodyHtmlTemplate, formError = null,
        )
    }

    fun closeEditor() = _uiState.update { it.copy(editorOpen = false, formError = null) }
    fun onEditName(v: String) = _uiState.update { it.copy(editName = v, formError = null) }
    fun onEditSubject(v: String) = _uiState.update { it.copy(editSubject = v, formError = null) }
    fun onEditBody(v: String) = _uiState.update { it.copy(editBody = v, formError = null) }

    fun saveTemplate() {
        val s = _uiState.value
        val err = CampaignMath.validateTemplateInput(s.editName, s.editSubject, s.editBody)
        if (err != null) { _uiState.update { it.copy(formError = err) }; return }
        _uiState.update { it.copy(saving = true, formError = null) }
        viewModelScope.launch {
            val result = if (s.editing == null) {
                repository.create(s.editName.trim(), s.editSubject.trim(), s.editBody)
            } else {
                repository.update(
                    s.editing.templateId,
                    CrmEmailTemplateUpdateInDto(
                        name = s.editName.trim(),
                        subjectTemplate = s.editSubject.trim(),
                        bodyHtmlTemplate = s.editBody,
                    ),
                )
            }
            when (result) {
                is ApiResult.Success -> { _uiState.update { it.copy(saving = false, editorOpen = false) }; load(fromUser = false) }
                is ApiResult.Failure -> _uiState.update { it.copy(saving = false, formError = result.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(saving = false, formError = "You're offline. Try again.") }
            }
        }
    }

    fun deleteTemplate(templateId: String) {
        _uiState.update { it.copy(busyDeleteId = templateId) }
        viewModelScope.launch {
            when (val r = repository.delete(templateId)) {
                is ApiResult.Success -> { _uiState.update { it.copy(busyDeleteId = null) }; load(fromUser = false) }
                is ApiResult.Failure -> _uiState.update { it.copy(busyDeleteId = null, errorMessage = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(busyDeleteId = null, errorMessage = "You're offline. Try again.") }
            }
        }
    }
}

// ─────────────────────────  Admin web-to-lead list (CMP-006)  ─────────────────────────

data class CrmMarketingLeadsUiState(
    val phase: Phase = Phase.Loading,
    val leads: List<CrmWebLead> = emptyList(),
    val moduleDisabled: Boolean = false,
    val forbidden: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

@HiltViewModel
class CrmMarketingLeadsViewModel @Inject constructor(
    private val repository: CrmMarketingAdminRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(CrmMarketingLeadsUiState())
    val uiState: StateFlow<CrmMarketingLeadsUiState> = _uiState.asStateFlow()

    init { load(fromUser = false) }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.leads.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CrmMarketingLeadsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.leads()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CrmMarketingLeadsUiState.Phase.Content,
                        leads = r.data.leads,
                        moduleDisabled = r.data.moduleDisabled,
                        forbidden = r.data.forbidden,
                        isRefreshing = false, isOffline = false, errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.leads.isNotEmpty()) CrmMarketingLeadsUiState.Phase.Content else CrmMarketingLeadsUiState.Phase.Error,
                        isRefreshing = false, isOffline = false, errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.leads.isNotEmpty()) CrmMarketingLeadsUiState.Phase.Content else CrmMarketingLeadsUiState.Phase.Error,
                        isRefreshing = false, isOffline = true, errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }
}
