package com.testlogon.android.feature.pmideas

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.pmideas.PmIdea
import com.testlogon.android.data.pmideas.PmIdeaStatus
import com.testlogon.android.data.pmideas.PmIdeasRepository
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

/** Drives [PmIdeasUiState] from [PmIdeasRepository]. Mirrors the web FeatureIdeasPage triage view. */
@HiltViewModel
class PmIdeasViewModel @Inject constructor(
    private val repository: PmIdeasRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PmIdeasUiState())
    val uiState: StateFlow<PmIdeasUiState> = _uiState.asStateFlow()

    private val _effects = Channel<PmIdeasEffect>(Channel.BUFFERED)
    val effects: Flow<PmIdeasEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onSelectTab(tab: PmIdeaStatus) {
        if (tab == _uiState.value.tab) return
        _uiState.update { it.copy(tab = tab, ideas = emptyList()) }
        load(fromUser = false)
    }

    // ---- Detail dialog ----
    fun onOpenDetail(idea: PmIdea) = _uiState.update { it.copy(detail = idea) }
    fun onDismissDetail() = _uiState.update { it.copy(detail = null) }

    // ---- Triage actions ----
    fun onApprove(ideaId: String) = viewModelScope.launch {
        when (repository.approve(ideaId)) {
            is ApiResult.Success -> {
                _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_approved))
                _uiState.update { it.copy(detail = null) }
                load(fromUser = true)
            }
            else -> _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_action_failed))
        }
    }

    fun onArchive(ideaId: String) = viewModelScope.launch {
        when (repository.archive(ideaId)) {
            is ApiResult.Success -> {
                _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_archived))
                _uiState.update { it.copy(detail = null) }
                load(fromUser = true)
            }
            else -> _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_action_failed))
        }
    }

    // ---- Reject dialog ----
    fun onOpenReject(ideaId: String) = _uiState.update { it.copy(rejectForm = RejectFormState(ideaId = ideaId)) }
    fun onDismissReject() {
        if (_uiState.value.rejectForm.isSubmitting) return
        _uiState.update { it.copy(rejectForm = RejectFormState()) }
    }
    fun onRejectReasonChange(v: String) = _uiState.update { it.copy(rejectForm = it.rejectForm.copy(reason = v)) }

    fun onSubmitReject() {
        val form = _uiState.value.rejectForm
        val ideaId = form.ideaId ?: return
        if (!form.canSubmit) return
        _uiState.update { it.copy(rejectForm = it.rejectForm.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (repository.reject(ideaId, form.reason)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(rejectForm = RejectFormState(), detail = null) }
                    _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_rejected))
                    load(fromUser = true)
                }
                else -> {
                    _uiState.update { it.copy(rejectForm = it.rejectForm.copy(isSubmitting = false)) }
                    _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_action_failed))
                }
            }
        }
    }

    // ---- Trigger review ----
    fun onTriggerReview() {
        if (_uiState.value.isTriggeringReview) return
        _uiState.update { it.copy(isTriggeringReview = true) }
        viewModelScope.launch {
            val result = repository.triggerReview()
            _uiState.update { it.copy(isTriggeringReview = false) }
            when (result) {
                is ApiResult.Success -> {
                    _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_review_triggered))
                    load(fromUser = true)
                }
                else -> _effects.send(PmIdeasEffect.ShowMessage(R.string.pmideas_action_failed))
            }
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.phase == PmIdeasPhase.Content
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else PmIdeasPhase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadIdeas(_uiState.value.tab.serverValue)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = if (result.data.isEmpty) PmIdeasPhase.Empty else PmIdeasPhase.Content,
                        ideas = result.data.ideas,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = PmIdeasPhase.SessionExpired, isRefreshing = false) }
                    } else {
                        _uiState.update { it.copy(phase = PmIdeasPhase.Error, isRefreshing = false, errorMessage = result.error.message) }
                    }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = PmIdeasPhase.Offline, isRefreshing = false, errorMessage = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
