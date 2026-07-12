package com.testlogon.android.feature.marketing

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.marketing.MarketingContent
import com.testlogon.android.data.marketing.MarketingRepository
import com.testlogon.android.navigation.MarketingEditorDest
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
 * Drives [MarketingEditorUiState] for a single content item (web MarketingContentEditorPage). Loads the
 * content by id, seeds the editable fields, then Save (PUT), Approve, and Schedule map to the matching
 * endpoints. Schedule is gated on status==approved (mirrors the web).
 */
@HiltViewModel
class MarketingEditorViewModel @Inject constructor(
    private val repository: MarketingRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val contentId: String = savedStateHandle.get<String>(MarketingEditorDest.ARG_CONTENT_ID).orEmpty()

    private val _uiState = MutableStateFlow(MarketingEditorUiState())
    val uiState: StateFlow<MarketingEditorUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MarketingEffect>(Channel.BUFFERED)
    val effects: Flow<MarketingEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    fun onRetry() = load()

    fun onTitleChange(v: String) = _uiState.update { it.copy(title = v) }
    fun onBodyChange(v: String) = _uiState.update { it.copy(body = v) }
    fun onSummaryChange(v: String) = _uiState.update { it.copy(summary = v) }
    fun onTagsChange(v: String) = _uiState.update { it.copy(tags = v) }
    fun onSeoTitleChange(v: String) = _uiState.update { it.copy(seoTitle = v) }
    fun onSeoDescriptionChange(v: String) = _uiState.update { it.copy(seoDescription = v) }
    fun onScheduleAtChange(epochSeconds: Long?) = _uiState.update { it.copy(scheduleAtSeconds = epochSeconds) }

    fun onSave() {
        val s = _uiState.value
        if (s.isSaving) return
        _uiState.update { it.copy(isSaving = true) }
        viewModelScope.launch {
            val tags = s.tags.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            val r = repository.updateContent(
                contentId = contentId,
                title = s.title,
                body = s.body,
                summary = s.summary,
                tags = tags,
                seoTitle = s.seoTitle,
                seoDescription = s.seoDescription,
            )
            _uiState.update { it.copy(isSaving = false) }
            handleMutation(r, R.string.marketing_saved)
        }
    }

    fun onApprove() {
        val s = _uiState.value
        if (s.isApproving) return
        _uiState.update { it.copy(isApproving = true) }
        viewModelScope.launch {
            val r = repository.approve(contentId)
            _uiState.update { it.copy(isApproving = false) }
            handleMutation(r, R.string.marketing_approved)
        }
    }

    fun onSchedule() {
        val s = _uiState.value
        val at = s.scheduleAtSeconds ?: return
        if (s.isScheduling) return
        _uiState.update { it.copy(isScheduling = true) }
        viewModelScope.launch {
            val r = repository.schedule(contentId, at)
            _uiState.update { it.copy(isScheduling = false) }
            handleMutation(r, R.string.marketing_scheduled)
        }
    }

    private suspend fun handleMutation(r: ApiResult<Unit>, successMsg: Int) {
        when (r) {
            is ApiResult.Success -> {
                _effects.send(MarketingEffect.ShowMessage(successMsg))
                load(preserveEdits = false)
            }
            is ApiResult.Failure ->
                if (r.error.status == HTTP_UNAUTHORIZED) {
                    _uiState.update { it.copy(phase = MarketingEditorUiState.Phase.SessionExpired) }
                } else {
                    _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_failed))
                }
            is ApiResult.NetworkError ->
                _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_failed))
        }
    }

    private fun load(preserveEdits: Boolean = false) {
        if (contentId.isBlank()) {
            _uiState.update { it.copy(phase = MarketingEditorUiState.Phase.Error, errorMessage = "Missing content id") }
            return
        }
        _uiState.update { it.copy(phase = if (it.content == null) MarketingEditorUiState.Phase.Loading else it.phase) }
        viewModelScope.launch {
            when (val result = repository.getContent(contentId)) {
                is ApiResult.Success -> seed(result.data, preserveEdits)
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = MarketingEditorUiState.Phase.SessionExpired) }
                    } else {
                        _uiState.update {
                            it.copy(phase = MarketingEditorUiState.Phase.Error, errorMessage = result.error.message)
                        }
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(phase = MarketingEditorUiState.Phase.Offline, errorMessage = OFFLINE_FALLBACK)
                    }
            }
        }
    }

    private fun seed(c: MarketingContent, preserveEdits: Boolean) {
        _uiState.update {
            it.copy(
                phase = MarketingEditorUiState.Phase.Content,
                content = c,
                title = if (preserveEdits) it.title else c.title,
                body = if (preserveEdits) it.body else c.body,
                summary = if (preserveEdits) it.summary else c.summary.orEmpty(),
                tags = if (preserveEdits) it.tags else c.tags.joinToString(", "),
                seoTitle = if (preserveEdits) it.seoTitle else c.seoTitle.orEmpty(),
                seoDescription = if (preserveEdits) it.seoDescription else c.seoDescription.orEmpty(),
                errorMessage = null,
            )
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Retry."
    }
}
