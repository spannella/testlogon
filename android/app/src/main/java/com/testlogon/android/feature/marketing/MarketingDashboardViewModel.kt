package com.testlogon.android.feature.marketing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.marketing.MarketingContent
import com.testlogon.android.data.marketing.MarketingContentPage
import com.testlogon.android.data.marketing.MarketingRepository
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
 * Drives [MarketingDashboardUiState] from [MarketingRepository]. Loads content (filtered by the active
 * tab) on first composition / tab change / pull-to-refresh. The create-draft dialog POSTs new content;
 * per-card lifecycle actions (approve/publish/archive/delete) call the matching endpoint then reload.
 */
@HiltViewModel
class MarketingDashboardViewModel @Inject constructor(
    private val repository: MarketingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MarketingDashboardUiState())
    val uiState: StateFlow<MarketingDashboardUiState> = _uiState.asStateFlow()

    private val _effects = Channel<MarketingEffect>(Channel.BUFFERED)
    val effects: Flow<MarketingEffect> = _effects.receiveAsFlow()

    /** Re-load whenever the caller returns (e.g. from the editor). */
    fun onResumed() = load(fromUser = false, force = true)

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onSelectTab(tab: MarketingTab) {
        if (_uiState.value.tab == tab) return
        _uiState.update { it.copy(tab = tab, page = null, phase = MarketingDashboardUiState.Phase.Loading) }
        load(fromUser = false, force = true)
    }

    // ---- Create dialog ----
    fun onOpenCreate() = _uiState.update { it.copy(create = CreateContentFormState(isOpen = true)) }
    fun onDismissCreate() {
        if (_uiState.value.create.isSubmitting) return
        _uiState.update { it.copy(create = CreateContentFormState(isOpen = false)) }
    }
    fun onTypeChange(v: String) = _uiState.update { it.copy(create = it.create.copy(contentType = v)) }
    fun onTitleChange(v: String) = _uiState.update { it.copy(create = it.create.copy(title = v)) }
    fun onBodyChange(v: String) = _uiState.update { it.copy(create = it.create.copy(body = v)) }

    fun onSubmitCreate() {
        val form = _uiState.value.create
        if (!form.canSubmit) return
        _uiState.update { it.copy(create = it.create.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createContent(form.contentType, form.title, form.body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(create = CreateContentFormState(isOpen = false)) }
                    _effects.send(MarketingEffect.ShowMessage(R.string.marketing_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(create = it.create.copy(isSubmitting = false)) }
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = MarketingDashboardUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_failed))
                    }
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(create = it.create.copy(isSubmitting = false)) }
                    _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_failed))
                }
            }
        }
    }

    // ---- Lifecycle actions ----
    fun onApprove(c: MarketingContent) = action(c.id) { repository.approve(c.id) }
    fun onPublish(c: MarketingContent) = action(c.id) { repository.publish(c.id) }
    fun onArchive(c: MarketingContent) = action(c.id) { repository.archive(c.id) }
    fun onDelete(c: MarketingContent) = action(c.id) { repository.delete(c.id) }

    private fun action(contentId: String, block: suspend () -> ApiResult<Unit>) {
        if (_uiState.value.busyContentId != null) return
        _uiState.update { it.copy(busyContentId = contentId) }
        viewModelScope.launch {
            val r = block()
            _uiState.update { it.copy(busyContentId = null) }
            when (r) {
                is ApiResult.Success -> {
                    _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_done))
                    load(fromUser = true)
                }
                is ApiResult.Failure ->
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = MarketingDashboardUiState.Phase.SessionExpired) }
                    } else {
                        _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_failed))
                    }
                is ApiResult.NetworkError ->
                    _effects.send(MarketingEffect.ShowMessage(R.string.marketing_action_failed))
            }
        }
    }

    private fun load(fromUser: Boolean, force: Boolean = false) {
        val state = _uiState.value
        if (state.isRefreshing && !force) return
        val hasContent = state.page != null
        _uiState.update {
            it.copy(
                phase = if (hasContent && !force) it.phase else MarketingDashboardUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        val type = _uiState.value.tab.type
        viewModelScope.launch {
            when (val result = repository.loadContent(type)) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = MarketingDashboardUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: MarketingContentPage) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) MarketingDashboardUiState.Phase.Empty else MarketingDashboardUiState.Phase.Content,
                page = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cachedContent()
        if (cached != null && _uiState.value.tab == MarketingTab.ALL) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) MarketingDashboardUiState.Phase.Empty else MarketingDashboardUiState.Phase.Content,
                    page = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(MarketingEffect.ShowMessage(R.string.marketing_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) MarketingDashboardUiState.Phase.Offline else MarketingDashboardUiState.Phase.Error,
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
