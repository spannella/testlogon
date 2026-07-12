package com.testlogon.android.feature.ads.contentcontrols.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.ads.ContentAdOverrideIn
import com.testlogon.android.feature.ads.contentcontrols.data.ContentAdControlsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import java.math.RoundingMode
import javax.inject.Inject

/**
 * Presentation logic for the CONTENT AD-CONTROLS screen (web parity: ContentAdControlsPage.tsx).
 *
 * On init, loads the active overrides, the current revenue share, and the ad-revenue breakdown plus
 * advertiser transparency for the default 30-day window. Edits update the in-memory override form; Save
 * upserts; the active list has per-row delete; the revenue share has its own editor; the breakdown window
 * is reselectable. READ plus WRITE; no polling loop.
 *
 * Dispatcher seam: ioDispatcher defaults to IO and is read inside coroutines so a test can swap it.
 */
@HiltViewModel
class ContentAdControlsViewModel @Inject constructor(
    private val repository: ContentAdControlsRepository,
) : ViewModel() {

    var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

    private val _uiState = MutableStateFlow<ContentAdControlsUiState>(ContentAdControlsUiState.Loading)
    val uiState: StateFlow<ContentAdControlsUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun load() {
        _uiState.value = ContentAdControlsUiState.Loading
        viewModelScope.launch {
            val overridesRes = withContext(ioDispatcher) { repository.listOverrides() }
            if (overridesRes is ApiResult.Failure) {
                _uiState.value = ContentAdControlsUiState.Error(overridesRes.error); return@launch
            }
            if (overridesRes is ApiResult.NetworkError) {
                _uiState.value = ContentAdControlsUiState.Error(networkError()); return@launch
            }
            val overrides = (overridesRes as ApiResult.Success).data

            val shareRes = withContext(ioDispatcher) { repository.getRevenueShare() }
            val shareBps = (shareRes as? ApiResult.Success)?.data ?: DEFAULT_SHARE_BPS

            _uiState.value = ContentAdControlsUiState.Content(
                overrides = overrides,
                revenueShareBps = shareBps,
                breakdownDays = DEFAULT_DAYS,
            )
            loadBreakdown(DEFAULT_DAYS)
        }
    }

    fun onRetry() = load()

    // Override editor

    fun updateForm(transform: (OverrideForm) -> OverrideForm) = updateContent {
        it.copy(form = transform(it.form), saved = false, saveError = null)
    }

    fun saveOverride() {
        val content = _uiState.value as? ContentAdControlsUiState.Content ?: return
        if (content.saving || !content.form.canSave) return
        _uiState.value = content.copy(saving = true, saveError = null, saved = false)
        val form = content.form
        viewModelScope.launch {
            val body = ContentAdOverrideIn(
                contentType = "video",
                adEnabled = form.adEnabled,
                adDensity = form.adDensity.wire,
                preRollEnabled = form.preRollEnabled,
                midRollEnabled = form.midRollEnabled,
                adsFreeForSubscribers = form.adsFreeForSubscribers,
            )
            when (val r = withContext(ioDispatcher) { repository.upsertOverride(form.contentId.trim(), body) }) {
                is ApiResult.Success -> {
                    val listed = withContext(ioDispatcher) { repository.listOverrides() }
                    val rows = (listed as? ApiResult.Success)?.data
                    val saved = r.data
                    updateContent { c ->
                        c.copy(
                            saving = false,
                            saved = true,
                            form = OverrideForm(),
                            overrides = rows ?: (c.overrides.filterNot { it.contentId == saved.contentId } + saved),
                        )
                    }
                }
                is ApiResult.Failure -> updateContent { it.copy(saving = false, saveError = r.error.message) }
                is ApiResult.NetworkError -> updateContent { it.copy(saving = false, saveError = OFFLINE_FALLBACK) }
            }
        }
    }

    fun deleteOverride(contentId: String) {
        val content = _uiState.value as? ContentAdControlsUiState.Content ?: return
        if (content.deletingContentId != null) return
        _uiState.value = content.copy(deletingContentId = contentId)
        viewModelScope.launch {
            when (withContext(ioDispatcher) { repository.deleteOverride(contentId) }) {
                is ApiResult.Success -> updateContent { c ->
                    c.copy(deletingContentId = null, overrides = c.overrides.filterNot { it.contentId == contentId })
                }
                is ApiResult.Failure -> updateContent { it.copy(deletingContentId = null, saveError = REMOVE_FAIL) }
                is ApiResult.NetworkError -> updateContent { it.copy(deletingContentId = null, saveError = OFFLINE_FALLBACK) }
            }
        }
    }

    // Revenue share

    fun onShareInputChanged(text: String) = updateContent { it.copy(shareInput = text, shareError = null) }

    fun saveRevenueShare() {
        val content = _uiState.value as? ContentAdControlsUiState.Content ?: return
        if (content.savingShare) return
        val pct = content.shareInput.trim().toBigDecimalOrNull()
        if (pct == null || pct.signum() < 0 || pct > BigDecimal(100)) {
            updateContent { it.copy(shareError = SHARE_RANGE) }
            return
        }
        val bps = pct.multiply(BigDecimal(100)).setScale(0, RoundingMode.HALF_UP).toInt().coerceIn(0, MAX_SHARE_BPS)
        _uiState.value = content.copy(savingShare = true, shareError = null)
        viewModelScope.launch {
            when (val r = withContext(ioDispatcher) { repository.setRevenueShare(bps) }) {
                is ApiResult.Success -> updateContent { it.copy(savingShare = false, revenueShareBps = r.data, shareInput = "") }
                is ApiResult.Failure -> updateContent { it.copy(savingShare = false, shareError = r.error.message) }
                is ApiResult.NetworkError -> updateContent { it.copy(savingShare = false, shareError = OFFLINE_FALLBACK) }
            }
        }
    }

    // Breakdown

    fun selectBreakdownDays(days: Int) {
        val content = _uiState.value as? ContentAdControlsUiState.Content ?: return
        if (content.breakdownDays == days && content.breakdown != null) return
        _uiState.value = content.copy(breakdownDays = days)
        loadBreakdown(days)
    }

    private fun loadBreakdown(days: Int) {
        updateContent { it.copy(breakdownLoading = true) }
        viewModelScope.launch {
            val breakdown = (withContext(ioDispatcher) { repository.getRevenueBreakdown(days) } as? ApiResult.Success)?.data
            val advertisers = (withContext(ioDispatcher) { repository.getTransparency() } as? ApiResult.Success)?.data.orEmpty()
            updateContent { it.copy(breakdownLoading = false, breakdown = breakdown, advertisers = advertisers) }
        }
    }

    private inline fun updateContent(
        transform: (ContentAdControlsUiState.Content) -> ContentAdControlsUiState.Content,
    ) {
        (_uiState.value as? ContentAdControlsUiState.Content)?.let { _uiState.value = transform(it) }
    }

    private fun networkError() = ApiError(status = ApiError.STATUS_NETWORK, message = OFFLINE_FALLBACK)

    companion object {
        private const val DEFAULT_DAYS = 30
        private const val DEFAULT_SHARE_BPS = 7000
        private const val MAX_SHARE_BPS = 7000
        private const val OFFLINE_FALLBACK = "Could not reach the server. Try again."
        private const val REMOVE_FAIL = "Could not remove the override."
        private const val SHARE_RANGE = "Enter a percentage between 0 and 100."
    }
}
