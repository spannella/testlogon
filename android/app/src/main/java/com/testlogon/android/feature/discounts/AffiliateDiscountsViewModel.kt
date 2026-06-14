package com.testlogon.android.feature.discounts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discounts.AffiliateDiscounts
import com.testlogon.android.data.discounts.AffiliateDiscountsRepository
import com.testlogon.android.data.discounts.DiscountKind
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
 * AND-267 — drives [AffiliateDiscountsUiState] from [AffiliateDiscountsRepository].
 *
 * Loads the attached affiliate discounts on first composition + pull-to-refresh. An empty items[] -> the
 * Empty state; on a failed refresh a cached snapshot is served behind a stale banner, else Error/Offline
 * (mirrors AND-265's affiliates VM). Copy/share are one-shot [Channel] effects so the screen performs the
 * clipboard/intent side effect (VM stays Android-free). The displayed value is promo_value_display
 * verbatim; the share text is click_through_url (or the code fallback) — there is no server share_url.
 */
@HiltViewModel
class AffiliateDiscountsViewModel @Inject constructor(
    private val repository: AffiliateDiscountsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(AffiliateDiscountsUiState())
    val uiState: StateFlow<AffiliateDiscountsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AffiliateDiscountsEffect>(Channel.BUFFERED)
    val effects: Flow<AffiliateDiscountsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    /** Client-side chip filter over the loaded list (best-effort derived kind). Null = show all. */
    fun onFilterSelected(kind: DiscountKind?) {
        _uiState.update { it.copy(filterKind = kind) }
    }

    /** Copies the discount's code (promo_code, falling back to affiliate_code) to the clipboard. */
    fun onCopyCode(creativeId: String) {
        discountFor(creativeId)?.displayCode?.let { code ->
            viewModelScope.launch {
                _effects.send(AffiliateDiscountsEffect.CopyCode(code))
                _effects.send(AffiliateDiscountsEffect.ShowMessage(R.string.discounts_code_copied))
            }
        }
    }

    /** Shares the discount's click-through URL (or the code text when absent) via the share sheet. */
    fun onShareLink(creativeId: String) {
        discountFor(creativeId)?.shareText()?.let { text ->
            viewModelScope.launch { _effects.send(AffiliateDiscountsEffect.ShareLink(text)) }
        }
    }

    private fun discountFor(creativeId: String) =
        _uiState.value.discounts?.items?.firstOrNull { it.creativeId == creativeId }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.discounts != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else AffiliateDiscountsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadDiscounts()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> reduceFailure(result.error.message, offline = false)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: AffiliateDiscounts) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) {
                    AffiliateDiscountsUiState.Phase.Empty
                } else {
                    AffiliateDiscountsUiState.Phase.Content
                },
                discounts = data,
                isRefreshing = false,
                isStale = false,
                errorMessage = null,
            )
        }
    }

    private suspend fun reduceFailure(message: String, offline: Boolean) {
        val cached = repository.cached()
        if (cached != null) {
            _uiState.update {
                it.copy(
                    phase = if (cached.isEmpty) {
                        AffiliateDiscountsUiState.Phase.Empty
                    } else {
                        AffiliateDiscountsUiState.Phase.Content
                    },
                    discounts = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(AffiliateDiscountsEffect.ShowMessage(R.string.discounts_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) {
                        AffiliateDiscountsUiState.Phase.Offline
                    } else {
                        AffiliateDiscountsUiState.Phase.Error
                    },
                    discounts = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    companion object {
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
