package com.testlogon.android.feature.referrals

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.referrals.GrowthLinks
import com.testlogon.android.data.referrals.ReferralDashboard
import com.testlogon.android.data.referrals.ReferralsRepository
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
 * AND-264 — drives [ReferralsUiState] from [ReferralsRepository].
 *
 * Loads the dashboard on first composition and on pull-to-refresh. An empty referral_codes[] -> the
 * Ineligible empty state; a hard 401 (after the AND-027 refresh+retry) -> SessionExpired. On a failed
 * refresh a cached snapshot is served behind a stale banner, else Error/Offline. One-shot copy/share/
 * message effects use a [Channel]-backed [effects] flow (not a StateFlow) so they are not replayed on
 * rotation. The VM is free of Android framework types — the link string is built here (pure) and the
 * Route performs the clipboard/share side effect.
 */
@HiltViewModel
class ReferralsViewModel @Inject constructor(
    private val repository: ReferralsRepository,
) : ViewModel() {

    private val webOrigin: String = GrowthLinks.WEB_ORIGIN

    private val _uiState = MutableStateFlow(ReferralsUiState(webOrigin = webOrigin))
    val uiState: StateFlow<ReferralsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<ReferralsEffect>(Channel.BUFFERED)
    val effects: Flow<ReferralsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    /** Copies the share link for the first active code (or the first code). */
    fun onCopyClicked() {
        primaryShareLink()?.let { link ->
            viewModelScope.launch {
                _effects.send(ReferralsEffect.CopyLink(link))
                _effects.send(ReferralsEffect.ShowMessage(R.string.referrals_link_copied))
            }
        }
    }

    /** Shares the link for the first active code (or the first code) via the system share sheet. */
    fun onShareClicked() {
        primaryShareLink()?.let { link ->
            viewModelScope.launch { _effects.send(ReferralsEffect.Share(link)) }
        }
    }

    /** Copies a specific code's link (per-code action). */
    fun onCopyCode(code: String) {
        linkFor(code)?.let { link ->
            viewModelScope.launch {
                _effects.send(ReferralsEffect.CopyLink(link))
                _effects.send(ReferralsEffect.ShowMessage(R.string.referrals_link_copied))
            }
        }
    }

    /** Shares a specific code's link (per-code action). */
    fun onShareCode(code: String) {
        linkFor(code)?.let { link ->
            viewModelScope.launch { _effects.send(ReferralsEffect.Share(link)) }
        }
    }

    /** Empty-state CTA: creates a new referral code, then reloads the dashboard. */
    fun onCreateCode() {
        if (_uiState.value.isCreatingCode) return
        _uiState.update { it.copy(isCreatingCode = true) }
        viewModelScope.launch {
            when (val result = repository.createCode()) {
                is ApiResult.Success -> {
                    _effects.send(ReferralsEffect.ShowMessage(R.string.referrals_code_created))
                    _uiState.update { it.copy(isCreatingCode = false) }
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(isCreatingCode = false) }
                    _effects.send(ReferralsEffect.ShowMessage(R.string.referrals_create_failed))
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(isCreatingCode = false) }
                    _effects.send(ReferralsEffect.ShowMessage(R.string.referrals_create_failed))
                }
            }
        }
    }

    private fun primaryShareLink(): String? {
        val codes = _uiState.value.dashboard?.codes ?: return null
        val code = codes.firstOrNull { it.active } ?: codes.firstOrNull() ?: return null
        return code.shareLink(webOrigin)
    }

    private fun linkFor(code: String): String? =
        _uiState.value.dashboard?.codes?.firstOrNull { it.code == code }?.shareLink(webOrigin)

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.dashboard != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else ReferralsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadDashboard()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> {
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update {
                            it.copy(phase = ReferralsUiState.Phase.SessionExpired, isRefreshing = false)
                        }
                    } else {
                        reduceFailure(result.error.message, offline = false)
                    }
                }
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: ReferralDashboard) {
        _uiState.update {
            it.copy(
                phase = if (data.isIneligible) {
                    ReferralsUiState.Phase.Ineligible
                } else {
                    ReferralsUiState.Phase.Content
                },
                dashboard = data,
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
                    phase = if (cached.isIneligible) {
                        ReferralsUiState.Phase.Ineligible
                    } else {
                        ReferralsUiState.Phase.Content
                    },
                    dashboard = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(ReferralsEffect.ShowMessage(R.string.referrals_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) ReferralsUiState.Phase.Offline else ReferralsUiState.Phase.Error,
                    dashboard = null,
                    isRefreshing = false,
                    isStale = false,
                    errorMessage = message,
                )
            }
        }
    }

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
