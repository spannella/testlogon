package com.testlogon.android.feature.affiliates

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.affiliates.AffiliateDashboard
import com.testlogon.android.data.affiliates.AffiliateLink
import com.testlogon.android.data.affiliates.AffiliateMath
import com.testlogon.android.data.affiliates.AffiliatesRepository
import com.testlogon.android.data.referrals.GrowthLinks
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
 * AND-265 — drives [AffiliatesUiState] from [AffiliatesRepository].
 *
 * Loads on first composition + pull-to-refresh. Empty links[] -> Empty; failed refresh with cache ->
 * stale Content (banner), else Error/Offline. Copy/share are one-shot [Channel] effects so the screen
 * performs the clipboard/intent side effect (VM stays Android-free); the full URL (webOrigin + short_url)
 * is built here. Create/delete are the two mutations: create validates via the pure [AffiliateMath] before
 * hitting the network; both fold their result into the repository snapshot and re-render.
 */
@HiltViewModel
class AffiliatesViewModel @Inject constructor(
    private val repository: AffiliatesRepository,
) : ViewModel() {

    private val webOrigin: String = GrowthLinks.WEB_ORIGIN

    private val _uiState = MutableStateFlow(AffiliatesUiState(webOrigin = webOrigin))
    val uiState: StateFlow<AffiliatesUiState> = _uiState.asStateFlow()

    private val _effects = Channel<AffiliatesEffect>(Channel.BUFFERED)
    val effects: Flow<AffiliatesEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)

    fun onRetry() = load(fromUser = true)

    fun onChartPointSelected(index: Int?) {
        _uiState.update { it.copy(selectedChartIndex = index) }
    }

    fun onCopyLink(linkId: String) {
        urlFor(linkId)?.let { url ->
            viewModelScope.launch {
                _effects.send(AffiliatesEffect.CopyUrl(url))
                _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_link_copied))
            }
        }
    }

    fun onShareLink(linkId: String) {
        urlFor(linkId)?.let { url ->
            viewModelScope.launch { _effects.send(AffiliatesEffect.ShareUrl(url)) }
        }
    }

    // ---- Create link ----

    fun onOpenCreate() {
        _uiState.update { it.copy(createForm = AffiliatesUiState.CreateForm()) }
    }

    fun onDismissCreate() {
        _uiState.update { it.copy(createForm = null) }
    }

    fun onCreateFormChanged(
        targetType: String? = null,
        targetId: String? = null,
        commissionPercent: String? = null,
        customCode: String? = null,
    ) {
        _uiState.update { state ->
            val form = state.createForm ?: return@update state
            state.copy(
                createForm = form.copy(
                    targetType = targetType ?: form.targetType,
                    targetId = targetId ?: form.targetId,
                    commissionPercent = commissionPercent ?: form.commissionPercent,
                    customCode = customCode ?: form.customCode,
                    errorRes = null,
                ),
            )
        }
    }

    fun onSubmitCreate() {
        val form = _uiState.value.createForm ?: return
        if (form.submitting) return

        // commission_percent is an OPTIONAL integer percentage; a non-numeric non-blank entry is invalid.
        val commissionRaw = form.commissionPercent.trim()
        val commission: Int? = if (commissionRaw.isEmpty()) {
            null
        } else {
            commissionRaw.toIntOrNull() ?: run {
                setCreateError(R.string.affiliates_create_error_commission)
                return
            }
        }

        when (
            val result = AffiliateMath.validateCreate(
                targetType = form.targetType,
                targetId = form.targetId,
                commissionPercent = commission,
                customCode = form.customCode,
            )
        ) {
            is AffiliateMath.CreateResult.Invalid -> setCreateError(errorRes(result.error))
            is AffiliateMath.CreateResult.Valid -> {
                _uiState.update { it.copy(createForm = form.copy(submitting = true, errorRes = null)) }
                viewModelScope.launch {
                    when (val r = repository.createLink(result.request)) {
                        is ApiResult.Success -> {
                            _uiState.update {
                                it.copy(
                                    createForm = null,
                                    dashboard = repository.cached(),
                                    phase = AffiliatesUiState.Phase.Content,
                                )
                            }
                            _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_create_success))
                        }
                        is ApiResult.Failure -> setCreateError(R.string.affiliates_create_error_generic)
                        is ApiResult.NetworkError -> setCreateError(R.string.affiliates_create_error_offline)
                    }
                }
            }
        }
    }

    private fun setCreateError(resId: Int) {
        _uiState.update { state ->
            val form = state.createForm ?: return@update state
            state.copy(createForm = form.copy(submitting = false, errorRes = resId))
        }
    }

    private fun errorRes(error: AffiliateMath.CreateError): Int = when (error) {
        AffiliateMath.CreateError.BLANK_TARGET_ID -> R.string.affiliates_create_error_target
        AffiliateMath.CreateError.COMMISSION_OUT_OF_RANGE -> R.string.affiliates_create_error_commission
        AffiliateMath.CreateError.INVALID_CUSTOM_CODE -> R.string.affiliates_create_error_code
    }

    // ---- Delete link ----

    fun onRequestDelete(linkId: String) {
        val link = _uiState.value.dashboard?.links?.firstOrNull { it.id == linkId } ?: return
        _uiState.update {
            it.copy(
                pendingDelete = AffiliatesUiState.PendingDelete(
                    linkId = linkId,
                    label = link.label.ifBlank { link.trackingCode },
                ),
            )
        }
    }

    fun onDismissDelete() {
        _uiState.update { it.copy(pendingDelete = null) }
    }

    fun onConfirmDelete() {
        val pending = _uiState.value.pendingDelete ?: return
        if (pending.deleting) return
        _uiState.update { it.copy(pendingDelete = pending.copy(deleting = true)) }
        viewModelScope.launch {
            when (repository.deleteLink(pending.linkId)) {
                is ApiResult.Success -> {
                    val next = repository.cached()
                    _uiState.update {
                        it.copy(
                            pendingDelete = null,
                            dashboard = next,
                            phase = if (next == null || next.isEmpty) {
                                AffiliatesUiState.Phase.Empty
                            } else {
                                AffiliatesUiState.Phase.Content
                            },
                        )
                    }
                    _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_delete_success))
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(pendingDelete = pending.copy(deleting = false)) }
                    _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_delete_failed))
                }
            }
        }
    }

    private fun urlFor(linkId: String): String? =
        _uiState.value.dashboard?.links?.firstOrNull { it.id == linkId }?.shareUrl(webOrigin)

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.dashboard != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else AffiliatesUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
                errorMessage = if (hasContent) it.errorMessage else null,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadDashboard()) {
                is ApiResult.Success -> reduceSuccess(result.data)
                is ApiResult.Failure -> reduceFailure(result.error.message, offline = false)
                is ApiResult.NetworkError -> reduceFailure(OFFLINE_FALLBACK, offline = true)
            }
        }
    }

    private fun reduceSuccess(data: AffiliateDashboard) {
        _uiState.update {
            it.copy(
                phase = if (data.isEmpty) AffiliatesUiState.Phase.Empty else AffiliatesUiState.Phase.Content,
                dashboard = data,
                isRefreshing = false,
                isStale = false,
                selectedChartIndex = null,
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
                        AffiliatesUiState.Phase.Empty
                    } else {
                        AffiliatesUiState.Phase.Content
                    },
                    dashboard = cached,
                    isRefreshing = false,
                    isStale = true,
                    errorMessage = null,
                )
            }
            _effects.send(AffiliatesEffect.ShowMessage(R.string.affiliates_refresh_failed_stale))
        } else {
            _uiState.update {
                it.copy(
                    phase = if (offline) AffiliatesUiState.Phase.Offline else AffiliatesUiState.Phase.Error,
                    dashboard = null,
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
