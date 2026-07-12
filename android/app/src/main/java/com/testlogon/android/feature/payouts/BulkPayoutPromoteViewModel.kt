package com.testlogon.android.feature.payouts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.payouts.BulkEligibleItem
import com.testlogon.android.data.payouts.BulkPayoutPromoteRepository
import com.testlogon.android.data.payouts.PayoutBatch
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Web-parity admin bulk-payout PROMOTE console (eligible -> select -> preview -> EXECUTE). Mirrors the
 * write half of /admin/bulk-payouts. ADMIN-drivable; a backend 403 -> Forbidden.
 *
 * EXECUTE MOVES REAL FUNDS. The state machine is deliberately explicit: the user selects eligible items,
 * requests a Preview (a draft batch, no funds moved), then must confirm to Execute. The confirm dialog is
 * driven by the screen; this VM only exposes `preview()` and `execute()`.
 */
sealed interface BulkPromoteUiState {
    data object Loading : BulkPromoteUiState
    data class Content(
        val kind: String,
        val eligible: List<BulkEligibleItem>,
        val selected: Set<String> = emptySet(),
        val preview: PayoutBatch? = null,
        val executed: PayoutBatch? = null,
        val actionInFlight: Boolean = false,
        val isRefreshing: Boolean = false,
        val actionMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : BulkPromoteUiState
    data object Forbidden : BulkPromoteUiState
    data class Error(val type: AdminOpsErrorType) : BulkPromoteUiState
}

@HiltViewModel
class BulkPayoutPromoteViewModel @Inject constructor(
    private val repo: BulkPayoutPromoteRepository,
) : ViewModel() {

    private val kind = "payout"

    private val _state = MutableStateFlow<BulkPromoteUiState>(BulkPromoteUiState.Loading)
    val state: StateFlow<BulkPromoteUiState> = _state.asStateFlow()

    init {
        loadEligible(resetLoading = true)
    }

    fun retry() = loadEligible(resetLoading = true)

    fun refresh() {
        val cur = _state.value
        if (cur is BulkPromoteUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        loadEligible(resetLoading = false, isRefresh = true)
    }

    private fun loadEligible(resetLoading: Boolean, isRefresh: Boolean = false) {
        if (resetLoading) _state.value = BulkPromoteUiState.Loading
        viewModelScope.launch {
            when (val r = repo.eligible(kind)) {
                is ApiResult.Success -> {
                    // Preserve any still-valid selection across a refresh.
                    val keepSel = (_state.value as? BulkPromoteUiState.Content)?.selected.orEmpty()
                    val validIds = r.data.map { it.refId }.toSet()
                    _state.value = BulkPromoteUiState.Content(
                        kind = kind,
                        eligible = r.data,
                        selected = keepSel.intersect(validIds),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun toggle(refId: String) {
        val cur = _state.value as? BulkPromoteUiState.Content ?: return
        if (cur.actionInFlight) return
        val next = if (refId in cur.selected) cur.selected - refId else cur.selected + refId
        // Selecting changes the basis, so any prior preview/execute is invalidated.
        _state.value = cur.copy(selected = next, preview = null, executed = null)
    }

    fun selectAll() {
        val cur = _state.value as? BulkPromoteUiState.Content ?: return
        _state.value = cur.copy(selected = cur.eligible.map { it.refId }.toSet(), preview = null, executed = null)
    }

    fun clearSelection() {
        val cur = _state.value as? BulkPromoteUiState.Content ?: return
        _state.value = cur.copy(selected = emptySet(), preview = null, executed = null)
    }

    fun preview() {
        val cur = _state.value as? BulkPromoteUiState.Content ?: return
        if (cur.actionInFlight || cur.selected.isEmpty()) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null, executed = null)
        viewModelScope.launch {
            when (val r = repo.preview(cur.kind, cur.selected.toList())) {
                is ApiResult.Success -> {
                    val c = _state.value as? BulkPromoteUiState.Content ?: return@launch
                    _state.value = c.copy(actionInFlight = false, preview = r.data)
                }
                is ApiResult.Failure -> reduceActionError(
                    if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    /** MOVES REAL FUNDS. Executes the previewed draft batch (by its batch_id). */
    fun execute() {
        val cur = _state.value as? BulkPromoteUiState.Content ?: return
        val draft = cur.preview ?: return
        if (cur.actionInFlight) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null)
        viewModelScope.launch {
            when (val r = repo.execute(cur.kind, cur.selected.toList(), draft.id)) {
                is ApiResult.Success -> {
                    // Executed: reload eligible (the executed refs drop out) and surface the result batch.
                    val batch = r.data
                    when (val el = repo.eligible(cur.kind)) {
                        is ApiResult.Success -> _state.value = BulkPromoteUiState.Content(
                            kind = cur.kind,
                            eligible = el.data,
                            executed = batch,
                            actionMessage = "Executed ${batch.successCount}/${batch.itemCount} " +
                                "(${batch.failureCount} failed).",
                        )
                        else -> {
                            val c = _state.value as? BulkPromoteUiState.Content ?: return@launch
                            _state.value = c.copy(
                                actionInFlight = false,
                                preview = null,
                                selected = emptySet(),
                                executed = batch,
                                actionMessage = "Executed ${batch.successCount}/${batch.itemCount}.",
                            )
                        }
                    }
                }
                is ApiResult.Failure -> reduceActionError(
                    if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        if (status == 403) _state.value = BulkPromoteUiState.Forbidden
        else reduceError(isRefresh, adminOpsErrorFor(status))
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? BulkPromoteUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            BulkPromoteUiState.Error(type)
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? BulkPromoteUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, transientError = type)
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is BulkPromoteUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}
