package com.testlogon.android.feature.adminfraud

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminfraud.FraudAdminRepository
import com.testlogon.android.data.adminfraud.FraudCaseDto
import com.testlogon.android.data.adminfraud.FraudFlagDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 - admin fraud-review queue. Two tabs: FLAGS (review approve/block/investigate) and CASES (resolve
 * false_positive/confirmed_fraud/inconclusive). Mirrors /admin/fraud (FraudReviewQueuePage.tsx). 403 ->
 * Forbidden. Root-only config + freeze/risk actions are deferred.
 */
enum class FraudTab { FLAGS, CASES }

/** Flag review actions per FraudFlagReview (approve|block|investigate). */
val FRAUD_FLAG_ACTIONS: List<String> = listOf("approve", "block", "investigate")

/** Case resolutions per FraudCaseResolve (false_positive|confirmed_fraud|inconclusive). */
val FRAUD_CASE_RESOLUTIONS: List<String> = listOf("false_positive", "confirmed_fraud", "inconclusive")

sealed interface FraudDataState {
    data object Loading : FraudDataState
    data class Flags(
        val flags: List<FraudFlagDto>,
        val isRefreshing: Boolean = false,
    ) : FraudDataState
    data class Cases(
        val cases: List<FraudCaseDto>,
        val isRefreshing: Boolean = false,
    ) : FraudDataState
    data object Empty : FraudDataState
    data object Forbidden : FraudDataState
    data class Error(val type: AdminOpsErrorType) : FraudDataState
}

data class FraudAdminUiState(
    val tab: FraudTab = FraudTab.FLAGS,
    val data: FraudDataState = FraudDataState.Loading,
    val actionInFlightId: String? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class FraudAdminViewModel @Inject constructor(
    private val repo: FraudAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(FraudAdminUiState())
    val state: StateFlow<FraudAdminUiState> = _state.asStateFlow()

    init {
        load(FraudTab.FLAGS)
    }

    fun retry() = load(_state.value.tab)

    fun selectTab(tab: FraudTab) {
        if (_state.value.tab == tab && _state.value.data !is FraudDataState.Error) return
        load(tab)
    }

    fun refresh() {
        val cur = _state.value
        _state.value = cur.copy(
            data = when (val d = cur.data) {
                is FraudDataState.Flags -> d.copy(isRefreshing = true)
                is FraudDataState.Cases -> d.copy(isRefreshing = true)
                else -> d
            },
            transientError = null,
        )
        fetch(cur.tab, isRefresh = true)
    }

    private fun load(tab: FraudTab) {
        _state.value = _state.value.copy(tab = tab, data = FraudDataState.Loading)
        fetch(tab, isRefresh = false)
    }

    private fun fetch(tab: FraudTab, isRefresh: Boolean) {
        viewModelScope.launch {
            when (tab) {
                FraudTab.FLAGS -> when (val r = repo.queue("pending")) {
                    is ApiResult.Success -> {
                        val flags = r.data.flags
                        _state.value = _state.value.copy(
                            data = if (flags.isEmpty()) FraudDataState.Empty else FraudDataState.Flags(flags),
                        )
                    }
                    is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                    is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
                }
                FraudTab.CASES -> when (val r = repo.cases(null)) {
                    is ApiResult.Success -> {
                        val cases = r.data
                        _state.value = _state.value.copy(
                            data = if (cases.isEmpty()) FraudDataState.Empty else FraudDataState.Cases(cases),
                        )
                    }
                    is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                    is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
                }
            }
        }
    }

    fun reviewFlag(flagId: String, action: String, notes: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = flagId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.reviewFlag(flagId, action, notes)) {
                is ApiResult.Success -> {
                    val cur = _state.value
                    val d = cur.data as? FraudDataState.Flags
                    val updated = d?.flags?.map { if (it.flagId == flagId) r.data else it }
                    _state.value = cur.copy(
                        data = updated?.let { d.copy(flags = it) } ?: cur.data,
                        actionInFlightId = null,
                        message = "Flag ${action}d",
                    )
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun resolveCase(caseId: String, resolution: String, notes: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = caseId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.resolveCase(caseId, resolution, notes)) {
                is ApiResult.Success -> {
                    val cur = _state.value
                    val d = cur.data as? FraudDataState.Cases
                    val updated = d?.cases?.map {
                        if (it.caseId == caseId) it.copy(status = r.data.status.ifBlank { it.status }, resolution = r.data.resolution ?: resolution) else it
                    }
                    _state.value = cur.copy(
                        data = updated?.let { d.copy(cases = it) } ?: cur.data,
                        actionInFlightId = null,
                        message = "Case resolved: $resolution",
                    )
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    fun clearMessage() {
        _state.value = _state.value.copy(message = null, transientError = null)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = FraudDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is FraudDataState.Flags || cur.data is FraudDataState.Cases
        _state.value = if (isRefresh && hasData) {
            cur.copy(
                data = when (val d = cur.data) {
                    is FraudDataState.Flags -> d.copy(isRefreshing = false)
                    is FraudDataState.Cases -> d.copy(isRefreshing = false)
                    else -> d
                },
                transientError = type,
            )
        } else {
            cur.copy(data = FraudDataState.Error(type))
        }
    }
}
