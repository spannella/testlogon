package com.testlogon.android.feature.adminfraud

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminfraud.FraudAdminRepository
import com.testlogon.android.data.adminfraud.FraudCaseDto
import com.testlogon.android.data.adminfraud.FraudFlagDto
import com.testlogon.android.data.adminfraud.UserRiskProfileDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B5 / FIN-015 - admin fraud-detection console. Three tabs: FLAGS (review approve/block/investigate),
 * CASES (resolve false_positive/confirmed_fraud/inconclusive), and USER (risk lookup + freeze/unfreeze).
 * Mirrors /admin/fraud (fraudDetection.ts). 403 -> Forbidden. Root-only config + chargebacks + stats
 * are deferred (no UI surface).
 */
enum class FraudTab { FLAGS, CASES, USER }

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

/** Per-user risk lookup sub-state (the USER tab). */
sealed interface UserRiskState {
    data object Idle : UserRiskState
    data object Loading : UserRiskState
    data class Loaded(val profile: UserRiskProfileDto) : UserRiskState
    data object NotFound : UserRiskState
    data object Forbidden : UserRiskState
    data class Error(val type: AdminOpsErrorType) : UserRiskState
}

data class FraudAdminUiState(
    val tab: FraudTab = FraudTab.FLAGS,
    val data: FraudDataState = FraudDataState.Loading,
    val actionInFlightId: String? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
    val userQuery: String = "",
    val userRisk: UserRiskState = UserRiskState.Idle,
    val freezeInFlight: Boolean = false,
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
        if (tab == FraudTab.USER) {
            _state.value = _state.value.copy(tab = tab)
            return
        }
        if (_state.value.tab == tab && _state.value.data !is FraudDataState.Error) return
        load(tab)
    }

    fun refresh() {
        val cur = _state.value
        if (cur.tab == FraudTab.USER) {
            if (cur.userQuery.isNotBlank()) lookupUser()
            return
        }
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
                FraudTab.USER -> Unit
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

    // --- USER tab: risk lookup + freeze/unfreeze ---

    fun updateUserQuery(q: String) {
        _state.value = _state.value.copy(userQuery = q)
    }

    fun lookupUser() {
        val id = _state.value.userQuery.trim()
        if (id.isEmpty()) return
        _state.value = _state.value.copy(userRisk = UserRiskState.Loading, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.userRisk(id)) {
                is ApiResult.Success -> _state.value = _state.value.copy(userRisk = UserRiskState.Loaded(r.data))
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    userRisk = when (r.error.status) {
                        404 -> UserRiskState.NotFound
                        403 -> UserRiskState.Forbidden
                        401 -> UserRiskState.Error(AdminOpsErrorType.AUTH)
                        else -> UserRiskState.Error(AdminOpsErrorType.SERVER)
                    },
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(userRisk = UserRiskState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun freezeUser(reason: String) {
        val cur = _state.value
        val profile = (cur.userRisk as? UserRiskState.Loaded)?.profile ?: return
        if (cur.freezeInFlight) return
        _state.value = cur.copy(freezeInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.freezeUser(profile.userId, reason)) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    freezeInFlight = false,
                    userRisk = UserRiskState.Loaded(profile.copy(frozen = r.data.frozen, frozenAt = r.data.frozenAt)),
                    message = "User frozen",
                )
                is ApiResult.Failure -> reduceFreezeError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceFreezeError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun unfreezeUser() {
        val cur = _state.value
        val profile = (cur.userRisk as? UserRiskState.Loaded)?.profile ?: return
        if (cur.freezeInFlight) return
        _state.value = cur.copy(freezeInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.unfreezeUser(profile.userId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    freezeInFlight = false,
                    userRisk = UserRiskState.Loaded(profile.copy(frozen = r.data.frozen, frozenAt = null)),
                    message = "User unfrozen",
                )
                is ApiResult.Failure -> reduceFreezeError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceFreezeError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceFreezeError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(freezeInFlight = false, transientError = type)
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
