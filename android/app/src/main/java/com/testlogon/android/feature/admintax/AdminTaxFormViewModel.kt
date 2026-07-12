package com.testlogon.android.feature.admintax

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.admintax.AdminForm1099Dto
import com.testlogon.android.data.admintax.AdminTaxFormRepository
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import javax.inject.Inject

/**
 * Web-parity admin 1099 MANAGER. Mirrors /admin/tax-forms-1099 (year selector + forms list + per-form
 * correct + generate-for-user + batch-generate). ADMIN-drivable; a backend 403 -> Forbidden. All write
 * actions reload the selected year on success.
 */
sealed interface AdminTaxUiState {
    data object Loading : AdminTaxUiState
    data class Content(
        val year: Int,
        val forms: List<AdminForm1099Dto>,
        val isRefreshing: Boolean = false,
        val actionInFlight: Boolean = false,
        val actionMessage: String? = null,
        val transientError: AdminOpsErrorType? = null,
    ) : AdminTaxUiState
    data object Forbidden : AdminTaxUiState
    data class Error(val type: AdminOpsErrorType) : AdminTaxUiState
}

@HiltViewModel
class AdminTaxFormViewModel @Inject constructor(
    private val repo: AdminTaxFormRepository,
) : ViewModel() {

    // Tax forms are filed the following calendar year; default to the most recent completed tax year.
    private var year: Int = LocalDate.now().year - 1

    /** Selectable years for the picker (most recent completed year and the four before it). */
    val years: List<Int> = (0..4).map { year - it }

    private val _state = MutableStateFlow<AdminTaxUiState>(AdminTaxUiState.Loading)
    val state: StateFlow<AdminTaxUiState> = _state.asStateFlow()

    init {
        load(resetLoading = true)
    }

    fun retry() = load(resetLoading = true)

    fun setYear(y: Int) {
        year = y
        load(resetLoading = true)
    }

    fun refresh() {
        val cur = _state.value
        if (cur is AdminTaxUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean = false) {
        if (resetLoading) _state.value = AdminTaxUiState.Loading
        viewModelScope.launch {
            when (val r = repo.listYear(year)) {
                is ApiResult.Success -> _state.value = AdminTaxUiState.Content(year = year, forms = r.data)
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun generateForUser(userSub: String) {
        val u = userSub.trim()
        if (u.isEmpty()) return
        runAction("Generated 1099 for $u.") { repo.generate(year, u) }
    }

    fun correctForUser(userSub: String) =
        runAction("Correction issued for $userSub.") { repo.correct(year, userSub) }

    fun batchGenerate() = runAction(null) { repo.batch(year) }

    private fun <T> runAction(successMsg: String?, block: suspend () -> ApiResult<T>) {
        val cur = _state.value as? AdminTaxUiState.Content ?: return
        if (cur.actionInFlight) return
        _state.value = cur.copy(actionInFlight = true, transientError = null, actionMessage = null)
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    val data = r.data
                    val msg = when {
                        successMsg != null -> successMsg
                        data is com.testlogon.android.data.admintax.AdminBatch1099ResultDto ->
                            "Batch: generated ${data.generated}, skipped ${data.skipped}, errors ${data.errors}."
                        else -> "Applied."
                    }
                    reloadAfterAction(msg)
                }
                is ApiResult.Failure -> reduceActionError(
                    if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    private suspend fun reloadAfterAction(successMsg: String) {
        when (val r = repo.listYear(year)) {
            is ApiResult.Success -> _state.value = AdminTaxUiState.Content(year = year, forms = r.data, actionMessage = successMsg)
            is ApiResult.Failure -> reduceActionError(adminOpsErrorFor(r.error.status))
            is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        if (status == 403) _state.value = AdminTaxUiState.Forbidden
        else reduceError(isRefresh, adminOpsErrorFor(status))
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? AdminTaxUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            AdminTaxUiState.Error(type)
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        val cur = _state.value as? AdminTaxUiState.Content ?: return
        _state.value = cur.copy(actionInFlight = false, transientError = type)
    }

    fun clearActionMessage() {
        val cur = _state.value
        if (cur is AdminTaxUiState.Content) {
            _state.value = cur.copy(actionMessage = null, transientError = null)
        }
    }
}
