package com.testlogon.android.feature.inframonitoring

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.infraec2.Ec2InstanceDto
import com.testlogon.android.data.infraec2.Ec2Repository
import com.testlogon.android.data.inframonitoring.InstanceMonitoringRepository
import com.testlogon.android.data.inframonitoring.MonitoringSnapshot
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Cloud-Infra: Instance monitoring. The web reaches this per-instance from the EC2 detail; on mobile
 * (no direct sidebar route) we let the user pick one of their instances, then load its health + metric
 * series + lifecycle timeline + auto-restart policy. Reuses the EC2 repository for the instance picker.
 * 403 -> Forbidden.
 */
sealed interface MonitoringPickerState {
    data object Loading : MonitoringPickerState
    data class Ready(val instances: List<Ec2InstanceDto>) : MonitoringPickerState
    data object Empty : MonitoringPickerState
    data object Forbidden : MonitoringPickerState
    data class Error(val type: AdminOpsErrorType) : MonitoringPickerState
}

sealed interface MonitoringDetailState {
    data object Idle : MonitoringDetailState
    data object Loading : MonitoringDetailState
    data class Loaded(val snapshot: MonitoringSnapshot) : MonitoringDetailState
    data class Error(val type: AdminOpsErrorType) : MonitoringDetailState
}

data class MonitoringUiState(
    val picker: MonitoringPickerState = MonitoringPickerState.Loading,
    val selectedInstanceId: String? = null,
    val detail: MonitoringDetailState = MonitoringDetailState.Idle,
    val policyUpdating: Boolean = false,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class InstanceMonitoringViewModel @Inject constructor(
    private val ec2Repo: Ec2Repository,
    private val monitoringRepo: InstanceMonitoringRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(MonitoringUiState())
    val state: StateFlow<MonitoringUiState> = _state.asStateFlow()

    init {
        loadInstances()
    }

    fun retry() {
        val selected = _state.value.selectedInstanceId
        if (selected != null) {
            select(selected)
        } else {
            loadInstances()
        }
    }

    private fun loadInstances() {
        _state.value = _state.value.copy(picker = MonitoringPickerState.Loading)
        viewModelScope.launch {
            when (val r = ec2Repo.list(null)) {
                is ApiResult.Success -> {
                    val items = r.data.instances.filterNot { it.status.equals("terminated", ignoreCase = true) }
                    _state.value = _state.value.copy(
                        picker = if (items.isEmpty()) MonitoringPickerState.Empty
                        else MonitoringPickerState.Ready(items),
                    )
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    picker = when (r.error.status) {
                        403 -> MonitoringPickerState.Forbidden
                        401 -> MonitoringPickerState.Error(AdminOpsErrorType.AUTH)
                        else -> MonitoringPickerState.Error(AdminOpsErrorType.SERVER)
                    },
                )
                is ApiResult.NetworkError -> _state.value =
                    _state.value.copy(picker = MonitoringPickerState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun select(instanceId: String) {
        _state.value = _state.value.copy(selectedInstanceId = instanceId, detail = MonitoringDetailState.Loading)
        loadDetail(instanceId)
    }

    fun clearSelection() {
        _state.value = _state.value.copy(selectedInstanceId = null, detail = MonitoringDetailState.Idle)
    }

    fun refreshDetail() {
        _state.value.selectedInstanceId?.let { loadDetail(it) }
    }

    private fun loadDetail(instanceId: String) {
        viewModelScope.launch {
            when (val r = monitoringRepo.snapshot(instanceId)) {
                is ApiResult.Success -> _state.value =
                    _state.value.copy(detail = MonitoringDetailState.Loaded(r.data))
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    detail = MonitoringDetailState.Error(
                        if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER,
                    ),
                )
                is ApiResult.NetworkError -> _state.value =
                    _state.value.copy(detail = MonitoringDetailState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }

    /** Flip the auto-restart policy for the selected instance, then refresh the detail. */
    fun setAutoRestart(enabled: Boolean) {
        val instanceId = _state.value.selectedInstanceId ?: return
        if (_state.value.policyUpdating) return
        _state.value = _state.value.copy(policyUpdating = true)
        viewModelScope.launch {
            val r = monitoringRepo.updateRestartPolicy(instanceId, autoRestartEnabled = enabled)
            _state.value = _state.value.copy(
                policyUpdating = false,
                transientError = when (r) {
                    is ApiResult.Success -> null
                    is ApiResult.Failure ->
                        if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER
                    is ApiResult.NetworkError -> AdminOpsErrorType.NETWORK
                },
            )
            if (r is ApiResult.Success) loadDetail(instanceId)
        }
    }

    fun clearMessage() {
        _state.value = _state.value.copy(transientError = null)
    }
}
