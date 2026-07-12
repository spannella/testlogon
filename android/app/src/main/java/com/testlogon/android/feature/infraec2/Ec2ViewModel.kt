package com.testlogon.android.feature.infraec2

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.infraec2.Ec2Action
import com.testlogon.android.data.infraec2.Ec2InstanceDto
import com.testlogon.android.data.infraec2.Ec2LaunchReq
import com.testlogon.android.data.infraec2.Ec2Reference
import com.testlogon.android.data.infraec2.Ec2Repository
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Cloud-Infra: EC2 launcher management. Lists the caller's instances (owner-scoped), launches new
 * ones from the instance-type + AMI reference, and drives lifecycle actions (start/stop/reboot/terminate).
 * Mirrors Ec2LauncherPage.tsx. A 403 (defence-in-depth) renders Forbidden. Reuses AdminOpsErrorType.
 */
sealed interface Ec2DataState {
    data object Loading : Ec2DataState
    data class Content(
        val instances: List<Ec2InstanceDto>,
        val isRefreshing: Boolean = false,
    ) : Ec2DataState
    data object Empty : Ec2DataState
    data object Forbidden : Ec2DataState
    data class Error(val type: AdminOpsErrorType) : Ec2DataState
}

data class Ec2UiState(
    val data: Ec2DataState = Ec2DataState.Loading,
    val reference: Ec2Reference? = null,
    val actionInFlightId: String? = null,
    val launchInFlight: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class Ec2ViewModel @Inject constructor(
    private val repo: Ec2Repository,
) : ViewModel() {

    private val _state = MutableStateFlow(Ec2UiState())
    val state: StateFlow<Ec2UiState> = _state.asStateFlow()

    init {
        load()
        loadReference()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is Ec2DataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = Ec2DataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(null)) {
                is ApiResult.Success -> {
                    val items = r.data.instances
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) Ec2DataState.Empty else Ec2DataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun loadReference() {
        viewModelScope.launch {
            when (val r = repo.reference()) {
                is ApiResult.Success -> _state.value = _state.value.copy(reference = r.data)
                else -> Unit // launch form self-disables until reference loads
            }
        }
    }

    fun launch(
        label: String,
        instanceType: String,
        amiId: String,
        sshKeyId: String?,
        securityGroupId: String?,
    ) {
        if (_state.value.launchInFlight) return
        if (label.isBlank() || instanceType.isBlank() || amiId.isBlank()) return
        _state.value = _state.value.copy(launchInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            val req = Ec2LaunchReq(
                label = label.trim(),
                instanceType = instanceType,
                amiId = amiId,
                sshKeyId = sshKeyId?.takeIf { it.isNotBlank() },
                securityGroupId = securityGroupId?.takeIf { it.isNotBlank() },
            )
            when (val r = repo.launch(req)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(launchInFlight = false, message = "Launched ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> {
                    _state.value = _state.value.copy(
                        launchInFlight = false,
                        transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER,
                    )
                }
                is ApiResult.NetworkError -> {
                    _state.value = _state.value.copy(launchInFlight = false, transientError = AdminOpsErrorType.NETWORK)
                }
            }
        }
    }

    fun performAction(instanceId: String, action: Ec2Action) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = instanceId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.action(instanceId, action)) {
                is ApiResult.Success -> {
                    val cur = _state.value
                    val d = cur.data as? Ec2DataState.Content
                    val updated = d?.instances?.map { if (it.instanceId == instanceId) r.data else it }
                    _state.value = cur.copy(
                        data = updated?.let { d.copy(instances = it) } ?: cur.data,
                        actionInFlightId = null,
                        message = "${action.name.lowercase().replaceFirstChar { it.uppercase() }} sent",
                    )
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clearMessage() {
        _state.value = _state.value.copy(message = null, transientError = null)
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = Ec2DataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is Ec2DataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as Ec2DataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = Ec2DataState.Error(type))
        }
    }
}
