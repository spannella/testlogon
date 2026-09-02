package com.testlogon.android.feature.infrak8s

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.infrak8s.K8sLaunchReq
import com.testlogon.android.data.infrak8s.K8sPodDto
import com.testlogon.android.data.infrak8s.K8sReference
import com.testlogon.android.data.infrak8s.K8sRepository
import com.testlogon.android.data.infrasweep.InfraSweepMath
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Cloud-Infra: K8s pod launcher management. List/deploy/terminate pods + view pod logs. Mirrors
 * K8sLauncherPage.tsx. Logs open in a modal fetched on demand. 403 -> Forbidden.
 */
sealed interface K8sDataState {
    data object Loading : K8sDataState
    data class Content(val pods: List<K8sPodDto>, val isRefreshing: Boolean = false) : K8sDataState
    data object Empty : K8sDataState
    data object Forbidden : K8sDataState
    data class Error(val type: AdminOpsErrorType) : K8sDataState
}

/** Pod-logs modal state. */
sealed interface K8sLogsState {
    data object Loading : K8sLogsState
    data class Loaded(val podId: String, val lines: List<String>) : K8sLogsState
    data class Error(val type: AdminOpsErrorType) : K8sLogsState
}

/** Pod-detail modal state (GET /pods/{id}); degrades to the list row on 404. */
sealed interface K8sDetailState {
    data object Loading : K8sDetailState
    data class Loaded(val pod: K8sPodDto) : K8sDetailState
    data class Error(val type: AdminOpsErrorType) : K8sDetailState
}

data class K8sUiState(
    val data: K8sDataState = K8sDataState.Loading,
    val reference: K8sReference? = null,
    val actionInFlightId: String? = null,
    val launchInFlight: Boolean = false,
    val logs: K8sLogsState? = null,
    val detail: K8sDetailState? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class K8sViewModel @Inject constructor(
    private val repo: K8sRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(K8sUiState())
    val state: StateFlow<K8sUiState> = _state.asStateFlow()

    init {
        load()
        loadReference()
    }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is K8sDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = K8sDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list(null)) {
                is ApiResult.Success -> {
                    val items = r.data.pods
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) K8sDataState.Empty else K8sDataState.Content(items),
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
                else -> Unit
            }
        }
    }

    fun launch(label: String, image: String, preset: String) {
        if (_state.value.launchInFlight) return
        if (label.isBlank() || image.isBlank()) return
        _state.value = _state.value.copy(launchInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.launch(K8sLaunchReq(label = label.trim(), image = image, preset = preset))) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(launchInFlight = false, message = "Deployed ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    launchInFlight = false,
                    transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER,
                )
                is ApiResult.NetworkError -> _state.value =
                    _state.value.copy(launchInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun terminate(podId: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = podId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.terminate(podId)) {
                is ApiResult.Success -> {
                    val cur = _state.value
                    val d = cur.data as? K8sDataState.Content
                    val updated = d?.pods?.map { if (it.podId == podId) r.data else it }
                    _state.value = cur.copy(
                        data = updated?.let { d.copy(pods = it) } ?: cur.data,
                        actionInFlightId = null,
                        message = "Pod terminated",
                    )
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun openLogs(podId: String) {
        _state.value = _state.value.copy(logs = K8sLogsState.Loading)
        viewModelScope.launch {
            when (val r = repo.logs(podId)) {
                is ApiResult.Success -> _state.value =
                    _state.value.copy(logs = K8sLogsState.Loaded(podId, r.data.lines))
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    logs = K8sLogsState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER),
                )
                is ApiResult.NetworkError -> _state.value =
                    _state.value.copy(logs = K8sLogsState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun closeLogs() {
        _state.value = _state.value.copy(logs = null)
    }
    /**
     * Open the pod detail (GET /pods/{id}). Reads the single pod fresh instead of filtering the
     * cached list; on 404/any failure we degrade to the [fallback] list row so the sheet still opens.
     */
    fun openDetail(fallback: K8sPodDto) {
        _state.value = _state.value.copy(detail = K8sDetailState.Loading)
        viewModelScope.launch {
            when (val r = repo.get(fallback.podId)) {
                is ApiResult.Success ->
                    _state.value = _state.value.copy(
                        detail = K8sDetailState.Loaded(InfraSweepMath.mergePodDetail(fallback, r.data)),
                    )
                is ApiResult.Failure ->
                    if (r.error.status == 404) {
                        _state.value = _state.value.copy(
                            detail = K8sDetailState.Loaded(InfraSweepMath.mergePodDetail(fallback, null)),
                        )
                    } else {
                        _state.value = _state.value.copy(
                            detail = K8sDetailState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER),
                        )
                    }
                is ApiResult.NetworkError ->
                    _state.value = _state.value.copy(detail = K8sDetailState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun closeDetail() {
        _state.value = _state.value.copy(detail = null)
    }

    fun clearMessage() {
        _state.value = _state.value.copy(message = null, transientError = null)
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = K8sDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is K8sDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as K8sDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = K8sDataState.Error(type))
        }
    }
}
