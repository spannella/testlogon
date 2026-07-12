package com.testlogon.android.feature.vnc

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vnc.CreateVncSessionDto
import com.testlogon.android.data.vnc.VncRepository
import com.testlogon.android.data.vnc.VncTransferFallbackDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: Remote Desktop / VNC session broker. Creates a VNC session for a validated target,
 * surfaces the connection info, fetches the transfer fallback, and tears the session down. Mirrors
 * RemoteDesktopPage.tsx's control-plane behavior. The LIVE pixel viewer (noVNC RFB over ws_url) is NOT a
 * mobile surface — presented as an honest "open on desktop" state with the connection details. A server
 * error envelope carries a VNC error `code`; friendly copy is derived from it.
 */
data class RemoteDesktopUiState(
    val targetId: String = "demo",
    val creating: Boolean = false,
    val ending: Boolean = false,
    val session: CreateVncSessionDto? = null,
    val fallback: VncTransferFallbackDto? = null,
    val fallbackLoading: Boolean = false,
    val errorMessage: String? = null,
    val message: String? = null,
)

@HiltViewModel
class RemoteDesktopViewModel @Inject constructor(
    private val repo: VncRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(RemoteDesktopUiState())
    val state: StateFlow<RemoteDesktopUiState> = _state.asStateFlow()

    fun setTarget(id: String) { _state.value = _state.value.copy(targetId = id) }

    fun createSession() {
        val cur = _state.value
        if (cur.creating || cur.targetId.isBlank()) return
        _state.value = cur.copy(creating = true, errorMessage = null, message = null)
        viewModelScope.launch {
            when (val r = repo.createSession(cur.targetId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    creating = false,
                    session = r.data,
                    fallback = null,
                    message = "Session ready",
                )
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    creating = false,
                    errorMessage = vncErrorMessage(r.error),
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    creating = false,
                    errorMessage = "You appear to be offline. Check your connection.",
                )
            }
        }
    }

    fun loadFallback() {
        val sid = _state.value.session?.sessionId ?: return
        if (_state.value.fallbackLoading) return
        _state.value = _state.value.copy(fallbackLoading = true, errorMessage = null)
        viewModelScope.launch {
            when (val r = repo.transferFallback(sid)) {
                is ApiResult.Success -> _state.value = _state.value.copy(fallbackLoading = false, fallback = r.data)
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    fallbackLoading = false,
                    errorMessage = vncErrorMessage(r.error),
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    fallbackLoading = false,
                    errorMessage = "You appear to be offline. Check your connection.",
                )
            }
        }
    }

    fun endSession() {
        val sid = _state.value.session?.sessionId ?: return
        if (_state.value.ending) return
        _state.value = _state.value.copy(ending = true, errorMessage = null)
        viewModelScope.launch {
            when (val r = repo.deleteSession(sid)) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    ending = false,
                    session = null,
                    fallback = null,
                    message = "Session closed",
                )
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    ending = false,
                    session = null,
                    fallback = null,
                    message = "Session closed",
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    ending = false,
                    errorMessage = "You appear to be offline. Check your connection.",
                )
            }
        }
    }

    fun clearMessage() { _state.value = _state.value.copy(message = null, errorMessage = null) }

    /**
     * Map a VNC error to friendly copy, mirroring the web ERROR_MESSAGES. The VNC router nests the code
     * under a `detail.error.code` envelope, so [ApiError.code] is usually null (the generic parser only
     * reads a top-level `detail.code`); recover the nested code from the raw body when needed.
     */
    private fun vncErrorMessage(error: ApiError): String {
        val code = error.code ?: nestedErrorCode(error.raw as? String)
        return vncErrorMessage(code, error.status)
    }

    /** Best-effort extraction of `detail.error.code` from the raw JSON body (never throws). */
    private fun nestedErrorCode(body: String?): String? {
        if (body.isNullOrBlank()) return null
        val idx = body.indexOf("\"code\"")
        if (idx < 0) return null
        val colon = body.indexOf(':', idx)
        if (colon < 0) return null
        val q1 = body.indexOf('"', colon + 1)
        if (q1 < 0) return null
        val q2 = body.indexOf('"', q1 + 1)
        if (q2 < 0) return null
        return body.substring(q1 + 1, q2).takeIf { it.startsWith("VNC_") }
    }

    private fun vncErrorMessage(code: String?, status: Int): String = when (code) {
        "VNC_AUTH_UNAUTHORIZED" -> "You are not authorized to access this VNC target."
        "VNC_TARGET_NOT_FOUND" -> "Target not found. Select a registered target ID."
        "VNC_TARGET_UNREACHABLE" -> "The VNC target is currently unreachable."
        "VNC_BRIDGE_TIMEOUT" -> "Bridge timed out while connecting. Try again."
        "VNC_TOKEN_EXPIRED" -> "Session token expired. Start a new session."
        "VNC_TOKEN_INVALID" -> "Session token is invalid. Start a new session."
        "VNC_SESSION_NOT_FOUND" -> "Session not found. Start a new session."
        "VNC_SESSION_TERMINATED" -> "Session terminated by policy or timeout."
        "VNC_RATE_LIMITED" -> "Too many VNC session attempts. Please wait and retry."
        else -> when (status) {
            401 -> "Your session expired. Please sign in again."
            403 -> "You are not authorized to access remote desktop."
            else -> "Unexpected VNC error. Retry and contact support if it persists."
        }
    }
}
