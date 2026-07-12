package com.testlogon.android.feature.sshkeys

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.sshkeys.GenerateSshKeyReq
import com.testlogon.android.data.sshkeys.PublicKeyDto
import com.testlogon.android.data.sshkeys.SshKeyDto
import com.testlogon.android.data.sshkeys.SshKeysRepository
import com.testlogon.android.data.sshkeys.UploadSshKeyReq
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * B7 Remote-Access: SSH-key management. Lists the caller's keys (owner-scoped), generates a new key
 * pair (server keeps the private key), uploads an existing private key, deletes, and shows/copies the
 * OpenSSH public key. Mirrors SshKeyManagerPage.tsx. A 403 renders Forbidden. Reuses AdminOpsErrorType.
 */
sealed interface SshKeysDataState {
    data object Loading : SshKeysDataState
    data class Content(val keys: List<SshKeyDto>, val isRefreshing: Boolean = false) : SshKeysDataState
    data object Empty : SshKeysDataState
    data object Forbidden : SshKeysDataState
    data class Error(val type: AdminOpsErrorType) : SshKeysDataState
}

data class SshKeysUiState(
    val data: SshKeysDataState = SshKeysDataState.Loading,
    val mutating: Boolean = false,
    val actionInFlightId: String? = null,
    val publicKey: PublicKeyDto? = null,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class SshKeysViewModel @Inject constructor(
    private val repo: SshKeysRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(SshKeysUiState())
    val state: StateFlow<SshKeysUiState> = _state.asStateFlow()

    init { load() }

    fun retry() = load()

    fun refresh() {
        val cur = _state.value
        if (cur.data is SshKeysDataState.Content) {
            _state.value = cur.copy(data = cur.data.copy(isRefreshing = true), transientError = null)
        }
        fetch(isRefresh = true)
    }

    private fun load() {
        _state.value = _state.value.copy(data = SshKeysDataState.Loading)
        fetch(isRefresh = false)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> {
                    val items = r.data.keys
                    _state.value = _state.value.copy(
                        data = if (items.isEmpty()) SshKeysDataState.Empty else SshKeysDataState.Content(items),
                    )
                }
                is ApiResult.Failure -> reduceFailure(isRefresh, r.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun generate(label: String, keyType: String, keyBits: Int) {
        if (_state.value.mutating || label.isBlank()) return
        _state.value = _state.value.copy(mutating = true, transientError = null, message = null)
        viewModelScope.launch {
            val req = GenerateSshKeyReq(label = label.trim(), keyType = keyType, keyBits = keyBits)
            when (val r = repo.generate(req)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(mutating = false, message = "Generated ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceMutateError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceMutateError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun upload(label: String, privateKeyPem: String, passphrase: String?) {
        if (_state.value.mutating || label.isBlank() || privateKeyPem.isBlank()) return
        _state.value = _state.value.copy(mutating = true, transientError = null, message = null)
        viewModelScope.launch {
            val req = UploadSshKeyReq(
                label = label.trim(),
                privateKeyPem = privateKeyPem,
                passphrase = passphrase?.takeIf { it.isNotBlank() },
            )
            when (val r = repo.upload(req)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(mutating = false, message = "Imported ${r.data.label}")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceMutateError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceMutateError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun delete(keyId: String) {
        if (_state.value.actionInFlightId != null) return
        _state.value = _state.value.copy(actionInFlightId = keyId, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.delete(keyId)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlightId = null, message = "Key deleted")
                    fetch(isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun showPublicKey(keyId: String) {
        viewModelScope.launch {
            when (val r = repo.publicKey(keyId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(publicKey = r.data)
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER,
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun dismissPublicKey() { _state.value = _state.value.copy(publicKey = null) }

    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }

    private fun reduceMutateError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(mutating = false, transientError = type)
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        _state.value = _state.value.copy(actionInFlightId = null, transientError = type)
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) = when (status) {
        403 -> _state.value = _state.value.copy(data = SshKeysDataState.Forbidden)
        401 -> reduceError(isRefresh, AdminOpsErrorType.AUTH)
        else -> reduceError(isRefresh, AdminOpsErrorType.SERVER)
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val cur = _state.value
        val hasData = cur.data is SshKeysDataState.Content
        _state.value = if (isRefresh && hasData) {
            cur.copy(data = (cur.data as SshKeysDataState.Content).copy(isRefreshing = false), transientError = type)
        } else {
            cur.copy(data = SshKeysDataState.Error(type))
        }
    }
}
