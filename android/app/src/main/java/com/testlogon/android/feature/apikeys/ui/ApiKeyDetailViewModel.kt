package com.testlogon.android.feature.apikeys.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.apikeys.data.ApiKey
import com.testlogon.android.feature.apikeys.data.ApiKeyCapabilities
import com.testlogon.android.feature.apikeys.data.ApiKeysRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Batch 8 (#17, #18) - drives the API-key DETAIL screen: capability editing (PATCH scopes) + IP-rule management
 * (POST ip_rules, full SET/replace).
 *
 * The detail seeds from the repository's in-memory snapshot (the list already loaded it, INCLUDING allow/deny
 * CIDRs); if no cache row exists yet (e.g. process death) it does a one-shot [ApiKeysRepository.list] to repopulate
 * it. Capability edits and IP-rule edits write through to the cache so the list reflects them on back.
 */
@HiltViewModel
class ApiKeyDetailViewModel @Inject constructor(
    private val repo: ApiKeysRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val keyId: String = checkNotNull(savedStateHandle[ARG_KEY_ID]) { "missing $ARG_KEY_ID" }

    private val _state = MutableStateFlow(ApiKeyDetailUiState(keyId = keyId, loading = true))
    val state: StateFlow<ApiKeyDetailUiState> = _state.asStateFlow()

    private val _effects = Channel<ApiKeysEffect>(Channel.BUFFERED)
    val effects: Flow<ApiKeysEffect> = _effects.receiveAsFlow()

    init {
        load()
    }

    private fun load() {
        val cached = repo.cached(keyId)
        if (cached != null) {
            _state.value = _state.value.fromKey(cached).copy(loading = false)
        } else {
            viewModelScope.launch {
                when (repo.list()) {
                    is ApiResult.Success -> {
                        val row = repo.cached(keyId)
                        _state.value = if (row != null) {
                            _state.value.fromKey(row).copy(loading = false)
                        } else {
                            _state.value.copy(loading = false, loadError = NOT_FOUND)
                        }
                    }
                    else -> _state.value = _state.value.copy(loading = false, loadError = OFFLINE)
                }
            }
        }
    }

    // ---- capability editing (#17) ----

    fun toggleCapability(id: String) {
        val s = _state.value
        if (s.savingCapabilities) return
        val next = if (id in s.editedCapabilities) s.editedCapabilities - id else s.editedCapabilities + id
        _state.value = s.copy(editedCapabilities = next, capabilityError = null)
    }

    fun saveCapabilities() {
        val s = _state.value
        if (s.savingCapabilities || !s.capabilitiesDirty) return
        val payload = ApiKeyCapabilities.ALL.map { it.id }.filter { it in s.editedCapabilities }
        _state.value = s.copy(savingCapabilities = true, capabilityError = null)
        viewModelScope.launch {
            when (val r = repo.setCapabilities(keyId, payload)) {
                is ApiResult.Success ->
                    _state.value = _state.value.copy(
                        savingCapabilities = false,
                        capabilities = r.data,
                        editedCapabilities = r.data.toSet(),
                    )
                is ApiResult.Failure -> handleMutationError(r.error.status, r.error.message) {
                    _state.value = _state.value.copy(savingCapabilities = false, capabilityError = it)
                }
                is ApiResult.NetworkError ->
                    _state.value = _state.value.copy(savingCapabilities = false, capabilityError = OFFLINE)
            }
        }
    }

    // ---- IP-rule management (#18) ----

    fun addAllow(cidr: String) = mutateIpRules { it.copy(allowCidrs = it.allowCidrs + cidr.trim()) }
    fun removeAllow(cidr: String) = mutateIpRules { it.copy(allowCidrs = it.allowCidrs - cidr) }
    fun addDeny(cidr: String) = mutateIpRules { it.copy(denyCidrs = it.denyCidrs + cidr.trim()) }
    fun removeDeny(cidr: String) = mutateIpRules { it.copy(denyCidrs = it.denyCidrs - cidr) }

    /** Edit (replace) a CIDR in-place: removes [old] then adds [new] in the same SET round-trip. */
    fun editAllow(old: String, new: String) =
        mutateIpRules { it.copy(allowCidrs = it.allowCidrs.map { c -> if (c == old) new.trim() else c }) }
    fun editDeny(old: String, new: String) =
        mutateIpRules { it.copy(denyCidrs = it.denyCidrs.map { c -> if (c == old) new.trim() else c }) }

    private fun mutateIpRules(transform: (ApiKeyDetailUiState) -> ApiKeyDetailUiState) {
        val s = _state.value
        if (s.savingIpRules) return
        val target = transform(s)
        val allow = target.allowCidrs.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        val deny = target.denyCidrs.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        _state.value = s.copy(savingIpRules = true, ipRuleError = null)
        viewModelScope.launch {
            when (val r = repo.setIpRules(keyId, allow, deny)) {
                is ApiResult.Success ->
                    _state.value = _state.value.copy(
                        savingIpRules = false,
                        allowCidrs = r.data.first,
                        denyCidrs = r.data.second,
                    )
                is ApiResult.Failure -> handleMutationError(r.error.status, r.error.message) {
                    _state.value = _state.value.copy(savingIpRules = false, ipRuleError = it)
                }
                is ApiResult.NetworkError ->
                    _state.value = _state.value.copy(savingIpRules = false, ipRuleError = OFFLINE)
            }
        }
    }

    private inline fun handleMutationError(status: Int?, message: String, setError: (String) -> Unit) {
        // A fresh-MFA 401 surfaces inline (the user can re-verify); a non-MFA 401 routes to the re-auth handoff.
        if (status == HTTP_UNAUTHORIZED && !message.contains("MFA", ignoreCase = true)) {
            _effects.trySend(ApiKeysEffect.NavigateToLogin)
            setError(message)
        } else {
            setError(message)
        }
    }

    private fun ApiKeyDetailUiState.fromKey(key: ApiKey): ApiKeyDetailUiState = copy(
        label = key.label,
        prefix = key.prefix,
        capabilities = key.capabilities,
        editedCapabilities = key.capabilities.toSet(),
        allowCidrs = key.allowCidrs,
        denyCidrs = key.denyCidrs,
        loadError = null,
    )

    companion object {
        const val ARG_KEY_ID = "keyId"
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE = "Couldn't reach the server. Try again."
        private const val NOT_FOUND = "This key is no longer available."
    }
}
