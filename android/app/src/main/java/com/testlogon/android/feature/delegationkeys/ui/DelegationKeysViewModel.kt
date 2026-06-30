package com.testlogon.android.feature.delegationkeys.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.delegationkeys.data.DelegationApiKey
import com.testlogon.android.feature.delegationkeys.data.DelegationKeyRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives the [DelegationKeysUiState] for the delegation-API keys screen (web parity: /delegation-api).
 *
 * load() fetches both key groups in parallel (Loading -> Content/Error). refresh() keeps the current
 * content and flips isStale on a non-fatal failure. create*() drive the dialog (which lazily fetches the
 * managed-creators list). revoke() removes a key from the appropriate tab. There is NO poll loop.
 */
@HiltViewModel
class DelegationKeysViewModel @Inject constructor(
    private val repo: DelegationKeyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow<DelegationKeysUiState>(DelegationKeysUiState.Loading)
    val uiState: StateFlow<DelegationKeysUiState> = _uiState.asStateFlow()

    private val _createForm = MutableStateFlow(CreateDelegationKeyForm())
    val createForm: StateFlow<CreateDelegationKeyForm> = _createForm.asStateFlow()

    private var loadJob: Job? = null

    init {
        load()
    }

    fun load() {
        if (loadJob?.isActive == true) return
        if (_uiState.value !is DelegationKeysUiState.Content) {
            _uiState.value = DelegationKeysUiState.Loading
        }
        fetch(isRefresh = false)
    }

    fun retry() = load()

    fun refresh() {
        if (loadJob?.isActive == true) return
        val current = _uiState.value as? DelegationKeysUiState.Content
        if (current != null) _uiState.value = current.copy(isRefreshing = true)
        fetch(isRefresh = true)
    }

    fun selectTab(tab: DelegationKeysTab) {
        val current = _uiState.value as? DelegationKeysUiState.Content ?: return
        _uiState.value = current.copy(tab = tab)
    }

    private fun fetch(isRefresh: Boolean) {
        loadJob = viewModelScope.launch {
            val mineDeferred = async { repo.listMyKeys() }
            val creatorDeferred = async { repo.listCreatorKeys() }
            val mine = mineDeferred.await()
            val creator = creatorDeferred.await()
            // Both must succeed to fully refresh; otherwise surface a failure (keeping prior content if any).
            if (mine is ApiResult.Success && creator is ApiResult.Success) {
                val prior = _uiState.value as? DelegationKeysUiState.Content
                _uiState.value = DelegationKeysUiState.Content(
                    tab = prior?.tab ?: DelegationKeysTab.MINE,
                    myKeys = mine.data,
                    creatorKeys = creator.data,
                    newSecret = prior?.newSecret,
                )
            } else {
                val message = firstError(mine) ?: firstError(creator) ?: OFFLINE_FALLBACK
                emitFailure(isRefresh, message)
            }
        }
    }

    private fun firstError(result: ApiResult<List<DelegationApiKey>>): String? = when (result) {
        is ApiResult.Failure -> result.error.message
        is ApiResult.NetworkError -> OFFLINE_FALLBACK
        is ApiResult.Success -> null
    }

    private fun emitFailure(isRefresh: Boolean, message: String) {
        val prior = _uiState.value as? DelegationKeysUiState.Content
        _uiState.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, isStale = true)
        } else {
            DelegationKeysUiState.Error(message)
        }
    }

    // ---- Revoke ----

    fun revoke(keyId: String) {
        val current = _uiState.value as? DelegationKeysUiState.Content ?: return
        if (current.revokingId != null) return
        val isCreatorTab = current.tab == DelegationKeysTab.CREATOR
        _uiState.value = current.copy(revokingId = keyId, actionError = null)
        viewModelScope.launch {
            val result = if (isCreatorTab) repo.revokeCreatorKey(keyId) else repo.revokeMyKey(keyId)
            val now = _uiState.value as? DelegationKeysUiState.Content ?: return@launch
            when (result) {
                is ApiResult.Success -> {
                    _uiState.value = if (isCreatorTab) {
                        now.copy(creatorKeys = now.creatorKeys.filterNot { it.keyId == keyId }, revokingId = null)
                    } else {
                        now.copy(myKeys = now.myKeys.filterNot { it.keyId == keyId }, revokingId = null)
                    }
                }
                is ApiResult.Failure ->
                    _uiState.value = now.copy(revokingId = null, actionError = result.error.message)
                is ApiResult.NetworkError ->
                    _uiState.value = now.copy(revokingId = null, actionError = OFFLINE_FALLBACK)
            }
        }
    }

    fun dismissSecret() {
        val current = _uiState.value as? DelegationKeysUiState.Content ?: return
        _uiState.value = current.copy(newSecret = null)
    }

    fun clearActionError() {
        val current = _uiState.value as? DelegationKeysUiState.Content ?: return
        _uiState.value = current.copy(actionError = null)
    }

    // ---- Create dialog ----

    fun openCreate() {
        _createForm.value = CreateDelegationKeyForm(visible = true)
        viewModelScope.launch {
            when (val result = repo.listManagedCreators()) {
                is ApiResult.Success -> _createForm.update { it.copy(creators = result.data) }
                is ApiResult.Failure -> _createForm.update { it.copy(submitError = result.error.message) }
                is ApiResult.NetworkError -> _createForm.update { it.copy(submitError = OFFLINE_FALLBACK) }
            }
        }
    }

    fun dismissCreate() {
        _createForm.value = CreateDelegationKeyForm(visible = false)
    }

    fun onLabelChange(value: String) =
        _createForm.update { it.copy(label = value, submitError = null) }

    fun onCreatorChange(creatorId: String) =
        _createForm.update { form ->
            // Drop any selected permissions no longer allowed by the newly-selected creator.
            val allowed = form.creators.firstOrNull { it.creatorId == creatorId }?.permissions?.toSet().orEmpty()
            form.copy(creatorId = creatorId, permissions = form.permissions.intersect(allowed), submitError = null)
        }

    fun onTogglePermission(permission: String, enabled: Boolean) =
        _createForm.update {
            val next = if (enabled) it.permissions + permission else it.permissions - permission
            it.copy(permissions = next, submitError = null)
        }

    fun submitCreate() {
        val form = _createForm.value
        if (!form.canSubmit) return
        _createForm.update { it.copy(submitting = true, submitError = null) }
        viewModelScope.launch {
            val result = repo.createKey(
                label = form.label.trim(),
                creatorId = form.creatorId,
                permissions = form.permissions.toList(),
                expiresInDays = null,
            )
            when (result) {
                is ApiResult.Success -> {
                    _createForm.value = CreateDelegationKeyForm(visible = false)
                    // Write-through the new (secret-less) row at the head of My Keys + surface the one-time secret.
                    val content = _uiState.value as? DelegationKeysUiState.Content
                    val row = result.data.key
                    if (content != null) {
                        _uiState.value = content.copy(
                            myKeys = listOf(row) + content.myKeys.filterNot { it.keyId == row.keyId },
                            tab = DelegationKeysTab.MINE,
                            newSecret = result.data.secret,
                        )
                    }
                    refresh()
                }
                is ApiResult.Failure ->
                    _createForm.update { it.copy(submitting = false, submitError = result.error.message) }
                is ApiResult.NetworkError ->
                    _createForm.update { it.copy(submitting = false, submitError = OFFLINE_FALLBACK) }
            }
        }
    }

    private companion object {
        const val OFFLINE_FALLBACK = "Couldn't reach the server. Pull down to retry."
    }
}
