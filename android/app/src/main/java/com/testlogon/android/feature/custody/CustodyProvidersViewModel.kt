package com.testlogon.android.feature.custody

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyProvider
import com.testlogon.android.data.custody.CustodyProviders
import com.testlogon.android.data.custody.CustodyRepository
import com.testlogon.android.data.custody.CustodyVaults
import com.testlogon.android.data.custody.ProviderStatusDetail
import com.testlogon.android.data.custody.WithdrawalApproval
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Per-provider live status slice (lazily probed when a card is expanded). Keyed by provider id in
 * [ProvidersUiState.statuses].
 */
data class ProviderStatusUi(
    val loading: Boolean = false,
    val error: String? = null,
    val data: ProviderStatusDetail? = null,
)

/** The withdrawal-approval lookup form + polled result on the Providers screen. */
data class ApprovalLookupUiState(
    val withdrawalId: String = "",
    val loading: Boolean = false,
    val error: String? = null,
    val data: WithdrawalApproval? = null,
)

data class ProvidersUiState(
    val providers: Async<CustodyProviders> = Async(loading = true),
    val vaults: Async<CustodyVaults> = Async(loading = true),
    /** Per-provider expanded status probes, keyed by provider id. */
    val statuses: Map<String, ProviderStatusUi> = emptyMap(),
    /** In-flight connect/disconnect action, keyed by provider id. */
    val actionInFlight: Set<String> = emptySet(),
    /** Last action error, keyed by provider id. */
    val actionErrors: Map<String, String> = emptyMap(),
    /** In-flight per-vault provider change, keyed by vault id. */
    val vaultChangeInFlight: Set<String> = emptySet(),
    val vaultChangeErrors: Map<String, String> = emptyMap(),
    val approval: ApprovalLookupUiState = ApprovalLookupUiState(),
) {
    val providerList: List<CustodyProvider> get() = providers.data?.providers.orEmpty()
}

/**
 * ViewModel for the EXTERNAL custody provider screen (Fireblocks / BitGo / internal gateway). Reads
 * degrade to a soft "pending backend" state on 404; connect/disconnect + per-vault provider change are
 * mutations whose failures surface a clear message. Provider secrets are never handled here -- the
 * screen only initiates the server-side connection and shows status.
 */
@HiltViewModel
class CustodyProvidersViewModel @Inject constructor(
    private val repo: CustodyRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ProvidersUiState())
    val uiState: StateFlow<ProvidersUiState> = _uiState.asStateFlow()

    init {
        loadProviders()
        loadVaults()
    }

    fun loadProviders() {
        _uiState.update { it.copy(providers = it.providers.copy(loading = true, error = null)) }
        viewModelScope.launch {
            _uiState.update { st -> st.copy(providers = repo.getProviders().toAsync()) }
        }
    }

    fun loadVaults() {
        _uiState.update { it.copy(vaults = it.vaults.copy(loading = true, error = null)) }
        viewModelScope.launch {
            _uiState.update { st -> st.copy(vaults = repo.getVaults().toAsync()) }
        }
    }

    /** Lazily probe a provider's live status (health/attestation/reconciliation/pending approvals). */
    fun loadProviderStatus(id: String) {
        if (id.isBlank()) return
        _uiState.update { st ->
            st.copy(statuses = st.statuses + (id to (st.statuses[id] ?: ProviderStatusUi()).copy(loading = true, error = null)))
        }
        viewModelScope.launch {
            val ui = when (val r = repo.getProviderStatus(id)) {
                is ApiResult.Success -> ProviderStatusUi(loading = false, data = r.data)
                is ApiResult.Failure -> ProviderStatusUi(loading = false, error = r.error.messageFor())
                is ApiResult.NetworkError -> ProviderStatusUi(loading = false, error = "Network error. Check your connection and try again.")
            }
            _uiState.update { st -> st.copy(statuses = st.statuses + (id to ui)) }
        }
    }

    fun connect(id: String, label: String?) {
        if (id.isBlank() || id in _uiState.value.actionInFlight) return
        setActionInFlight(id, true)
        viewModelScope.launch {
            when (val r = repo.connectProvider(id, label)) {
                is ApiResult.Success -> {
                    setActionInFlight(id, false)
                    loadProviders()
                    loadProviderStatus(id)
                }
                is ApiResult.Failure -> finishActionWithError(id, r.error.messageFor())
                is ApiResult.NetworkError -> finishActionWithError(id, "Network error. Check your connection and try again.")
            }
        }
    }

    fun disconnect(id: String) {
        if (id.isBlank() || id in _uiState.value.actionInFlight) return
        setActionInFlight(id, true)
        viewModelScope.launch {
            when (val r = repo.disconnectProvider(id)) {
                is ApiResult.Success -> {
                    setActionInFlight(id, false)
                    loadProviders()
                }
                is ApiResult.Failure -> finishActionWithError(id, r.error.messageFor())
                is ApiResult.NetworkError -> finishActionWithError(id, "Network error. Check your connection and try again.")
            }
        }
    }

    private fun setActionInFlight(id: String, inFlight: Boolean) {
        _uiState.update { st ->
            st.copy(
                actionInFlight = if (inFlight) st.actionInFlight + id else st.actionInFlight - id,
                actionErrors = st.actionErrors - id,
            )
        }
    }

    private fun finishActionWithError(id: String, msg: String) {
        _uiState.update { st ->
            st.copy(
                actionInFlight = st.actionInFlight - id,
                actionErrors = st.actionErrors + (id to msg),
            )
        }
    }

    /** Set a vault's backing provider (PUT). Refreshes the vaults list on success. */
    fun setVaultProvider(vault: String, provider: String) {
        if (vault.isBlank() || vault in _uiState.value.vaultChangeInFlight) return
        _uiState.update { st ->
            st.copy(
                vaultChangeInFlight = st.vaultChangeInFlight + vault,
                vaultChangeErrors = st.vaultChangeErrors - vault,
            )
        }
        viewModelScope.launch {
            when (val r = repo.setVaultProvider(vault, provider)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(vaultChangeInFlight = it.vaultChangeInFlight - vault) }
                    loadVaults()
                }
                is ApiResult.Failure -> finishVaultChangeWithError(vault, r.error.messageFor())
                is ApiResult.NetworkError -> finishVaultChangeWithError(vault, "Network error. Check your connection and try again.")
            }
        }
    }

    private fun finishVaultChangeWithError(vault: String, msg: String) {
        _uiState.update { st ->
            st.copy(
                vaultChangeInFlight = st.vaultChangeInFlight - vault,
                vaultChangeErrors = st.vaultChangeErrors + (vault to msg),
            )
        }
    }

    // ---- withdrawal approval lookup ----

    fun onApprovalIdChanged(v: String) {
        _uiState.update { it.copy(approval = it.approval.copy(withdrawalId = v.trim(), error = null)) }
    }

    fun lookupApproval() {
        val id = _uiState.value.approval.withdrawalId.trim()
        if (id.isEmpty()) {
            _uiState.update { it.copy(approval = it.approval.copy(error = "Enter a withdrawal id.")) }
            return
        }
        _uiState.update { it.copy(approval = it.approval.copy(loading = true, error = null)) }
        viewModelScope.launch {
            when (val r = repo.getWithdrawalApproval(id)) {
                is ApiResult.Success -> _uiState.update { it.copy(approval = it.approval.copy(loading = false, data = r.data)) }
                is ApiResult.Failure -> _uiState.update { it.copy(approval = it.approval.copy(loading = false, error = r.error.messageFor())) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(approval = it.approval.copy(loading = false, error = "Network error. Check your connection and try again.")) }
            }
        }
    }
}

private fun <T> ApiResult<T>.toAsync(): Async<T> = when (this) {
    is ApiResult.Success -> Async(loading = false, error = null, data = data)
    is ApiResult.Failure -> Async(loading = false, error = error.messageFor())
    is ApiResult.NetworkError -> Async(loading = false, error = "Network error. Check your connection and try again.")
}

private fun ApiError.messageFor(): String = when (status) {
    403 -> "You do not have access to this."
    else -> message
}
