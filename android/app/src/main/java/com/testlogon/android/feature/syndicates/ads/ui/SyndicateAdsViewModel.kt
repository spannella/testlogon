package com.testlogon.android.feature.syndicates.ads.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import com.testlogon.android.feature.syndicates.ads.data.SyndicateAdsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV2-709/710/711 (F7) — presentation logic for the SYNDICATE-ADS hub. A syndicate admin lists the
 * syndicate's ad accounts, creates one (company_name + billing_email -> the syndicate-scoped create), and
 * sees the placement-split summary. Creating (or tapping) an account records it as the process
 * [AdsStudioSelection] so the REUSED create-campaign / create-creative / fund / analytics screens open
 * against the SYNDICATE account.
 *
 * All endpoints are admin-gated: a 403 flips the list to [SyndicateAdsAccountsState.Forbidden] (and hides
 * the config). [createState] is separate from the form fields so an in-flight/failed create never clobbers
 * the typed input. Create is NON-idempotent -> ignored while submitting, NO auto-retry.
 */
@HiltViewModel
class SyndicateAdsViewModel @Inject constructor(
    private val repository: SyndicateAdsRepository,
    private val selection: AdsStudioSelection,
    savedState: SavedStateHandle,
) : ViewModel() {

    val syndicateId: String =
        checkNotNull(savedState[ARG_SYNDICATE_ID]) { "missing $ARG_SYNDICATE_ID nav arg" }

    private val _accountsState =
        MutableStateFlow<SyndicateAdsAccountsState>(SyndicateAdsAccountsState.Loading)
    val accountsState: StateFlow<SyndicateAdsAccountsState> = _accountsState.asStateFlow()

    private val _configState = MutableStateFlow<SyndicateAdConfigState>(SyndicateAdConfigState.Loading)
    val configState: StateFlow<SyndicateAdConfigState> = _configState.asStateFlow()

    private val _companyName = MutableStateFlow("")
    val companyName: StateFlow<String> = _companyName.asStateFlow()

    private val _billingEmail = MutableStateFlow("")
    val billingEmail: StateFlow<String> = _billingEmail.asStateFlow()

    private val _createState = MutableStateFlow<SyndicateAdCreateState>(SyndicateAdCreateState.Idle)
    val createState: StateFlow<SyndicateAdCreateState> = _createState.asStateFlow()

    init {
        load()
    }

    /** Reloads the accounts list + the placement-split summary. Also refreshed on returning to the hub. */
    fun load() {
        loadAccounts()
        loadConfig()
    }

    fun loadAccounts() {
        _accountsState.value = SyndicateAdsAccountsState.Loading
        viewModelScope.launch {
            when (val r = repository.listAccounts(syndicateId)) {
                is ApiResult.Success -> _accountsState.value =
                    if (r.data.isEmpty()) SyndicateAdsAccountsState.Empty
                    else SyndicateAdsAccountsState.Content(r.data)
                is ApiResult.Failure ->
                    _accountsState.value =
                        if (r.error.status == HTTP_FORBIDDEN) SyndicateAdsAccountsState.Forbidden
                        else SyndicateAdsAccountsState.Error(r.error.message)
                is ApiResult.NetworkError ->
                    _accountsState.value = SyndicateAdsAccountsState.Error(OFFLINE)
            }
        }
    }

    private fun loadConfig() {
        _configState.value = SyndicateAdConfigState.Loading
        viewModelScope.launch {
            when (val r = repository.getPlacementConfig(syndicateId)) {
                is ApiResult.Success -> _configState.value = SyndicateAdConfigState.Content(r.data)
                is ApiResult.Failure, is ApiResult.NetworkError ->
                    _configState.value = SyndicateAdConfigState.Hidden
            }
        }
    }

    fun onCompanyName(text: String) { _companyName.value = text; clearCreateError() }
    fun onBillingEmail(text: String) { _billingEmail.value = text; clearCreateError() }

    /** True when the company name is present and the billing email is minimally well-formed. */
    val canCreate: Boolean
        get() = _companyName.value.isNotBlank() && isEmail(_billingEmail.value)

    /**
     * Creates the syndicate ad account. Ignored when invalid OR already in flight. On success: records the
     * new account as the studio selection (so the reused campaign/creative/fund screens target it) and
     * refreshes the list. NON-idempotent -> NO retry.
     */
    fun createAccount() {
        if (_createState.value is SyndicateAdCreateState.Submitting) return
        val company = _companyName.value.trim()
        val email = _billingEmail.value.trim()
        if (company.isBlank() || !isEmail(email)) return

        _createState.value = SyndicateAdCreateState.Submitting
        viewModelScope.launch {
            when (val r = repository.createAccount(syndicateId, company, email)) {
                is ApiResult.Success -> {
                    selection.selectAccount(r.data.accountId)
                    _createState.value = SyndicateAdCreateState.Success(r.data.accountId, r.data.status)
                    _companyName.value = ""
                    _billingEmail.value = ""
                    loadAccounts()
                }
                is ApiResult.Failure ->
                    _createState.value = SyndicateAdCreateState.Error(friendly(r.error))
                is ApiResult.NetworkError ->
                    _createState.value = SyndicateAdCreateState.Error(OFFLINE)
            }
        }
    }

    /** Records an existing account as the studio selection so the reused screens target it. */
    fun selectAccount(accountId: String) {
        selection.selectAccount(accountId)
    }

    fun consumeCreateSuccess() {
        if (_createState.value is SyndicateAdCreateState.Success) {
            _createState.value = SyndicateAdCreateState.Idle
        }
    }

    private fun clearCreateError() {
        if (_createState.value is SyndicateAdCreateState.Error) {
            _createState.value = SyndicateAdCreateState.Idle
        }
    }

    private fun friendly(error: ApiError): String = when (error.status) {
        HTTP_FORBIDDEN -> "Only a syndicate admin can manage its ads."
        HTTP_UNPROCESSABLE -> error.message.ifBlank { "Please check the details and try again." }
        else -> error.message
    }

    companion object {
        const val ARG_SYNDICATE_ID = "syndicateId"
        private const val HTTP_FORBIDDEN = 403
        private const val HTTP_UNPROCESSABLE = 422
        private const val OFFLINE = "Couldn't reach the server. Try again."

        fun isEmail(s: String): Boolean {
            val t = s.trim()
            val at = t.indexOf('@')
            return at > 0 && t.indexOf('.', at) > at + 1 && !t.endsWith(".")
        }
    }
}
