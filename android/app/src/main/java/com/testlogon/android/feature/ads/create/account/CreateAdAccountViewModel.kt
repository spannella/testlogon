package com.testlogon.android.feature.ads.create.account

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.AdAccountRef
import com.testlogon.android.feature.ads.create.data.AdsCreateRepository
import com.testlogon.android.feature.ads.create.data.AdsStudioSelection
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ADV-107 - presentation logic for the CREATE-AD-ACCOUNT screen (company_name + billing_email -> POST
 * ui/ads/accounts). The account is created in pending_review status (admin approves before deposit/serving),
 * so on success the screen shows the pending state + a CTA to continue to campaign creation.
 *
 * [submitState] is separate from the form fields so an in-flight / success / error never clobbers the typed
 * input. Create is NON-idempotent: while [SubmitState.Submitting] a second [submit] is IGNORED (no
 * double-submit) and there is NO auto-retry. A 422 validation failure surfaces the server message.
 */
@HiltViewModel
class CreateAdAccountViewModel @Inject constructor(
    private val repository: AdsCreateRepository,
    private val selection: AdsStudioSelection,
) : ViewModel() {

    sealed interface SubmitState {
        data object Idle : SubmitState
        data object Submitting : SubmitState
        data class Success(val account: AdAccountRef) : SubmitState
        data class Error(val message: String) : SubmitState
    }

    private val _companyName = MutableStateFlow("")
    val companyName: StateFlow<String> = _companyName.asStateFlow()

    private val _billingEmail = MutableStateFlow("")
    val billingEmail: StateFlow<String> = _billingEmail.asStateFlow()

    private val _submitState = MutableStateFlow<SubmitState>(SubmitState.Idle)
    val submitState: StateFlow<SubmitState> = _submitState.asStateFlow()

    fun onCompanyName(text: String) {
        _companyName.value = text
        clearError()
    }

    fun onBillingEmail(text: String) {
        _billingEmail.value = text
        clearError()
    }

    /** True when both fields are non-blank and the email is minimally well-formed. */
    val canSubmit: Boolean
        get() = _companyName.value.isNotBlank() && isEmail(_billingEmail.value)

    /**
     * Submits the create. Ignored when invalid OR already in flight (no double-submit). On success:
     * [SubmitState.Success] + records the new account as the studio selection. On failure:
     * [SubmitState.Error] with a friendly message. NON-idempotent -> NO retry.
     */
    fun submit() {
        if (_submitState.value is SubmitState.Submitting) return
        val company = _companyName.value.trim()
        val email = _billingEmail.value.trim()
        if (company.isBlank() || !isEmail(email)) return

        _submitState.value = SubmitState.Submitting
        viewModelScope.launch {
            when (val result = repository.createAccount(company, email)) {
                is ApiResult.Success -> {
                    selection.selectAccount(result.data.accountId)
                    _submitState.value = SubmitState.Success(result.data)
                }
                is ApiResult.Failure -> _submitState.value = SubmitState.Error(friendly(result.error))
                is ApiResult.NetworkError -> _submitState.value = SubmitState.Error(OFFLINE)
            }
        }
    }

    private fun clearError() {
        if (_submitState.value is SubmitState.Error) _submitState.value = SubmitState.Idle
    }

    private fun friendly(error: ApiError): String = when (error.status) {
        HTTP_UNPROCESSABLE -> error.message.ifBlank { "Please check the details and try again." }
        else -> error.message
    }

    private companion object {
        const val HTTP_UNPROCESSABLE = 422
        const val OFFLINE = "Couldn't reach the server. Try again."

        fun isEmail(s: String): Boolean {
            val t = s.trim()
            val at = t.indexOf('@')
            return at > 0 && t.indexOf('.', at) > at + 1 && !t.endsWith(".")
        }
    }
}
