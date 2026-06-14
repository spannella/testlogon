package com.testlogon.android.feature.donation

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.donation.data.DonationRepository
import com.testlogon.android.feature.donation.model.DonationRequest
import com.testlogon.android.feature.donation.model.Fundraiser
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject

/**
 * AND-393 - presentation logic for the session-free DonationScreen.
 *
 * The fundraiser id comes from the route ([SavedStateHandle]). On init the fundraiser is loaded via the
 * COOKIELESS [DonationRepository] (anonymous-capable, AC-2); a successful load with `status == active`
 * yields [Phase.Form], a closed/unknown status yields [Phase.Unavailable], a not-found yields
 * [Phase.Unavailable], and a transient failure yields [Phase.LoadError] with a working Retry.
 *
 * Amount and (optional) email are validated locally ([onAmountChanged]/[onEmailChanged]); submit is
 * gated by [DonationUiState.canSubmit]. [submit] posts the donation (NOT auto-retried; double-submit is
 * blocked by [DonationUiState.isSubmitting]) and reaches [Phase.Confirmed] via the repository's
 * soft-fallback even when the receipt GET fails. A best-effort idempotency key is generated ONCE per
 * form-fill and stashed in SavedStateHandle so a user-initiated retry reuses it (AC-6).
 *
 * NO poll loop; plain MutableStateFlow; donor PII is held only in memory + SavedStateHandle (§8).
 */
@HiltViewModel
class DonationViewModel @Inject constructor(
    private val repository: DonationRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val fundraiserId: String = savedState.get<String>(ARG_FUNDRAISER_ID).orEmpty()

    private val _uiState = MutableStateFlow(DonationUiState(fundraiserId = fundraiserId))
    val uiState: StateFlow<DonationUiState> = _uiState.asStateFlow()

    /** Best-effort idempotency key, stable across config changes and user-initiated retries (AC-6). */
    private val idempotencyKey: String
        get() = savedState.get<String>(KEY_IDEMPOTENCY) ?: UUID.randomUUID().toString().also {
            savedState[KEY_IDEMPOTENCY] = it
        }

    init {
        if (fundraiserId.isBlank()) {
            _uiState.update { it.copy(phase = Phase.Unavailable) }
        } else {
            loadFundraiser()
        }
    }

    /** Load (or re-load on Retry) the fundraiser summary. */
    fun loadFundraiser() {
        if (fundraiserId.isBlank()) return
        _uiState.update { it.copy(phase = Phase.LoadingFundraiser, transientError = null) }
        viewModelScope.launch {
            when (val result = repository.getFundraiser(fundraiserId)) {
                is ApiResult.Success -> applyFundraiser(result.data)
                is ApiResult.Failure ->
                    // No documented 404 body on this route; a server error that is not retryable (4xx)
                    // is treated as an unavailable fundraiser, a 5xx as a retryable load error (§7).
                    _uiState.update {
                        it.copy(
                            phase = if (result.error.status in 500..599) {
                                Phase.LoadError
                            } else {
                                Phase.Unavailable
                            },
                            transientError = result.error.message.takeIf { _ ->
                                result.error.status in 500..599
                            },
                        )
                    }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(phase = Phase.LoadError, transientError = OFFLINE) }
            }
        }
    }

    /** Routes a loaded fundraiser to the Form (open) or Unavailable (closed/unknown status) phase. */
    private fun applyFundraiser(fundraiser: Fundraiser) {
        _uiState.update {
            it.copy(
                fundraiser = fundraiser,
                phase = if (fundraiser.status.isOpen) Phase.Form else Phase.Unavailable,
            )
        }
    }

    /** Apply a preset amount (in cents) from a chip. */
    fun onPresetSelected(amountCents: Long) {
        onAmountChanged(formatCentsAsInput(amountCents))
    }

    /** Validate and apply the typed amount (parsed to integer cents). */
    fun onAmountChanged(raw: String) {
        val cents = parseAmountCents(raw)
        val error = validateAmount(raw, cents)
        _uiState.update {
            it.copy(
                amountInput = raw,
                amountCents = cents.takeIf { _ -> error == null },
                fieldErrors = it.fieldErrors.withFieldError(DonationField.Amount, error),
            )
        }
    }

    /** Validate and apply the typed email (OPTIONAL; blank never blocks, malformed does). */
    fun onEmailChanged(value: String) {
        val error = validateEmail(value)
        _uiState.update {
            it.copy(
                donorEmail = value,
                fieldErrors = it.fieldErrors.withFieldError(DonationField.Email, error),
            )
        }
    }

    /** Apply the typed donor name (OPTIONAL; only a length cap, never required). */
    fun onNameChanged(value: String) {
        val error = if (value.length > MAX_NAME_LEN) ERR_NAME_TOO_LONG else null
        _uiState.update {
            it.copy(
                donorName = value,
                fieldErrors = it.fieldErrors.withFieldError(DonationField.Name, error),
            )
        }
    }

    /** Submit the donation. Double-submit guarded; NOT auto-retried; reaches Confirmed via soft-fallback. */
    fun submit() {
        val state = _uiState.value
        val amount = state.amountCents
        if (!state.canSubmit || amount == null) return
        val fundraiser = state.fundraiser
        _uiState.update { it.copy(phase = Phase.Submitting, isSubmitting = true, transientError = null) }
        // Touch the idempotency key so it is generated/persisted once per form-fill (best-effort, AC-6).
        val key = idempotencyKey
        check(key.isNotBlank())
        viewModelScope.launch {
            val result = repository.donate(
                fundraiserId = fundraiserId,
                request = DonationRequest(
                    amountCents = amount,
                    donorName = state.donorName.takeIf { it.isNotBlank() },
                    donorEmail = state.donorEmail.takeIf { it.isNotBlank() },
                ),
                currency = fundraiser?.currency ?: DEFAULT_CURRENCY,
                groupName = fundraiser?.groupName,
                fundraiserTitle = fundraiser?.title,
            )
            when (result) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(phase = Phase.Confirmed, isSubmitting = false, receipt = result.data)
                    }
                is ApiResult.Failure -> {
                    // Map a 422 back to the offending field; otherwise surface a transient error and stay
                    // on the form so the user can retry (NOT auto-retried).
                    val amountErr = repository.fieldError(result.error, WIRE_AMOUNT)
                    val emailErr = repository.fieldError(result.error, WIRE_EMAIL)
                    val nameErr = repository.fieldError(result.error, WIRE_NAME)
                    val mapped = listOfNotNull(
                        amountErr?.let { DonationField.Amount to it },
                        emailErr?.let { DonationField.Email to it },
                        nameErr?.let { DonationField.Name to it },
                    ).toMap()
                    _uiState.update {
                        it.copy(
                            phase = Phase.Form,
                            isSubmitting = false,
                            fieldErrors = it.fieldErrors + mapped,
                            transientError = if (mapped.isEmpty()) result.error.message else null,
                        )
                    }
                }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(phase = Phase.Form, isSubmitting = false, transientError = OFFLINE)
                    }
            }
        }
    }

    /** Clear the transient (non-field) error banner. */
    fun consumeError() {
        _uiState.update { it.copy(transientError = null) }
    }

    // ---- Validation helpers (distinct names; never shadow an interface method) ----

    private fun validateAmount(raw: String, cents: Long?): String? = when {
        raw.isBlank() -> ERR_AMOUNT_REQUIRED
        cents == null -> ERR_AMOUNT_INVALID
        cents < MIN_AMOUNT_CENTS -> ERR_AMOUNT_TOO_LOW
        cents > MAX_AMOUNT_CENTS -> ERR_AMOUNT_TOO_HIGH
        else -> null
    }

    private fun validateEmail(value: String): String? = when {
        value.isBlank() -> null // OPTIONAL: blank never blocks (AC-4).
        value.length > MAX_EMAIL_LEN -> ERR_EMAIL_TOO_LONG
        !EMAIL_REGEX.matches(value) -> ERR_EMAIL_INVALID
        else -> null
    }

    /** Parses a major-unit decimal string ("25" / "25.00" / "25.5") to integer cents, or null. */
    private fun parseAmountCents(raw: String): Long? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        if (!AMOUNT_REGEX.matches(trimmed)) return null
        val parts = trimmed.split(".")
        val whole = parts[0].ifEmpty { "0" }.toLongOrNull() ?: return null
        val fraction = parts.getOrNull(1).orEmpty().padEnd(2, '0').take(2)
        val cents = fraction.toLongOrNull() ?: return null
        return whole * 100 + cents
    }

    /** Formats integer cents back to a plain major-unit input string (no currency symbol). */
    private fun formatCentsAsInput(cents: Long): String {
        val whole = cents / 100
        val frac = (cents % 100).toInt()
        return if (frac == 0) whole.toString() else "%d.%02d".format(whole, frac)
    }

    /** Adds or removes a field error, keeping the map minimal so [isFormValid] is reliable. */
    private fun Map<DonationField, String>.withFieldError(
        field: DonationField,
        error: String?,
    ): Map<DonationField, String> =
        if (error == null) this - field else this + (field to error)

    companion object {
        /** Nav arg carrying the fundraiser id (from the deep link / route). */
        const val ARG_FUNDRAISER_ID = "fundraiserId"

        private const val KEY_IDEMPOTENCY = "donation_idempotency_key"

        const val MIN_AMOUNT_CENTS = 100L
        const val MAX_AMOUNT_CENTS = 10_000_000L
        private const val MAX_EMAIL_LEN = 254
        private const val MAX_NAME_LEN = 100
        private const val DEFAULT_CURRENCY = "usd"

        // Wire field names for 422 loc-tail mapping (must match GroupDonateIn keys).
        private const val WIRE_AMOUNT = "amount_cents"
        private const val WIRE_EMAIL = "donor_email"
        private const val WIRE_NAME = "donor_name"

        private const val ERR_AMOUNT_REQUIRED = "Enter a donation amount."
        private const val ERR_AMOUNT_INVALID = "Enter a valid amount."
        private const val ERR_AMOUNT_TOO_LOW = "The minimum donation is $1.00."
        private const val ERR_AMOUNT_TOO_HIGH = "That amount is too large."
        private const val ERR_EMAIL_INVALID = "Enter a valid email address."
        private const val ERR_EMAIL_TOO_LONG = "That email is too long."
        private const val ERR_NAME_TOO_LONG = "That name is too long."
        private const val OFFLINE = "Couldn't reach the server. Try again."

        // A decimal with up to two fraction digits (e.g. 25, 25.0, 25.50, .50).
        private val AMOUNT_REGEX = Regex("""^\d*(\.\d{1,2})?$""")
        private val EMAIL_REGEX = Regex("""^[^\s@]+@[^\s@]+\.[^\s@]+$""")
    }
}
