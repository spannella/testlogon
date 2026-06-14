package com.testlogon.android.feature.donation

import com.testlogon.android.feature.donation.model.DonationReceipt
import com.testlogon.android.feature.donation.model.Fundraiser

/**
 * AND-393 - UI contract for the session-free DonationScreen.
 *
 * A single immutable [DonationUiState] is exposed as a StateFlow. [phase] drives which surface renders:
 * the loading skeleton, the donation form, the unavailable terminal (closed / not-found fundraiser), the
 * confirmation receipt, or a retryable load error. Form input (amount/email/name) is held here and
 * survives configuration changes via SavedStateHandle in the ViewModel.
 *
 * VALIDATION (§6/AC-3/AC-4): submit is gated on a valid amount and NO field errors; the donor email is
 * OPTIONAL (a blank email never blocks submit; a malformed email, when entered, does). The min/max amount
 * bounds are the verified GroupDonateIn bounds (100 .. 10000000 cents).
 */
data class DonationUiState(
    val fundraiserId: String,
    val phase: Phase = Phase.LoadingFundraiser,
    val fundraiser: Fundraiser? = null,
    val amountInput: String = "",
    val amountCents: Long? = null,
    val donorEmail: String = "",
    val donorName: String = "",
    val fieldErrors: Map<DonationField, String> = emptyMap(),
    val isSubmitting: Boolean = false,
    val transientError: String? = null,
    val receipt: DonationReceipt? = null,
) {
    /** Valid iff the amount parsed to a legal value and there are no outstanding field errors. */
    val isFormValid: Boolean
        get() = amountCents != null && fieldErrors.isEmpty()

    /** Submit is enabled only on a valid form, while not already submitting, in the Form phase. */
    val canSubmit: Boolean
        get() = isFormValid && !isSubmitting && phase == Phase.Form
}

/** The mutually-exclusive surfaces of the donation screen. */
enum class Phase {
    LoadingFundraiser,
    Form,
    Unavailable,
    Submitting,
    Confirmed,
    LoadError,
}

/** The form fields that can carry an inline validation error. */
enum class DonationField {
    Amount,
    Email,
    Name,
}
