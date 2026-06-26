package com.testlogon.android.feature.kyc.wizard

// Batch-9 (#18) - UI state + step model for the guided KYC verification wizard.
//
// The wizard turns the previously confusing, fragmented KYC flow into a single clear step-by-step:
//   1. EMAIL verification   (send code -> enter code -> confirmed)
//   2. PHONE verification   (send code -> enter code -> confirmed)
//   3. ID front + back       (create a case, then hand off to the proven ID-scanner flow)
//   4. DONE                  (overall status + what was completed)
// A progress header is always visible so the user can see where they are and what is next.

/** The four top-level steps of the wizard, in order. */
enum class KycStep {
    EMAIL,
    PHONE,
    ID,
    DONE,
    ;

    /** 1-based position for the "Step N of M" progress label. */
    val position: Int get() = ordinal + 1

    companion object {
        /** Total steps shown in the progress header. */
        const val TOTAL = 4
    }
}

/** Per-channel (email/phone) verification sub-state inside steps 1 and 2. */
enum class VerifyPhase {
    /** Nothing sent yet; the user enters/confirms the target then asks for a code. */
    IDLE,

    /** A start request is in flight. */
    SENDING,

    /** A code was sent; the user enters it (the dev code is prefilled when the server returns one). */
    CODE_SENT,

    /** A confirm request is in flight. */
    CONFIRMING,

    /** This channel is verified. */
    VERIFIED,
}

/** State for one verify channel (email or phone). */
data class ChannelState(
    val phase: VerifyPhase = VerifyPhase.IDLE,
    /** The email address / phone number the user is verifying. */
    val target: String = "",
    /** The code the user has typed (prefilled from dev_code when the server returns one). */
    val code: String = "",
    /** A human hint about where the code was sent (server `target`, e.g. a masked address). */
    val sentTo: String? = null,
    /** Inline error for this channel (cleared on the next action). */
    val error: String? = null,
) {
    val verified: Boolean get() = phase == VerifyPhase.VERIFIED
    val busy: Boolean get() = phase == VerifyPhase.SENDING || phase == VerifyPhase.CONFIRMING
}

/** State for the ID step. The actual capture/scan runs in the proven ID-scanner screen we navigate to. */
data class IdStepState(
    /** True while the KYC case is being created (needed before the ID-scanner can run). */
    val creatingCase: Boolean = false,
    /** The created case id (set once the case exists). */
    val caseId: String? = null,
    /** True once the user has returned from the ID-scanner having uploaded both sides. */
    val submitted: Boolean = false,
    val error: String? = null,
)

/**
 * The single immutable UI state for the wizard. [loading] covers the initial tier-status fetch (so we can
 * skip already-met steps); [fatalError] replaces the whole surface only for an unrecoverable load failure.
 */
data class KycWizardUiState(
    val loading: Boolean = true,
    val fatalError: String? = null,
    val step: KycStep = KycStep.EMAIL,
    val email: ChannelState = ChannelState(),
    val phone: ChannelState = ChannelState(),
    val id: IdStepState = IdStepState(),
    /** Server-reported flags so we can mark already-completed steps done on entry. */
    val emailAlreadyVerified: Boolean = false,
    val phoneAlreadyVerified: Boolean = false,
    val idAlreadyDone: Boolean = false,
) {
    val emailDone: Boolean get() = email.verified || emailAlreadyVerified
    val phoneDone: Boolean get() = phone.verified || phoneAlreadyVerified
    val idDone: Boolean get() = id.submitted || idAlreadyDone

    /** How many of the 3 actionable steps are complete (drives the progress bar fraction). */
    val completedCount: Int get() = listOf(emailDone, phoneDone, idDone).count { it }
}
