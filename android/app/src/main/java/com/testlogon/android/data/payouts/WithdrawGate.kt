package com.testlogon.android.data.payouts

import com.testlogon.android.core.model.kyc.KycCaseStatus

/**
 * PAY-22 — the pure, unit-testable PRE-WITHDRAWAL gate decision (mirrors the backend PAY-C gate).
 *
 * A withdrawal is BLOCKED until BOTH:
 *   (a) the creator's KYC is APPROVED (resolved from the EXISTING kyc_cases flow — the same store the
 *       B6 admin review writes and the backend request_payout reads), AND
 *   (b) a CERTIFIED W-9 is on file (GET ui/payouts/tax-info).
 *
 * The backend enforces this too (403 `kyc_required` / `tax_info_required`); this client gate mirrors it
 * so the user is routed BEFORE attempting a withdraw. It FAILS CLOSED: an unresolved leg (either read
 * failed) -> [Unresolved] so the withdraw form is never enabled without a confirmed gate.
 */
sealed interface WithdrawGate {

    /** Still loading the gate legs. */
    data object Loading : WithdrawGate

    /** A gate leg could not be resolved (KYC/tax read failed) -> fail closed; retry offered. */
    data object Unresolved : WithdrawGate

    /** KYC is not APPROVED — route the user to the existing KYC flow. Carries the current status. */
    data class NeedsKyc(val kycStatus: KycCaseStatus) : WithdrawGate

    /** KYC is APPROVED but no certified W-9 is on file — show the W-9 collection form. */
    data class NeedsTaxInfo(val kycStatus: KycCaseStatus, val taxInfo: PayoutTaxInfo) : WithdrawGate

    /** Both requirements satisfied — the withdraw form is enabled. */
    data class Allowed(val taxInfo: PayoutTaxInfo) : WithdrawGate

    /** True only when both legs are satisfied. */
    val canWithdraw: Boolean get() = this is Allowed
    val kycSatisfied: Boolean get() = this is NeedsTaxInfo || this is Allowed
    val taxSatisfied: Boolean get() = this is Allowed
}

/**
 * The resolved inputs for the gate. [kycApproved] is true iff any owned KYC case is APPROVED;
 * [kycStatus] is the most-informative current status (for messaging); [taxInfo] is the masked W-9 view.
 */
data class WithdrawGateInputs(
    val kycApproved: Boolean,
    val kycStatus: KycCaseStatus,
    val taxInfo: PayoutTaxInfo,
)

object WithdrawGateEvaluator {
    fun evaluate(inputs: WithdrawGateInputs?): WithdrawGate = when {
        inputs == null -> WithdrawGate.Unresolved
        !inputs.kycApproved -> WithdrawGate.NeedsKyc(inputs.kycStatus)
        !inputs.taxInfo.satisfiesGate -> WithdrawGate.NeedsTaxInfo(inputs.kycStatus, inputs.taxInfo)
        else -> WithdrawGate.Allowed(inputs.taxInfo)
    }
}
