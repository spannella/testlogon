package com.testlogon.android.data.payouts

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-259 — identity-verification (KYC) seam (SCAFFOLD ONLY — FLAGGED, KYC vendor SDK not configured).
 *
 * STOP-AND-FLAG (KYC is a HUMAN-DECISION vendor SDK): the document-capture / liveness / ID-scan launch
 * requires a vendor SDK (Stripe Identity / Persona / Onfido). That dependency is deliberately NOT added
 * (gradle/libs.versions.toml untouched) and NO real verification flow is launched. This mirrors the
 * existing [com.testlogon.android.data.messaging.BillingAuthorizer] and
 * [com.testlogon.android.data.billing.CardTokenizer] stub-seam pattern: the seam stops at "would need
 * the KYC SDK".
 *
 * [KycVerifier] is the contract the real vendor-backed implementation (a future ticket) will satisfy:
 * present the vendor's hosted identity flow, then return whether verification was submitted. Until then
 * [StubKycVerifier] is bound and ALWAYS returns [KycVerificationResult.NotConfigured]: it NEVER launches
 * a real flow, NEVER tokenizes identity documents, and NEVER fakes a verified state. The payout-setup
 * gate surfaces a clear "identity verification required / unavailable" panel; the real tier status is
 * still read from the backend KYC tier endpoints ([KycApi]) independently of this seam.
 *
 * The backend KYC capture endpoints DO exist (ui/kyc/documents, ui/kyc/id-scanner, ui/kyc/liveness-call)
 * but driving them is a multi-step capture flow owned by E42 (AND-321/AND-322) and still needs a vendor
 * SDK for on-device capture/liveness — hence the scaffold+flag here rather than a partial real flow.
 */
sealed interface KycVerificationResult {

    /** The vendor flow completed and evidence was submitted; the caller should re-evaluate the tier. */
    data object Submitted : KycVerificationResult

    /** The user dismissed the verification flow (no error surfaced). */
    data object Cancelled : KycVerificationResult

    /** The vendor flow failed (network / vendor error). */
    data class Failed(val message: String) : KycVerificationResult

    /**
     * No real KYC provider is wired (vendor SDK FLAGGED, not integrated). The gate MUST surface an
     * "identity verification unavailable" state and MUST NOT launch a real flow or fake a verified
     * state. [StubKycVerifier] always returns this.
     */
    data object NotConfigured : KycVerificationResult
}

/**
 * AND-259 — launches the vendor identity-verification flow and returns a [KycVerificationResult]. The
 * real implementation owns the vendor SDK lifecycle; this app-side contract stays free of SDK types so
 * feature/ViewModel code never depends on the SDK. No raw identity documents cross this boundary.
 */
interface KycVerifier {

    /**
     * Presents identity verification. Returns a [KycVerificationResult]. The [StubKycVerifier]
     * implementation returns [KycVerificationResult.NotConfigured] without launching anything.
     */
    suspend fun verifyIdentity(): KycVerificationResult
}

/**
 * AND-259 — default (FLAGGED) verifier. NEVER launches a real KYC flow, NEVER submits identity evidence,
 * NEVER fakes a verified state: always returns [KycVerificationResult.NotConfigured] so the gate shows a
 * clear "identity verification unavailable" state. The real vendor-backed binding replaces this @Binds
 * when the KYC SDK decision is made.
 */
@Singleton
class StubKycVerifier @Inject constructor() : KycVerifier {
    override suspend fun verifyIdentity(): KycVerificationResult = KycVerificationResult.NotConfigured
}
