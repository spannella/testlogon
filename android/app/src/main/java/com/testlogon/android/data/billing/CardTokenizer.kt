package com.testlogon.android.data.billing

import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-225 — Stripe Android SDK integration seam (SCAFFOLD ONLY — FLAGGED, payments not configured).
 *
 * STOP-AND-FLAG (Stripe is a HUMAN-DECISION vendor SDK): the Stripe Android SDK dependency is
 * deliberately NOT added (gradle/libs.versions.toml untouched) and NO real card tokenization /
 * PaymentSheet / SetupIntent confirm is performed. This mirrors the existing [BillingAuthorizer]
 * payment-stub pattern (and the KYC/WebRTC scaffold+flag approach): the seam stops at "would need the
 * Stripe SDK".
 *
 * [CardTokenizer] is the contract the real Stripe-backed implementation (a future ticket) will
 * satisfy: present Stripe's PaymentSheet in setup mode against a backend SetupIntent client_secret
 * (POST ui/billing/setup-intent/card), tokenize the card on-device, and confirm — so the app never
 * touches raw PAN/CVC. Until then [StubCardTokenizer] is bound, and it ALWAYS returns
 * [CardEntryResult.NotConfigured]: it NEVER tokenizes a card, NEVER calls setup-intent confirm, and
 * NEVER fakes a charge. The add-card UI surfaces a clear "card entry unavailable / payments not
 * configured" state.
 */
sealed interface CardEntryResult {

    /** A card was tokenized + the SetupIntent confirmed; carries the opaque saved-method id. */
    data class Saved(val paymentMethodId: String) : CardEntryResult

    /** User dismissed the card-entry sheet (no error surfaced). */
    data object Cancelled : CardEntryResult

    /** The processor declined the card / SetupIntent failed. */
    data class Failed(val message: String) : CardEntryResult

    /**
     * No real card-entry provider is wired (Stripe SDK FLAGGED, not integrated). The add-card flow
     * MUST surface a "payments not configured" state and MUST NOT tokenize a card or confirm a
     * SetupIntent. [StubCardTokenizer] always returns this.
     */
    data object NotConfigured : CardEntryResult
}

/**
 * AND-225/226 — collects a card via the vendor SDK's hosted UI and returns a saved-method result.
 *
 * The real implementation owns the Stripe PaymentSheet (setup mode) lifecycle; this app-side contract
 * stays free of Stripe types so feature/ViewModel code never depends on the SDK. No raw card fields
 * cross this boundary — collection is delegated entirely to the SDK.
 */
interface CardTokenizer {

    /**
     * Presents card entry to save a card for future use. Returns [CardEntryResult]. The [Stub]
     * implementation returns [CardEntryResult.NotConfigured] without any network or tokenization.
     */
    suspend fun addCard(): CardEntryResult
}

/**
 * AND-225/226 — default (FLAGGED) tokenizer. NEVER tokenizes a card, NEVER calls setup-intent confirm,
 * NEVER fakes a charge: always returns [CardEntryResult.NotConfigured] so the add-card UI shows a
 * clear "card entry unavailable / payments not configured" state. The real Stripe-backed binding
 * replaces this @Binds when the Stripe SDK decision is made.
 */
@Singleton
class StubCardTokenizer @Inject constructor() : CardTokenizer {
    override suspend fun addCard(): CardEntryResult = CardEntryResult.NotConfigured
}
