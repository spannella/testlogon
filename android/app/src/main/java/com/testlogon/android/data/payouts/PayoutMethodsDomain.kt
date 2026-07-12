package com.testlogon.android.data.payouts

/**
 * PAY-13 — framework-free domain models + DTO mappers for ROUTABLE payout methods.
 *
 * Honest under the mock: a method records a routable-shaped destination reference (bank token /
 * paypal email / connect_account_id) + a verification status — no real bank/Connect account is linked
 * until STRIPE_CONNECT_ENABLED / bank tokenization creds are keyed server-side (SEC-004 kept: only the
 * last-4 is ever displayed; the full number never reaches this layer).
 */

/** PAY-12 verification lifecycle. Unrecognized wire values fold to [UNKNOWN]. */
enum class PayoutMethodStatus {
    UNVERIFIED,
    VERIFYING,
    VERIFIED,
    FAILED,
    UNKNOWN,
    ;

    /** Only a VERIFIED method can be a payout destination (mirrors request_payout's server guard). */
    val isVerified: Boolean get() = this == VERIFIED

    companion object {
        fun from(raw: String?): PayoutMethodStatus = when (raw?.trim()?.lowercase()) {
            "unverified" -> UNVERIFIED
            "verifying" -> VERIFYING
            "verified" -> VERIFIED
            "failed" -> FAILED
            else -> UNKNOWN
        }
    }
}

/** The routable method type. [wire] is the server's `method_type` enum value. */
enum class RoutableMethodType(val wire: String) {
    BANK_ACH("bank_ach"),
    BANK_WIRE("bank_wire"),
    PAYPAL("paypal"),
    STRIPE_CONNECT("stripe_connect"),
    CHECK("check"),
    UNKNOWN(""),
    ;

    val isBank: Boolean get() = this == BANK_ACH || this == BANK_WIRE

    companion object {
        fun from(raw: String?): RoutableMethodType = when (raw?.trim()?.lowercase()) {
            "bank_ach" -> BANK_ACH
            "bank_wire" -> BANK_WIRE
            "paypal" -> PAYPAL
            "stripe_connect" -> STRIPE_CONNECT
            "check" -> CHECK
            else -> UNKNOWN
        }
    }
}

/** A routable payout method: a destination reference the PAY-D transfer targets + a verify status. */
data class PayoutMethod(
    val methodId: String,
    val type: RoutableMethodType,
    /** Raw wire `method_type` (retained for unknown values). */
    val rawType: String,
    val accountLast4: String,
    val routingLast4: String,
    val paypalEmail: String,
    val nickname: String,
    val isDefault: Boolean,
    val status: PayoutMethodStatus,
    val connectAccountId: String,
    /** The opaque routable destination reference (bank token / paypal:<email> / connect id). */
    val externalAccountRef: String,
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
) {
    /** True when the method exposes a routable destination the transfer can target. */
    val isRoutable: Boolean get() = externalAccountRef.isNotBlank()
}

/** PAY-11 — the creator's Stripe Connect account status. */
data class ConnectAccount(
    val connectAccountId: String,
    val onboardingStatus: String,
    val payoutsEnabled: Boolean,
) {
    val exists: Boolean get() = connectAccountId.isNotBlank()
}

/** PAY-11 — the result of requesting an onboarding link (real URL when keyed; mock self-completes). */
data class ConnectOnboarding(
    val connectAccountId: String,
    /** Non-empty only when real Stripe Connect is keyed; empty under the mock. */
    val onboardingUrl: String,
    val onboardingStatus: String,
    val payoutsEnabled: Boolean,
    val real: Boolean,
) {
    val needsBrowser: Boolean get() = onboardingUrl.isNotBlank()
}

/**
 * A validated add-method request. The bank variant carries the WRITE-ONLY full routing/account which is
 * tokenized server-side (SEC-004) — this app never stores or re-displays it after submit.
 */
sealed interface AddPayoutMethodInput {
    val nickname: String
    val setAsDefault: Boolean

    data class Bank(
        val routingNumber: String,
        val accountNumber: String,
        /** false -> bank_ach, true -> bank_wire. */
        val wire: Boolean = false,
        override val nickname: String = "",
        override val setAsDefault: Boolean = false,
    ) : AddPayoutMethodInput

    data class Paypal(
        val email: String,
        override val nickname: String = "",
        override val setAsDefault: Boolean = false,
    ) : AddPayoutMethodInput

    data class Connect(
        val connectAccountId: String,
        override val nickname: String = "",
        override val setAsDefault: Boolean = false,
    ) : AddPayoutMethodInput
}

// ---- Mappers ----

internal fun PayoutMethodOutDto.toDomain(): PayoutMethod = PayoutMethod(
    methodId = methodId,
    type = RoutableMethodType.from(methodType),
    rawType = methodType,
    accountLast4 = accountLast4,
    routingLast4 = routingLast4,
    paypalEmail = paypalEmail,
    nickname = nickname,
    isDefault = isDefault,
    status = PayoutMethodStatus.from(methodStatus),
    connectAccountId = connectAccountId,
    externalAccountRef = externalAccountRef,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
)

internal fun PayoutMethodListDto.toDomain(): List<PayoutMethod> = methods.map { it.toDomain() }

internal fun ConnectAccountDto.toDomain(): ConnectAccount = ConnectAccount(
    connectAccountId = connectAccountId,
    onboardingStatus = onboardingStatus,
    payoutsEnabled = payoutsEnabled,
)

internal fun ConnectOnboardingDto.toDomain(): ConnectOnboarding = ConnectOnboarding(
    connectAccountId = connectAccountId,
    onboardingUrl = onboardingUrl,
    onboardingStatus = onboardingStatus,
    payoutsEnabled = payoutsEnabled,
    real = real,
)

internal fun AddPayoutMethodInput.toDto(): PayoutMethodInDto = when (this) {
    is AddPayoutMethodInput.Bank -> PayoutMethodInDto(
        methodType = if (wire) RoutableMethodType.BANK_WIRE.wire else RoutableMethodType.BANK_ACH.wire,
        accountNumber = accountNumber,
        routingNumber = routingNumber,
        nickname = nickname,
        setAsDefault = setAsDefault,
    )
    is AddPayoutMethodInput.Paypal -> PayoutMethodInDto(
        methodType = RoutableMethodType.PAYPAL.wire,
        paypalEmail = email,
        nickname = nickname,
        setAsDefault = setAsDefault,
    )
    is AddPayoutMethodInput.Connect -> PayoutMethodInDto(
        methodType = RoutableMethodType.STRIPE_CONNECT.wire,
        connectAccountId = connectAccountId,
        nickname = nickname,
        setAsDefault = setAsDefault,
    )
}
