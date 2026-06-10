package com.testlogon.android.feature.messaging

import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult

/**
 * AND-139 — configurable [BillingAuthorizer] for unit tests. Defaults to authorizing with a fixed
 * payment-method id (no network/charge); set [result] to script Cancelled/Declined/Failed/
 * NotConfigured outcomes. Records the authorized amounts for assertions.
 */
class FakeBillingAuthorizer(
    var result: BillingResult = BillingResult.Authorized("pm_test", 0L),
) : BillingAuthorizer {

    val authorizeCalls = mutableListOf<Pair<Long, String>>()

    override suspend fun authorize(
        amountMinorUnits: Long,
        currency: String,
        memo: String?,
    ): BillingResult {
        authorizeCalls += amountMinorUnits to currency
        return when (val r = result) {
            is BillingResult.Authorized -> r.copy(authorizedMinorUnits = amountMinorUnits)
            else -> r
        }
    }
}
