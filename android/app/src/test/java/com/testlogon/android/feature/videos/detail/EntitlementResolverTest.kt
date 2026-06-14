package com.testlogon.android.feature.videos.detail

import com.testlogon.android.feature.videos.FakeVideosRepository
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-197 / AND-198 — table-driven branch coverage for the pure [EntitlementResolver]. Mirrors the web
 * VideoAccessGate precedence; verifies fail-closed behavior (no spurious Granted) and that NOT_FOUND /
 * REGION_BLOCKED are NOT produced here (they belong to the HTTP error layer).
 */
class EntitlementResolverTest {

    private fun detail(
        status: String = "ready",
        isEntitled: Boolean = false,
        accessMode: String? = null,
        priceCents: Int? = null,
        purchaseAvailable: Boolean = false,
        subscriptionUpsell: Boolean = false,
    ) = FakeVideosRepository.detail(
        id = "vid_1",
        status = status,
        isEntitled = isEntitled,
        accessMode = accessMode,
        priceCents = priceCents,
        purchaseAvailable = purchaseAvailable,
        subscriptionUpsell = subscriptionUpsell,
    )

    @Test
    fun accessEntitled_grants_regardlessOfAuth() {
        val access = FakeVideosRepository.access(entitled = true)
        assertEquals(
            Entitlement.Granted("vid_1"),
            EntitlementResolver.resolve(detail(), access, isAuthenticated = false),
        )
        assertEquals(
            Entitlement.Granted("vid_1"),
            EntitlementResolver.resolve(detail(), access, isAuthenticated = true),
        )
    }

    @Test
    fun accessNull_fallsBackToInlineEntitled_grants() {
        val result = EntitlementResolver.resolve(
            detail(isEntitled = true),
            access = null,
            isAuthenticated = true,
        )
        assertEquals(Entitlement.Granted("vid_1"), result)
    }

    @Test
    fun accessNull_inlineNotEntitled_ppv_failsClosed_toPurchaseRequired() {
        // Fail-closed: access failed (null), inline not entitled, purchasable -> PurchaseRequired (NOT Granted).
        val result = EntitlementResolver.resolve(
            detail(isEntitled = false, purchaseAvailable = true, priceCents = 499),
            access = null,
            isAuthenticated = true,
        )
        assertEquals(Entitlement.PurchaseRequired(499), result)
    }

    @Test
    fun ppv_authed_purchaseRequired_unauthed_loginRequired() {
        val access = FakeVideosRepository.access(entitled = false, accessMode = "ppv", priceCents = 499)
        assertEquals(
            Entitlement.PurchaseRequired(499),
            EntitlementResolver.resolve(detail(accessMode = "ppv", priceCents = 499), access, isAuthenticated = true),
        )
        assertEquals(
            Entitlement.LoginRequired,
            EntitlementResolver.resolve(detail(accessMode = "ppv", priceCents = 499), access, isAuthenticated = false),
        )
    }

    @Test
    fun subscriberOnly_authed_subscriptionRequired_unauthed_loginRequired() {
        val access = FakeVideosRepository.access(entitled = false, accessMode = "subscriber_only")
        assertEquals(
            Entitlement.SubscriptionRequired,
            EntitlementResolver.resolve(detail(accessMode = "subscriber_only"), access, isAuthenticated = true),
        )
        assertEquals(
            Entitlement.LoginRequired,
            EntitlementResolver.resolve(detail(accessMode = "subscriber_only"), access, isAuthenticated = false),
        )
    }

    @Test
    fun subscriptionUpsell_authed_purchaseOrSubscribe_unauthed_loginRequired() {
        val access = FakeVideosRepository.access(entitled = false, subscriptionUpsell = true, priceCents = 499)
        assertEquals(
            Entitlement.PurchaseOrSubscribe(499),
            EntitlementResolver.resolve(detail(subscriptionUpsell = true, priceCents = 499), access, isAuthenticated = true),
        )
        assertEquals(
            Entitlement.LoginRequired,
            EntitlementResolver.resolve(detail(subscriptionUpsell = true, priceCents = 499), access, isAuthenticated = false),
        )
    }

    @Test
    fun notReadyStatus_isUnavailableNotReady_regardlessOfEntitlement() {
        val access = FakeVideosRepository.access(entitled = true)
        assertEquals(
            Entitlement.Unavailable(UnavailableReason.NOT_READY),
            EntitlementResolver.resolve(detail(status = "encoding"), access, isAuthenticated = true),
        )
    }

    @Test
    fun readyButNoGatingFlags_isUnavailableUnknown_neverGranted() {
        val access = FakeVideosRepository.access(entitled = false)
        assertEquals(
            Entitlement.Unavailable(UnavailableReason.UNKNOWN),
            EntitlementResolver.resolve(detail(isEntitled = false), access, isAuthenticated = true),
        )
    }

    @Test
    fun purchaseAvailableWithoutPpvMode_authed_purchaseRequired() {
        val access = FakeVideosRepository.access(entitled = false, purchaseAvailable = true, priceCents = 250)
        assertEquals(
            Entitlement.PurchaseRequired(250),
            EntitlementResolver.resolve(detail(purchaseAvailable = true, priceCents = 250), access, isAuthenticated = true),
        )
    }
}
