package com.testlogon.android.data.referrals

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** AND-264 — pure share-link derivation tests (<webOrigin>/?ref=<code>). */
class ReferralLinkTest {

    private fun sampleReferral(code: String) = ReferralCode(
        code = code,
        active = true,
        commissionTier = "standard",
        referralCount = 0,
        createdAt = "2026-05-01",
    )

    @Test
    fun shareLink_buildsRefQuery() {
        assertEquals(
            "https://app.testlogon.com/?ref=AB12CD34",
            sampleReferral("AB12CD34").shareLink("https://app.testlogon.com"),
        )
    }

    @Test
    fun shareLink_trimsTrailingSlashOnOrigin() {
        assertEquals(
            "https://app.testlogon.com/?ref=X1",
            sampleReferral("X1").shareLink("https://app.testlogon.com/"),
        )
    }

    @Test
    fun webOrigin_isPublicHttpsNotDevApiHost() {
        // The link must NOT use the cleartext dev API host.
        assertEquals("https://app.testlogon.com", GrowthLinks.WEB_ORIGIN)
        assertFalse(GrowthLinks.WEB_ORIGIN.contains("18.222.237.167"))
    }
}
