package com.testlogon.android.data.payouts

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-259 — STOP-AND-FLAG: the bound [StubKycVerifier] NEVER launches a real KYC vendor flow. It always
 * returns [KycVerificationResult.NotConfigured] (no submitted/verified state can be faked).
 */
class KycVerifierTest {

    @Test
    fun stub_alwaysReturnsNotConfigured_neverLaunches() = runTest {
        val verifier: KycVerifier = StubKycVerifier()
        repeat(3) {
            assertEquals(KycVerificationResult.NotConfigured, verifier.verifyIdentity())
        }
    }
}
