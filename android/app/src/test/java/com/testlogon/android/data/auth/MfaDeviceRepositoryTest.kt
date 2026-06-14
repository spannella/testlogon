package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-064 — MfaDeviceRepository against the [FakeAuthApi]; asserts merge/sort, mapping, and bodies. */
class MfaDeviceRepositoryTest {

    private val moshi = Moshi.Builder().build()
    private val api = FakeAuthApi()
    private val repo = MfaDeviceRepositoryImpl(api, ApiErrorParser(moshi))

    @Test
    fun list_mergesThreeEndpoints_tagsType_andSorts() = runTest {
        api.totpDevicesResult = {
            TotpDeviceListDto(listOf(TotpDeviceDto(deviceId = "t1", enabled = true, createdAt = 100)))
        }
        api.smsDevicesResult = {
            SmsDeviceListDto(listOf(SmsDeviceDto(deviceId = "s1", phoneE164 = "+15551231234", createdAt = 300)))
        }
        api.emailDevicesResult = {
            EmailDeviceListDto(listOf(EmailDeviceDto(deviceId = "e1", email = "a@b.com", createdAt = 200)))
        }

        val r = repo.list()
        assertTrue(r is ApiResult.Success)
        val devices = (r as ApiResult.Success).data
        assertEquals(3, devices.size)
        // TOTP first (ordinal), then by createdAt desc within the merged list.
        assertEquals(MfaFactorType.TOTP, devices[0].type)
        assertEquals("s1", devices[1].deviceId) // sms 300 before email 200
        assertEquals("e1", devices[2].deviceId)
        assertEquals("+15551231234", devices[1].destination)
    }

    @Test
    fun list_partialFailure_stillReturnsMergedList() = runTest {
        api.totpDevicesResult = { throw FakeAuthApi.httpError(500) }
        api.smsDevicesResult = { SmsDeviceListDto(listOf(SmsDeviceDto(deviceId = "s1", createdAt = 1))) }
        api.emailDevicesResult = { EmailDeviceListDto() }

        val r = repo.list()
        assertTrue(r is ApiResult.Success)
        assertEquals(1, (r as ApiResult.Success).data.size)
    }

    @Test
    fun confirmTotp_sendsDeviceIdAndTwoCodes() = runTest {
        api.confirmTotpDeviceResult = { EnrollResultDto(ok = true, recoveryCodes = listOf("r1", "r2")) }
        val r = repo.confirmTotp("dev_1", "111111", "222222")
        assertTrue(r is ApiResult.Success)
        assertEquals(listOf("r1", "r2"), (r as ApiResult.Success).data.recoveryCodes)
        assertEquals("dev_1", api.lastTotpConfirmBody?.deviceId)
        assertEquals("111111", api.lastTotpConfirmBody?.totpCode)
        assertEquals("222222", api.lastTotpConfirmBody?.totpCode2)
    }

    @Test
    fun beginSms_sendsPhoneE164Key() = runTest {
        api.beginSmsDeviceResult = { DeviceChallengeDto(challengeId = "c1", sentTo = listOf("+1•••4567"), smsDeviceId = "s1") }
        val r = repo.beginCode(MfaFactorType.SMS, "+15551234567")
        assertTrue(r is ApiResult.Success)
        assertEquals("c1", (r as ApiResult.Success).data.challengeId)
        assertEquals("+15551234567", api.lastSmsBeginBody?.phoneE164)
    }

    @Test
    fun confirmCode_keysOnChallengeId_andTypePath() = runTest {
        api.confirmCodeDeviceResult = { EnrollResultDto(ok = true, smsDeviceId = "s1") }
        val r = repo.confirmCode(MfaFactorType.SMS, "chal_1", "654321")
        assertTrue(r is ApiResult.Success)
        assertEquals("sms", api.lastCodeConfirmType)
        assertEquals("chal_1", api.lastCodeConfirmBody?.challengeId)
        assertEquals("654321", api.lastCodeConfirmBody?.code)
    }

    @Test
    fun removeTotp_sendsTotpCode_singleStep() = runTest {
        val r = repo.removeTotp("dev_1", "999111")
        assertTrue(r is ApiResult.Success)
        assertEquals("dev_1", api.lastTotpRemoveDeviceId)
        assertEquals("999111", api.lastTotpRemoveBody?.totpCode)
    }

    @Test
    fun removeCode_twoStep_beginThenConfirm() = runTest {
        api.beginRemoveCodeDeviceResult = { DeviceChallengeDto(challengeId = "rc1", sentTo = listOf("+1•••4567")) }
        val begin = repo.beginRemoveCode(MfaFactorType.SMS, "s1")
        assertTrue(begin is ApiResult.Success)
        assertEquals("sms", api.lastRemoveBeginType)
        assertEquals("s1", api.lastRemoveBeginDeviceId)
        assertNull((begin as ApiResult.Success).data.deviceId) // remove/begin carries no device id

        val confirm = repo.confirmRemoveCode(MfaFactorType.SMS, "rc1", "313131")
        assertTrue(confirm is ApiResult.Success)
        assertEquals("sms", api.lastRemoveConfirmType)
        assertEquals("rc1", api.lastRemoveConfirmBody?.challengeId)
        assertEquals("313131", api.lastRemoveConfirmBody?.code)
    }

    @Test
    fun confirmTotp_httpError_mapsToFailureWithStatus() = runTest {
        api.confirmTotpDeviceResult = { throw FakeAuthApi.httpError(400, """{"detail":{"code":"mfa_invalid_code"}}""") }
        val r = repo.confirmTotp("dev_1", "1", "2")
        assertTrue(r is ApiResult.Failure)
        assertEquals(400, (r as ApiResult.Failure).error.status)
    }
}
