package com.testlogon.android.feature.account

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.DeviceChallenge
import com.testlogon.android.data.auth.EnrollResult
import com.testlogon.android.data.auth.FakeMfaDeviceRepository
import com.testlogon.android.data.auth.MfaDevice
import com.testlogon.android.data.auth.MfaFactorType
import com.testlogon.android.data.auth.TotpEnrollment
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class MfaDevicesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakeMfaDeviceRepository

    @Before
    fun setUp() {
        repo = FakeMfaDeviceRepository()
    }

    private fun vm() = MfaDevicesViewModel(repo)

    @Test
    fun load_populatesDevices() = runTest(mainRule.dispatcher) {
        repo.listResult = ApiResult.Success(
            listOf(MfaDevice("t1", MfaFactorType.TOTP, "Auth", null, true, false, 1)),
        )
        val v = vm()
        v.load()
        advanceUntilIdle()
        assertEquals(1, v.state.value.devices.size)
        assertEquals(false, v.state.value.isLoading)
    }

    @Test
    fun totpEnroll_happyPath_showsRecoveryCodes_thenList() = runTest(mainRule.dispatcher) {
        repo.beginTotpResult = ApiResult.Success(TotpEnrollment("d1", "data:image/png;base64,AAAA", "JBSWY3DP"))
        repo.confirmTotpResult = ApiResult.Success(EnrollResult(ok = true, deviceId = null, recoveryCodes = listOf("r1")))
        repo.listResult = ApiResult.Success(emptyList())

        val v = vm()
        v.startTotpEnroll()
        advanceUntilIdle()
        val enroll = v.state.value.enroll as MfaDevicesViewModel.EnrollState.Totp
        assertEquals(MfaDevicesViewModel.Step.AwaitingCode, enroll.step)
        assertEquals("JBSWY3DP", enroll.enrollment?.secret)

        v.onTotpCodeChange("111111")
        v.onTotpCode2Change("222222")
        v.submitTotpConfirm()
        advanceUntilIdle()
        val after = v.state.value.enroll as MfaDevicesViewModel.EnrollState.Totp
        assertEquals(listOf("r1"), after.recoveryCodes)
        assertEquals(1, repo.confirmTotpCalls)
    }

    @Test
    fun totpConfirm_requiresBothCodes() = runTest(mainRule.dispatcher) {
        repo.beginTotpResult = ApiResult.Success(TotpEnrollment("d1", "uri", "sec"))
        val v = vm()
        v.startTotpEnroll()
        advanceUntilIdle()
        v.onTotpCodeChange("111111") // only first code
        v.submitTotpConfirm()
        advanceUntilIdle()
        assertEquals(0, repo.confirmTotpCalls)
        val enroll = v.state.value.enroll as MfaDevicesViewModel.EnrollState.Totp
        assertTrue(enroll.error != null)
    }

    @Test
    fun smsEnroll_happyPath_beginThenConfirm_reloadsList() = runTest(mainRule.dispatcher) {
        repo.beginCodeResult = ApiResult.Success(DeviceChallenge("c1", listOf("+1•••4567"), "s1"))
        repo.confirmCodeResult = ApiResult.Success(EnrollResult(ok = true, deviceId = "s1", recoveryCodes = emptyList()))
        repo.listResult = ApiResult.Success(emptyList())

        val v = vm()
        v.startCodeEnroll(MfaFactorType.SMS)
        v.onDestinationChange("+15551234567")
        v.submitBegin()
        advanceUntilIdle()
        val mid = v.state.value.enroll as MfaDevicesViewModel.EnrollState.Code
        assertEquals(MfaDevicesViewModel.Step.AwaitingCode, mid.step)

        v.onCodeChange("654321")
        v.submitCodeConfirm()
        advanceUntilIdle()
        assertEquals(MfaDevicesViewModel.EnrollState.None, v.state.value.enroll)
        assertEquals(1, repo.confirmCodeCalls)
    }

    @Test
    fun resend_disabledDuringCooldown() = runTest(mainRule.dispatcher) {
        repo.beginCodeResult = ApiResult.Success(DeviceChallenge("c1", emptyList(), "s1"))
        val v = vm()
        v.startCodeEnroll(MfaFactorType.SMS)
        v.onDestinationChange("+15551234567")
        v.submitBegin()
        runCurrent()
        val code = v.state.value.enroll as MfaDevicesViewModel.EnrollState.Code
        assertEquals(MfaDevicesViewModel.RESEND_COOLDOWN_SECONDS, code.resendInSeconds)
        v.resend()
        runCurrent()
        assertEquals(1, repo.beginCodeCalls) // resend blocked during cooldown
    }

    @Test
    fun cancelEnroll_clearsState() = runTest(mainRule.dispatcher) {
        repo.beginTotpResult = ApiResult.Success(TotpEnrollment("d1", "uri", "sec"))
        val v = vm()
        v.startTotpEnroll()
        advanceUntilIdle()
        v.cancelEnroll()
        assertEquals(MfaDevicesViewModel.EnrollState.None, v.state.value.enroll)
    }

    @Test
    fun removeTotp_singleStep_callsRemoveThenReloads() = runTest(mainRule.dispatcher) {
        repo.listResult = ApiResult.Success(emptyList())
        val v = vm()
        v.requestRemove(MfaDevice("t1", MfaFactorType.TOTP, "Auth", null, true, false, 1))
        v.onRemoveCodeChange("999111")
        v.confirmRemove()
        advanceUntilIdle()
        assertEquals(1, repo.removeTotpCalls)
        assertEquals(MfaDevicesViewModel.RemoveState.None, v.state.value.remove)
    }

    @Test
    fun removeSms_twoStep_beginThenConfirm() = runTest(mainRule.dispatcher) {
        repo.beginRemoveCodeResult = ApiResult.Success(DeviceChallenge("rc1", listOf("+1•••4567")))
        repo.listResult = ApiResult.Success(emptyList())
        val v = vm()
        v.requestRemove(MfaDevice("s1", MfaFactorType.SMS, "Phone", "+15551231234", true, false, 1))
        v.confirmRemove() // begin
        advanceUntilIdle()
        assertEquals(1, repo.beginRemoveCodeCalls)
        val rm = v.state.value.remove as MfaDevicesViewModel.RemoveState.Code
        assertEquals(MfaDevicesViewModel.Step.AwaitingCode, rm.step)

        v.onRemoveCodeChange("313131")
        v.confirmRemove() // confirm
        advanceUntilIdle()
        assertEquals(1, repo.confirmRemoveCodeCalls)
        assertEquals(MfaDevicesViewModel.RemoveState.None, v.state.value.remove)
    }

    @Test
    fun invalidCode_keepsAwaitingCode_andSurfacesError() = runTest(mainRule.dispatcher) {
        repo.beginCodeResult = ApiResult.Success(DeviceChallenge("c1", emptyList(), "s1"))
        repo.confirmCodeResult = ApiResult.Failure(ApiError(400, "Invalid code", "mfa_invalid_code"))
        val v = vm()
        v.startCodeEnroll(MfaFactorType.SMS)
        v.onDestinationChange("+15551234567")
        v.submitBegin()
        advanceUntilIdle()
        v.onCodeChange("000000")
        v.submitCodeConfirm()
        advanceUntilIdle()
        val code = v.state.value.enroll as MfaDevicesViewModel.EnrollState.Code
        assertEquals(MfaDevicesViewModel.Step.AwaitingCode, code.step)
        assertEquals("Invalid code", code.error)
    }
}
