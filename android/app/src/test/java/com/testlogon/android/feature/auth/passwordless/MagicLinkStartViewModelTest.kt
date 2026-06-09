package com.testlogon.android.feature.auth.passwordless

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakePasswordlessRepository
import com.testlogon.android.data.auth.PasswordlessStarted
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

class MagicLinkStartViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakePasswordlessRepository

    @Before
    fun setUp() {
        repo = FakePasswordlessRepository()
    }

    private fun vm() = MagicLinkStartViewModel(repo)

    @Test
    fun submit_disabledUntilIdentifierNonBlank() {
        val v = vm()
        assertFalse(v.uiState.value.isSubmitEnabled)
        v.onIdentifierChange("alice")
        assertTrue(v.uiState.value.isSubmitEnabled)
    }

    @Test
    fun blankIdentifier_makesZeroNetworkCalls() = runTest(mainRule.dispatcher) {
        val v = vm()
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(0, repo.startCalls)
    }

    @Test
    fun bareUsername_isAccepted_andDispatches() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(PasswordlessStarted(status = "sent"))
        val v = vm()
        v.onIdentifierChange("alice") // not email-shaped
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(1, repo.startCalls)
        assertEquals(MagicLinkPhase.Confirmation, v.uiState.value.phase)
    }

    @Test
    fun success_movesToConfirmation_withSentTo() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(PasswordlessStarted(status = "sent", sentTo = listOf("a***@x.com")))
        val v = vm()
        v.onIdentifierChange("  alice@example.com  ")
        v.onSubmit()
        runCurrent()
        assertEquals(MagicLinkPhase.Confirmation, v.uiState.value.phase)
        assertEquals(listOf("a***@x.com"), v.uiState.value.sentTo)
        assertEquals("alice@example.com", repo.lastStartIdentifier?.trim())
    }

    @Test
    fun success_startsResendCooldown_thatDecrementsToZero() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(PasswordlessStarted(status = "sent"))
        val v = vm()
        v.onIdentifierChange("alice")
        v.onSubmit()
        runCurrent()
        assertEquals(MagicLinkStartViewModel.RESEND_COOLDOWN_SECONDS, v.uiState.value.resendSecondsLeft)
        assertFalse(v.uiState.value.canResend)
        advanceUntilIdle()
        assertEquals(0, v.uiState.value.resendSecondsLeft)
        assertTrue(v.uiState.value.canResend)
    }

    @Test
    fun resendDuringCooldown_makesNoNetworkCall() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(PasswordlessStarted(status = "sent"))
        val v = vm()
        v.onIdentifierChange("alice")
        v.onSubmit()
        runCurrent()
        assertEquals(1, repo.startCalls)
        // Cooldown is active (only ~5s elapsed); resend must be blocked.
        advanceTimeBy(5_000)
        v.onResend()
        runCurrent()
        assertEquals(1, repo.startCalls)
    }

    @Test
    fun changeEmail_returnsToEntry_preservesIdentifier_stopsTicker() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(PasswordlessStarted(status = "sent"))
        val v = vm()
        v.onIdentifierChange("alice@example.com")
        v.onSubmit()
        runCurrent()
        v.onChangeEmail()
        advanceUntilIdle()
        assertEquals(MagicLinkPhase.Entry, v.uiState.value.phase)
        assertEquals("alice@example.com", v.uiState.value.identifier)
        assertEquals(0, v.uiState.value.resendSecondsLeft)
    }

    @Test
    fun failure_returnsToEntry_withError() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Failure(ApiError(422, "Invalid"))
        val v = vm()
        v.onIdentifierChange("alice")
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(MagicLinkPhase.Entry, v.uiState.value.phase)
        assertEquals("Invalid", v.uiState.value.error)
    }

    @Test
    fun networkError_returnsToEntry_withRetryableMessage() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.NetworkError(java.io.IOException())
        val v = vm()
        v.onIdentifierChange("alice")
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(MagicLinkPhase.Entry, v.uiState.value.phase)
        assertTrue(v.uiState.value.error!!.contains("Couldn't reach the server"))
    }

    @Test
    fun doubleSubmit_whileSending_callsRepoOnce() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(PasswordlessStarted(status = "sent"))
        val v = vm()
        v.onIdentifierChange("alice")
        v.onSubmit()
        v.onSubmit()
        advanceUntilIdle()
        assertEquals(1, repo.startCalls)
    }

    @Test
    fun toString_doesNotLeakIdentifier() {
        val v = vm()
        v.onIdentifierChange("secretuser@example.com")
        assertFalse(v.uiState.value.toString().contains("secretuser"))
    }

    @Test
    fun dismissError_clearsError() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Failure(ApiError(422, "Invalid"))
        val v = vm()
        v.onIdentifierChange("alice")
        v.onSubmit()
        advanceUntilIdle()
        v.onDismissError()
        assertNull(v.uiState.value.error)
    }
}
