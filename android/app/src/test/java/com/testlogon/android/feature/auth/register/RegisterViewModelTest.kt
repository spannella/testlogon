package com.testlogon.android.feature.auth.register

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.EmailAvailability
import com.testlogon.android.data.auth.FakeRegisterRepository
import com.testlogon.android.data.auth.RegisterStartOutcome
import com.testlogon.android.data.auth.User
import kotlinx.coroutines.launch
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

class RegisterViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private lateinit var repo: FakeRegisterRepository
    private lateinit var vm: RegisterViewModel

    private val validPassword = "Ada!Lovelace2026"

    @Before
    fun setUp() {
        repo = FakeRegisterRepository()
        vm = RegisterViewModel(repo)
    }

    private fun fillValidForm() {
        vm.onFullNameChange("Ada Lovelace")
        vm.onEmailChange("ada@example.com")
        vm.onPasswordChange(validPassword)
        vm.onConfirmChange(validPassword)
    }

    @Test
    fun initialState_isEmptyAndDisabled() {
        val s = vm.uiState.value
        assertEquals("", s.fullName)
        assertFalse(s.submitEnabled)
        assertFalse(s.isSubmitting)
    }

    @Test
    fun submitEnabled_whenAllValid_noMfa() {
        fillValidForm()
        assertTrue(vm.uiState.value.submitEnabled)
    }

    @Test
    fun submitDisabled_onPasswordMismatch() {
        fillValidForm()
        vm.onConfirmChange("different")
        assertFalse(vm.uiState.value.submitEnabled)
    }

    @Test
    fun smsMfa_makesPhoneRequired_blocksUntilValidPhone() {
        fillValidForm()
        vm.onToggleSmsMfa(true)
        assertTrue(vm.uiState.value.isPhoneRequired)
        assertFalse(vm.uiState.value.submitEnabled)
        vm.onPhoneChange("+15551234567")
        assertTrue(vm.uiState.value.submitEnabled)
        // Disabling SMS drops the requirement again.
        vm.onPhoneChange("")
        vm.onToggleSmsMfa(false)
        assertFalse(vm.uiState.value.isPhoneRequired)
        assertTrue(vm.uiState.value.submitEnabled)
    }

    @Test
    fun submit_invalidForm_surfacesFieldErrors_doesNotCallRepo() = runTest(mainRule.dispatcher) {
        vm.onFullNameChange("") // blank
        vm.onSubmit()
        advanceUntilIdle()
        assertEquals(RegisterFieldError.Required, vm.uiState.value.fullNameError)
        assertEquals(0, repo.startCalls)
    }

    @Test
    fun submit_verificationRequired_emitsGoToConfirm() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(
            RegisterStartOutcome.VerificationRequired("ada@example.com", "email", "a***@example.com"),
        )
        fillValidForm()

        val effects = mutableListOf<RegisterEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()

        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, effects.size)
        val ev = effects.first() as RegisterEffect.GoToConfirm
        assertEquals("ada@example.com", ev.email)
        assertEquals("email", ev.deliveryMedium)
    }

    @Test
    fun submit_authenticated_emitsGoToApp() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(RegisterStartOutcome.Authenticated(User("u", "s", "ip")))
        fillValidForm()

        val effects = mutableListOf<RegisterEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(RegisterEffect.GoToAppAuthenticated), effects)
    }

    @Test
    fun submit_verifiedSignIn_emitsGoToLogin() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(RegisterStartOutcome.VerifiedSignIn)
        fillValidForm()

        val effects = mutableListOf<RegisterEffect>()
        val job = launch { vm.effects.collect { effects += it } }
        runCurrent()
        vm.onSubmit()
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(RegisterEffect.GoToLoginSuccess), effects)
    }

    @Test
    fun submit_failure_showsFormError_andReEnables() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Failure(ApiError(422, "email already registered"))
        fillValidForm()
        vm.onSubmit()
        advanceUntilIdle()
        assertEquals("email already registered", vm.uiState.value.formError)
        assertFalse(vm.uiState.value.isSubmitting)
    }

    @Test
    fun submit_networkError_showsNetworkMessage() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        fillValidForm()
        vm.onSubmit()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.formError!!.contains("Couldn't reach the server"))
    }

    @Test
    fun doubleSubmit_whileInFlight_callsRepoOnce() = runTest(mainRule.dispatcher) {
        repo.startResult = ApiResult.Success(RegisterStartOutcome.VerifiedSignIn)
        fillValidForm()
        vm.onSubmit()
        vm.onSubmit()
        advanceUntilIdle()
        assertEquals(1, repo.startCalls)
    }

    @Test
    fun toString_doesNotLeakSecrets() {
        fillValidForm()
        val s = vm.uiState.value.toString()
        assertFalse(s.contains(validPassword))
        assertFalse(s.contains("ada@example.com"))
    }

    // ── AND-055 email availability ──

    @Test
    fun validEmail_afterDebounce_dispatchesOneCheck_trimmed() = runTest(mainRule.dispatcher) {
        repo.checkResult = ApiResult.Success(true)
        vm.onEmailChange("  ada@example.com  ")
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        assertEquals(1, repo.checkCalls)
        assertEquals("ada@example.com", repo.checkedEmails.last())
        assertEquals(EmailAvailability.Available, vm.uiState.value.emailAvailability)
    }

    @Test
    fun rapidTyping_collapsesToOneCheck() = runTest(mainRule.dispatcher) {
        repo.checkResult = ApiResult.Success(true)
        vm.onEmailChange("a@b")
        vm.onEmailChange("a@b.c")
        vm.onEmailChange("a@b.com")
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        assertEquals(1, repo.checkCalls)
        assertEquals("a@b.com", repo.checkedEmails.last())
    }

    @Test
    fun invalidEmail_dispatchesNothing_andUnknown() = runTest(mainRule.dispatcher) {
        vm.onEmailChange("foo")
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        assertEquals(0, repo.checkCalls)
        assertEquals(EmailAvailability.Unknown, vm.uiState.value.emailAvailability)
    }

    @Test
    fun takenEmail_setsTaken_blocksSubmit() = runTest(mainRule.dispatcher) {
        repo.checkResult = ApiResult.Success(false)
        fillValidForm()
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        assertEquals(EmailAvailability.Taken, vm.uiState.value.emailAvailability)
        assertTrue(vm.uiState.value.emailTaken)
        assertFalse(vm.uiState.value.submitEnabled)
    }

    @Test
    fun checkFailure_isAdvisoryError_doesNotBlockSubmit() = runTest(mainRule.dispatcher) {
        repo.checkResult = ApiResult.Failure(ApiError(429, "rate limited"))
        fillValidForm()
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        assertEquals(EmailAvailability.Error, vm.uiState.value.emailAvailability)
        assertTrue(vm.uiState.value.submitEnabled)
    }

    @Test
    fun onEmailChange_resetsAvailabilityToUnknown() = runTest(mainRule.dispatcher) {
        repo.checkResult = ApiResult.Success(false)
        fillValidForm()
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        assertEquals(EmailAvailability.Taken, vm.uiState.value.emailAvailability)
        vm.onEmailChange("ada2@example.com")
        assertEquals(EmailAvailability.Unknown, vm.uiState.value.emailAvailability)
    }

    @Test
    fun staleResult_isDiscarded_whenEmailMovedOn() = runTest(mainRule.dispatcher) {
        repo.checkResult = ApiResult.Success(false)
        vm.onEmailChange("old@example.com")
        // change before debounce fires -> flatMapLatest cancels the old query
        vm.onEmailChange("new@example.com")
        advanceTimeBy(RegisterViewModel.EMAIL_DEBOUNCE_MS + 50)
        advanceUntilIdle()
        // only the new email should have been checked
        assertEquals(listOf("new@example.com"), repo.checkedEmails)
    }
}
