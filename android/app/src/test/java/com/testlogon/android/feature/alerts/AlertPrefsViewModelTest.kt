package com.testlogon.android.feature.alerts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.alerts.AlertBeginResult
import com.testlogon.android.data.alerts.EmailAlertRepository
import com.testlogon.android.data.alerts.SmsAlertRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-090 — [AlertPrefsViewModel] add->verify->remove + stale/error state tests. */
class AlertPrefsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeEmailRepo : EmailAlertRepository {
        var emails = listOf("a@x.com")
        var listResult: ApiResult<List<String>>? = null
        var beginResult: ApiResult<AlertBeginResult> = ApiResult.Success(AlertBeginResult("chal_1", "new@x.com"))
        override suspend fun listEmails() = listResult ?: ApiResult.Success(emails)
        override suspend fun begin(email: String) = beginResult
        override suspend fun confirm(challengeId: String, code: String) =
            ApiResult.Success(emails + "new@x.com")
        override suspend fun remove(email: String) = ApiResult.Success(emails.filterNot { it == email })
    }

    private class FakeSmsRepo : SmsAlertRepository {
        var numbers = listOf("+15551231234")
        override suspend fun listNumbers() = ApiResult.Success(numbers)
        override suspend fun begin(rawPhone: String) =
            ApiResult.Success(AlertBeginResult("chl_1", "+1•••1234"))
        override suspend fun confirm(challengeId: String, code: String) =
            ApiResult.Success(numbers + "+15559998888")
        override suspend fun remove(phone: String) = ApiResult.Success(numbers.filterNot { it == phone })
    }

    @Test
    fun load_populatesEmailsAndNumbers() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo())
        advanceUntilIdle()
        val s = vm.state.value
        assertTrue(s.loaded)
        assertEquals(listOf("a@x.com"), s.emails)
        assertEquals(listOf("+15551231234"), s.smsNumbers)
        assertNull(s.error)
    }

    @Test
    fun addEmail_thenVerify_addsTarget() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo())
        advanceUntilIdle()
        vm.onEmailInputChanged("new@x.com")
        vm.addEmail()
        advanceUntilIdle()
        assertEquals(AlertChannel.EMAIL, vm.state.value.pending?.channel)
        assertEquals("new@x.com", vm.state.value.pending?.sentTo)

        vm.onCodeInputChanged("483920")
        vm.verify()
        advanceUntilIdle()
        assertNull(vm.state.value.pending)
        assertTrue("new@x.com" in vm.state.value.emails)
    }

    @Test
    fun verify_shortCode_doesNothing() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo())
        advanceUntilIdle()
        vm.onEmailInputChanged("new@x.com")
        vm.addEmail()
        advanceUntilIdle()
        vm.onCodeInputChanged("123") // < 6
        vm.verify()
        advanceUntilIdle()
        assertEquals(AlertChannel.EMAIL, vm.state.value.pending?.channel) // still pending
    }

    @Test
    fun removeSms_dropsNumber() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo())
        advanceUntilIdle()
        vm.removeSms("+15551231234")
        advanceUntilIdle()
        assertTrue(vm.state.value.smsNumbers.isEmpty())
    }

    @Test
    fun load_emailFailsButSmsOk_servesStale() = runTest {
        val email = FakeEmailRepo().apply { listResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = AlertPrefsViewModel(email, FakeSmsRepo())
        advanceUntilIdle()
        val s = vm.state.value
        assertTrue(s.isStale)
        assertNull(s.error) // not a full error — sms loaded
        assertEquals(listOf("+15551231234"), s.smsNumbers)
    }

    @Test
    fun load_bothFail_setsError() = runTest {
        val email = FakeEmailRepo().apply { listResult = ApiResult.Failure(ApiError(500, "boom")) }
        val sms = object : SmsAlertRepository {
            override suspend fun listNumbers() = ApiResult.Failure(ApiError(500, "boom"))
            override suspend fun begin(rawPhone: String) = ApiResult.Failure(ApiError(500, "boom"))
            override suspend fun confirm(challengeId: String, code: String) = ApiResult.Failure(ApiError(500, "boom"))
            override suspend fun remove(phone: String) = ApiResult.Failure(ApiError(500, "boom"))
        }
        val vm = AlertPrefsViewModel(email, sms)
        advanceUntilIdle()
        assertEquals("boom", vm.state.value.error)
    }
}
