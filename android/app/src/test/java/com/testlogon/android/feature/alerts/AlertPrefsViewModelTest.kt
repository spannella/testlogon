package com.testlogon.android.feature.alerts

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.alerts.AlertBeginResult
import com.testlogon.android.data.alerts.EmailAlertRepository
import com.testlogon.android.data.alerts.SmsAlertRepository
import com.testlogon.android.data.alerts.WebhookAlertRepository
import com.testlogon.android.data.alerts.WebhookPrefs
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

    private class FakeWebhookRepo : WebhookAlertRepository {
        var prefs = WebhookPrefs(emptyList(), emptyList())
        override suspend fun get() = ApiResult.Success(prefs)
        override suspend fun save(prefs: WebhookPrefs) = ApiResult.Success(prefs).also { this.prefs = prefs }
        override suspend fun addUrl(current: WebhookPrefs, rawUrl: String) =
            save(current.copy(urls = current.urls + rawUrl.trim()))
        override suspend fun removeUrl(current: WebhookPrefs, url: String) =
            save(current.copy(urls = current.urls.filterNot { it == url }))
    }

    @Test
    fun load_populatesEmailsAndNumbers() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), FakeWebhookRepo())
        advanceUntilIdle()
        val s = vm.state.value
        assertTrue(s.loaded)
        assertEquals(listOf("a@x.com"), s.emails)
        assertEquals(listOf("+15551231234"), s.smsNumbers)
        assertNull(s.error)
    }

    @Test
    fun addEmail_thenVerify_addsTarget() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), FakeWebhookRepo())
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
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), FakeWebhookRepo())
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
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), FakeWebhookRepo())
        advanceUntilIdle()
        vm.removeSms("+15551231234")
        advanceUntilIdle()
        assertTrue(vm.state.value.smsNumbers.isEmpty())
    }

    @Test
    fun load_emailFailsButSmsOk_servesStale() = runTest {
        val email = FakeEmailRepo().apply { listResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = AlertPrefsViewModel(email, FakeSmsRepo(), FakeWebhookRepo())
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
        val vm = AlertPrefsViewModel(email, sms, FakeWebhookRepo())
        advanceUntilIdle()
        assertEquals("boom", vm.state.value.error)
    }

    @Test
    fun addWebhook_validUrl_addsEndpoint() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), FakeWebhookRepo())
        advanceUntilIdle()
        vm.onWebhookInputChanged("https://hooks.example.com/x")
        vm.addWebhook()
        advanceUntilIdle()
        assertTrue("https://hooks.example.com/x" in vm.state.value.webhookUrls)
        assertEquals("", vm.state.value.webhookInput)
    }

    @Test
    fun addWebhook_invalidUrl_isNoOp() = runTest {
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), FakeWebhookRepo())
        advanceUntilIdle()
        vm.onWebhookInputChanged("not-a-url")
        vm.addWebhook()
        advanceUntilIdle()
        assertTrue(vm.state.value.webhookUrls.isEmpty())
    }

    @Test
    fun removeWebhook_dropsEndpoint() = runTest {
        val hook = FakeWebhookRepo().apply { prefs = WebhookPrefs(listOf("https://a.com/x"), emptyList()) }
        val vm = AlertPrefsViewModel(FakeEmailRepo(), FakeSmsRepo(), hook)
        advanceUntilIdle()
        assertEquals(listOf("https://a.com/x"), vm.state.value.webhookUrls)
        vm.removeWebhook("https://a.com/x")
        advanceUntilIdle()
        assertTrue(vm.state.value.webhookUrls.isEmpty())
    }
}
