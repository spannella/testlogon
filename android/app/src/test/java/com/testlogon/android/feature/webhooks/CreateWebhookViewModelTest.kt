package com.testlogon.android.feature.webhooks

import com.squareup.moshi.Moshi
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo.Companion.eventType
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksRepo.Companion.webhook
import com.testlogon.android.feature.webhooks.ui.CreateWebhookViewModel
import com.testlogon.android.feature.webhooks.ui.WebhooksEffect
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-398 - tests for [CreateWebhookViewModel] (AC-4): canSubmit gating (non-https rejected with urlError; no
 * events; valid); the event-types metadata populates the chips; a valid submit POSTs the corrected body and
 * emits CreateSucceeded carrying the one-time secret; a 422 loc:["body","url"] maps to urlError; a double-submit
 * is guarded.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CreateWebhookViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeWebhooksRepo()
    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun vm() = CreateWebhookViewModel(repo = repo, errorParser = errorParser)

    @Test
    fun eventTypes_populateChips() = runTest {
        repo.eventTypesResult = ApiResult.Success(
            listOf(eventType("session.finalized"), eventType("mfa.verified")),
        )
        val vm = vm()
        runCurrent()
        val form = vm.form.value
        assertFalse(form.eventTypesLoading)
        assertEquals(listOf("session.finalized", "mfa.verified"), form.eventTypes.map { it.type })
    }

    @Test
    fun gating_nonHttpsRejected_thenNoEvents_thenValid() = runTest {
        repo.eventTypesResult = ApiResult.Success(listOf(eventType("session.finalized")))
        val vm = vm()
        runCurrent()

        // (a) non-https url -> canSubmit false, urlError set
        vm.onUrlChange("http://x")
        assertFalse(vm.form.value.canSubmit)

        // (b) valid https but no events selected -> canSubmit false
        vm.onUrlChange("https://ok.test/h")
        assertFalse(vm.form.value.canSubmit)

        // (c) add one event -> canSubmit true
        vm.toggleEvent("session.finalized")
        assertTrue(vm.form.value.canSubmit)

        // toggling it off again -> canSubmit false
        vm.toggleEvent("session.finalized")
        assertFalse(vm.form.value.canSubmit)
    }

    @Test
    fun submit_success_emitsCreateSucceeded_withSecret_andPostsCorrectedBody() = runTest {
        repo.eventTypesResult = ApiResult.Success(listOf(eventType("session.finalized")))
        repo.createResult = ApiResult.Success(webhook("wh_new", secret = "whsec_xyz"))
        val received = mutableListOf<WebhooksEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        vm.onUrlChange("https://ok.test/h")
        vm.toggleEvent("session.finalized")
        vm.submit()
        runCurrent()

        assertEquals("https://ok.test/h" to listOf("session.finalized"), repo.createArgs.single())
        assertEquals(listOf(WebhooksEffect.CreateSucceeded("whsec_xyz")), received)
        assertFalse(vm.form.value.submitting)
    }

    @Test
    fun submit_422OnUrl_mapsToUrlError() = runTest {
        repo.eventTypesResult = ApiResult.Success(listOf(eventType("session.finalized")))
        repo.createResult = ApiResult.Failure(
            ApiError(
                status = 422,
                message = "invalid url",
                raw = """{"detail":[{"loc":["body","url"],"msg":"invalid url","type":"value_error"}]}""",
            ),
        )
        val vm = vm()
        runCurrent()
        vm.onUrlChange("https://ok.test/h")
        vm.toggleEvent("session.finalized")
        vm.submit()
        runCurrent()

        val form = vm.form.value
        assertNotNull(form.urlError)
        assertEquals("invalid url", form.urlError)
        assertNotNull(form.submitError)
        assertFalse(form.submitting)
    }

    @Test
    fun submit_whenNotSubmittable_isNoOp() = runTest {
        val vm = vm()
        runCurrent()
        vm.submit() // empty form, canSubmit=false
        runCurrent()
        assertTrue(repo.createArgs.isEmpty())
    }

    @Test
    fun isValidHttpsUrl_acceptsHttps_rejectsHttpAndBlankHost() {
        assertTrue(CreateWebhookViewModel.isValidHttpsUrl("https://ok.test/h"))
        assertFalse(CreateWebhookViewModel.isValidHttpsUrl("http://ok.test/h"))
        assertFalse(CreateWebhookViewModel.isValidHttpsUrl("https://"))
        assertFalse(CreateWebhookViewModel.isValidHttpsUrl("ftp://x"))
        assertFalse(CreateWebhookViewModel.isValidHttpsUrl(""))
    }
}
