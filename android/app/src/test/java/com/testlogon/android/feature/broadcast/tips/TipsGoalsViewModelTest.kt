package com.testlogon.android.feature.broadcast.tips

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.chat.BroadcastChatRepository
import com.testlogon.android.data.broadcast.chat.ChatMessage
import com.testlogon.android.data.broadcast.chat.ChatStreamSignal
import com.testlogon.android.data.broadcast.tips.Goal
import com.testlogon.android.data.broadcast.tips.TipMessage
import com.testlogon.android.data.broadcast.tips.TipsRepository
import com.testlogon.android.data.broadcast.tips.TipsSummary
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class TipsGoalsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val summary = MutableStateFlow<TipsSummary?>(null)
    private val goals = MutableStateFlow<List<Goal>>(emptyList())

    /** Records submit calls so the test can assert NO POST happened when payments are unavailable. */
    private class FakeTipsRepository(
        private val summary: MutableStateFlow<TipsSummary?>,
        private val goals: MutableStateFlow<List<Goal>>,
    ) : TipsRepository {
        var submitCount = 0
        var refreshCount = 0
        var submitResult: ApiResult<TipMessage> =
            ApiResult.Success(TipMessage("m1", 2500, "USD", 5000, null, 1))

        override fun observeTipsSummary(): Flow<TipsSummary?> = summary
        override fun observeGoals(): Flow<List<Goal>> = goals
        override suspend fun refresh(sessionId: String): ApiResult<Unit> {
            refreshCount++
            return ApiResult.Success(Unit)
        }
        override suspend fun submitTip(
            sessionId: String,
            amountCents: Long,
            paymentMethodId: String,
            text: String?,
            currency: String,
        ): ApiResult<TipMessage> {
            submitCount++
            return submitResult
        }
    }

    private class FakeChatRepository : BroadcastChatRepository {
        override fun chatEvents(sessionId: String): Flow<ChatStreamSignal> = emptyFlow()
        override suspend fun loadHistory(sessionId: String, limit: Int): ApiResult<List<ChatMessage>> =
            ApiResult.Success(emptyList())
        override suspend fun send(
            sessionId: String,
            text: String?,
            options: com.testlogon.android.data.broadcast.chat.ChatComposeOptions,
            imageUrl: String?,
            videoUrl: String?,
            thumbnailUrl: String?,
        ): ApiResult<ChatMessage> = error("unused")
        override suspend fun reactToMessage(
            sessionId: String,
            messageId: String,
            emoji: String,
            action: String,
        ): ApiResult<Map<String, Int>> = ApiResult.Success(emptyMap())
        override suspend fun unlock(sessionId: String, messageId: String, paymentMethodId: String): ApiResult<ChatMessage?> =
            ApiResult.Success(null)
        override suspend fun consumeView(sessionId: String, messageId: String): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun uploadImage(localUri: String): ApiResult<String> = ApiResult.Success("")
        override suspend fun uploadVideo(localUri: String): ApiResult<com.testlogon.android.data.broadcast.chat.BroadcastVideoUpload> =
            ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 0, message = "not exercised"))
        override fun selfId(): String? = "self"
    }

    private class FakeBilling(private val result: BillingResult) : BillingAuthorizer {
        override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult =
            result
    }

    private fun vm(billing: BillingAuthorizer, repo: FakeTipsRepository): TipsGoalsViewModel =
        TipsGoalsViewModel(
            sessionId = "s1",
            repo = repo,
            chatRepo = FakeChatRepository(),
            billing = billing,
        )

    @Test
    fun notConfigured_neverCharges_surfacesPaymentsUnavailable() = runTest {
        val repo = FakeTipsRepository(summary, goals)
        val viewModel = vm(FakeBilling(BillingResult.NotConfigured), repo)
        val effects = mutableListOf<TipsEffect>()
        val job = launch { viewModel.effects.collect { effects += it } }
        advanceUntilIdle()

        viewModel.submitTip(2500, "thanks")
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(TipsEffect.PaymentsUnavailable), effects)
        // The stub never charges: NO tip POST is made.
        assertEquals(0, repo.submitCount)
    }

    @Test
    fun authorized_postsOnce_thenRefreshes_emitsSent() = runTest {
        val repo = FakeTipsRepository(summary, goals)
        val viewModel = vm(FakeBilling(BillingResult.Authorized("pm_1", 2500)), repo)
        val effects = mutableListOf<TipsEffect>()
        val job = launch { viewModel.effects.collect { effects += it } }
        advanceUntilIdle()
        val refreshAtStart = repo.refreshCount

        viewModel.submitTip(2500, "thanks")
        advanceUntilIdle()
        job.cancel()

        assertEquals(listOf(TipsEffect.TipSent), effects)
        assertEquals(1, repo.submitCount)
        // One additional refresh after a successful tip (reconcile summary/goals).
        assertTrue(repo.refreshCount > refreshAtStart)
    }

    @Test
    fun amountBelowMin_failsValidation_noCharge() = runTest {
        val repo = FakeTipsRepository(summary, goals)
        val viewModel = vm(FakeBilling(BillingResult.Authorized("pm_1", 99)), repo)
        val effects = mutableListOf<TipsEffect>()
        val job = launch { viewModel.effects.collect { effects += it } }
        advanceUntilIdle()

        viewModel.submitTip(99, null)
        advanceUntilIdle()
        job.cancel()

        assertTrue(effects.single() is TipsEffect.TipFailed)
        assertEquals(0, repo.submitCount)
    }

    @Test
    fun submitFailure_emitsTipFailed() = runTest {
        val repo = FakeTipsRepository(summary, goals).apply {
            submitResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val viewModel = vm(FakeBilling(BillingResult.Authorized("pm_1", 2500)), repo)
        val effects = mutableListOf<TipsEffect>()
        val job = launch { viewModel.effects.collect { effects += it } }
        advanceUntilIdle()

        viewModel.submitTip(2500, null)
        advanceUntilIdle()
        job.cancel()

        val effect = effects.single()
        assertTrue(effect is TipsEffect.TipFailed)
        assertEquals("boom", (effect as TipsEffect.TipFailed).message)
        assertEquals(1, repo.submitCount)
    }

    @Test
    fun uiState_combinesSummaryAndGoals() = runTest {
        val repo = FakeTipsRepository(summary, goals)
        val viewModel = vm(FakeBilling(BillingResult.NotConfigured), repo)
        advanceUntilIdle()

        summary.value = TipsSummary("s1", totalCents = 1250, tipCount = 3)
        goals.value = listOf(Goal("g1", "s1", "mic", 500, 1000, false, null, 0))
        advanceUntilIdle()

        val state = viewModel.uiState.value
        assertEquals(1250L, state.summary?.totalCents)
        assertEquals(1, state.goals.size)
    }
}
