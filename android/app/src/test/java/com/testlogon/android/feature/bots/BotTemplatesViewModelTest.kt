package com.testlogon.android.feature.bots

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bots.AutoReplyMatchType
import com.testlogon.android.data.bots.AutoReplyRule
import com.testlogon.android.data.bots.Bot
import com.testlogon.android.data.bots.BotStatus
import com.testlogon.android.data.bots.BotTemplate
import com.testlogon.android.data.bots.BotsRepository
import com.testlogon.android.data.bots.TemplateCategory
import com.testlogon.android.navigation.BotsDest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class BotTemplatesViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val botId = "bot_1"

    private fun handle() = SavedStateHandle(mapOf(BotsDest.ARG_BOT_ID to botId))

    private fun template(
        id: String = "tpl_1",
        name: String = "Welcome",
        text: String = "Hi!",
        category: TemplateCategory = TemplateCategory.GREETING,
        bodyFormat: String = "plain",
    ) = BotTemplate(
        id = id,
        name = name,
        text = text,
        category = category,
        bodyFormat = bodyFormat,
    )

    /** Captures the args of a createTemplate call. */
    private data class TemplateCall(
        val botId: String,
        val name: String,
        val text: String,
        val category: TemplateCategory,
        val bodyFormat: String,
    )

    private class FakeBotsRepository : BotsRepository {
        var templatesResult: ApiResult<List<BotTemplate>> = ApiResult.Success(emptyList())
        var createResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var loadTemplatesCount = 0
        var createCall: TemplateCall? = null
        var deletedTemplate: Pair<String, String>? = null

        override suspend fun loadBots(): ApiResult<List<Bot>> = ApiResult.Success(emptyList())
        override suspend fun createBot(name: String, description: String?, personality: String?): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun updateBotStatus(botId: String, status: BotStatus): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun deleteBot(botId: String): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun loadAutoReplyRules(botId: String): ApiResult<List<AutoReplyRule>> =
            ApiResult.Success(emptyList())
        override suspend fun createAutoReplyRule(
            botId: String,
            triggerPattern: String,
            responseTemplate: String,
            matchType: AutoReplyMatchType,
            priority: Int,
            enabled: Boolean,
        ): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun updateAutoReplyRule(
            botId: String,
            ruleId: String,
            triggerPattern: String,
            responseTemplate: String,
            matchType: AutoReplyMatchType,
            priority: Int,
            enabled: Boolean,
        ): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun deleteAutoReplyRule(botId: String, ruleId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)

        override suspend fun loadTemplates(botId: String): ApiResult<List<BotTemplate>> {
            loadTemplatesCount++
            return templatesResult
        }

        override suspend fun createTemplate(
            botId: String,
            name: String,
            text: String,
            category: TemplateCategory,
            bodyFormat: String,
        ): ApiResult<Unit> {
            createCall = TemplateCall(botId, name, text, category, bodyFormat)
            return createResult
        }

        override suspend fun deleteTemplate(botId: String, templateId: String): ApiResult<Unit> {
            deletedTemplate = botId to templateId
            return deleteResult
        }

        override fun cachedBots(): List<Bot>? = null
        override fun clear() {}
    }

    // ---- Load ----

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Success(listOf(template())) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Content, vm.uiState.value.phase)
        assertEquals(1, vm.uiState.value.templates.size)
    }

    @Test
    fun load_success_empty_movesToEmpty() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Success(emptyList()) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_movesToError() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Failure(ApiError(401, "nope")) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun load_networkError_movesToOffline() = runTest {
        val repo = FakeBotsRepository().apply {
            templatesResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Offline, vm.uiState.value.phase)
    }

    // ---- Create ----

    @Test
    fun openCreate_thenFields_buildsSubmittableForm() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Success(listOf(template())) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenCreate()
        assertTrue(vm.uiState.value.form.isOpen)
        assertFalse(vm.uiState.value.form.canSubmit)
        vm.onNameChange("Away")
        vm.onTextChange("Back soon")
        assertTrue(vm.uiState.value.form.canSubmit)
    }

    @Test
    fun submitForm_create_passesValues_withDefaultBodyFormat_reloads_andSnackbars() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Success(listOf(template())) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        val loadsBefore = repo.loadTemplatesCount

        val effects = mutableListOf<TemplatesEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenCreate()
        vm.onNameChange("Away")
        vm.onTextChange("Back soon")
        vm.onCategoryChange(TemplateCategory.AWAY)
        vm.onSubmitForm()
        advanceUntilIdle()
        job.cancel()

        assertEquals(
            TemplateCall(botId, "Away", "Back soon", TemplateCategory.AWAY, "plain"),
            repo.createCall,
        )
        assertFalse(vm.uiState.value.form.isOpen)
        assertEquals(loadsBefore + 1, repo.loadTemplatesCount)
        assertTrue(effects.filterIsInstance<TemplatesEffect.ShowMessage>().isNotEmpty())
    }

    @Test
    fun submitForm_blankFields_isNoOp() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Success(listOf(template())) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenCreate()
        vm.onNameChange("Away") // text still blank
        assertFalse(vm.uiState.value.form.canSubmit)
        vm.onSubmitForm()
        advanceUntilIdle()

        assertNull(repo.createCall)
    }

    @Test
    fun submitForm_failure_keepsFormOpen_clearsSubmitting() = runTest {
        val repo = FakeBotsRepository().apply {
            templatesResult = ApiResult.Success(listOf(template()))
            createResult = ApiResult.Failure(ApiError(500, "fail"))
        }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenCreate()
        vm.onNameChange("Away")
        vm.onTextChange("Back soon")
        vm.onSubmitForm()
        advanceUntilIdle()

        assertTrue(vm.uiState.value.form.isOpen)
        assertFalse(vm.uiState.value.form.isSubmitting)
    }

    // ---- Delete ----

    @Test
    fun delete_success_callsRepo_andReloads() = runTest {
        val repo = FakeBotsRepository().apply { templatesResult = ApiResult.Success(listOf(template())) }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()
        val loadsBefore = repo.loadTemplatesCount

        vm.onDelete("tpl_1")
        advanceUntilIdle()

        assertEquals(botId to "tpl_1", repo.deletedTemplate)
        assertEquals(loadsBefore + 1, repo.loadTemplatesCount)
        assertFalse(vm.uiState.value.isMutating)
    }

    @Test
    fun delete_failure401_movesToSessionExpired() = runTest {
        val repo = FakeBotsRepository().apply {
            templatesResult = ApiResult.Success(listOf(template()))
            deleteResult = ApiResult.Failure(ApiError(401, "nope"))
        }
        val vm = BotTemplatesViewModel(repo, handle())
        advanceUntilIdle()

        vm.onDelete("tpl_1")
        advanceUntilIdle()

        assertEquals(BotsPhase.SessionExpired, vm.uiState.value.phase)
    }
}
