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
class BotAutoReplyViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val botId = "bot_1"

    private fun handle() = SavedStateHandle(mapOf(BotsDest.ARG_BOT_ID to botId))

    private fun rule(
        id: String = "rule_1",
        trigger: String = "hello",
        response: String = "hi there",
        matchType: AutoReplyMatchType = AutoReplyMatchType.KEYWORD,
        priority: Int = 100,
        enabled: Boolean = true,
    ) = AutoReplyRule(
        id = id,
        triggerPattern = trigger,
        responseTemplate = response,
        matchType = matchType,
        priority = priority,
        enabled = enabled,
        matchCount = 2,
    )

    /** Captures the args of a create/update auto-reply call. */
    private data class RuleCall(
        val botId: String,
        val ruleId: String?,
        val trigger: String,
        val response: String,
        val matchType: AutoReplyMatchType,
        val priority: Int,
        val enabled: Boolean,
    )

    private class FakeBotsRepository : BotsRepository {
        var rulesResult: ApiResult<List<AutoReplyRule>> = ApiResult.Success(emptyList())
        var createResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var updateResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var loadRulesCount = 0
        var createCall: RuleCall? = null
        var updateCall: RuleCall? = null
        var deletedRule: Pair<String, String>? = null

        override suspend fun loadBots(): ApiResult<List<Bot>> = ApiResult.Success(emptyList())
        override suspend fun createBot(name: String, description: String?, personality: String?): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun updateBotStatus(botId: String, status: BotStatus): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun deleteBot(botId: String): ApiResult<Unit> = ApiResult.Success(Unit)

        override suspend fun loadAutoReplyRules(botId: String): ApiResult<List<AutoReplyRule>> {
            loadRulesCount++
            return rulesResult
        }

        override suspend fun createAutoReplyRule(
            botId: String,
            triggerPattern: String,
            responseTemplate: String,
            matchType: AutoReplyMatchType,
            priority: Int,
            enabled: Boolean,
        ): ApiResult<Unit> {
            createCall = RuleCall(botId, null, triggerPattern, responseTemplate, matchType, priority, enabled)
            return createResult
        }

        override suspend fun updateAutoReplyRule(
            botId: String,
            ruleId: String,
            triggerPattern: String,
            responseTemplate: String,
            matchType: AutoReplyMatchType,
            priority: Int,
            enabled: Boolean,
        ): ApiResult<Unit> {
            updateCall = RuleCall(botId, ruleId, triggerPattern, responseTemplate, matchType, priority, enabled)
            return updateResult
        }

        override suspend fun deleteAutoReplyRule(botId: String, ruleId: String): ApiResult<Unit> {
            deletedRule = botId to ruleId
            return deleteResult
        }

        override suspend fun loadTemplates(botId: String): ApiResult<List<BotTemplate>> =
            ApiResult.Success(emptyList())
        override suspend fun createTemplate(
            botId: String,
            name: String,
            text: String,
            category: TemplateCategory,
            bodyFormat: String,
        ): ApiResult<Unit> = ApiResult.Success(Unit)
        override suspend fun deleteTemplate(botId: String, templateId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override fun cachedBots(): List<Bot>? = null
        override fun clear() {}
    }

    // ---- Load ----

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Content, vm.uiState.value.phase)
        assertEquals(1, vm.uiState.value.rules.size)
    }

    @Test
    fun load_success_empty_movesToEmpty() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(emptyList()) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_movesToError() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Failure(ApiError(401, "nope")) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        assertEquals(BotsPhase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun load_usesBotIdFromSavedStateHandle() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        // create then assert the captured botId matches the nav arg
        vm.onOpenCreate()
        vm.onTriggerChange("t")
        vm.onResponseChange("r")
        vm.onSubmitForm()
        advanceUntilIdle()
        assertEquals(botId, repo.createCall?.botId)
    }

    // ---- Create ----

    @Test
    fun submitForm_create_passesFormValues_reloads_closesForm_andSnackbars() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        val loadsBefore = repo.loadRulesCount

        val effects = mutableListOf<AutoReplyEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenCreate()
        assertTrue(vm.uiState.value.form.isOpen)
        assertFalse(vm.uiState.value.form.isEditing)
        vm.onTriggerChange("buy")
        vm.onResponseChange("Sure!")
        vm.onMatchTypeChange(AutoReplyMatchType.CONTAINS)
        vm.onPriorityChange("50")
        vm.onEnabledChange(false)
        vm.onSubmitForm()
        advanceUntilIdle()
        job.cancel()

        assertEquals(
            RuleCall(botId, null, "buy", "Sure!", AutoReplyMatchType.CONTAINS, 50, false),
            repo.createCall,
        )
        assertNull(repo.updateCall)
        assertFalse(vm.uiState.value.form.isOpen)
        assertEquals(loadsBefore + 1, repo.loadRulesCount)
        assertTrue(effects.filterIsInstance<AutoReplyEffect.ShowMessage>().isNotEmpty())
    }

    @Test
    fun submitForm_blankFields_isNoOp() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenCreate()
        // response left blank -> canSubmit false
        vm.onTriggerChange("buy")
        assertFalse(vm.uiState.value.form.canSubmit)
        vm.onSubmitForm()
        advanceUntilIdle()

        assertNull(repo.createCall)
    }

    @Test
    fun priorityChange_stripsNonDigits_andBlankDefaultsTo100() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenCreate()
        vm.onPriorityChange("1a2b")
        assertEquals("12", vm.uiState.value.form.priority)

        vm.onTriggerChange("t")
        vm.onResponseChange("r")
        vm.onPriorityChange("")
        vm.onSubmitForm()
        advanceUntilIdle()
        assertEquals(100, repo.createCall?.priority)
    }

    // ---- Edit ----

    @Test
    fun openEdit_preFillsFormFromRule() = runTest {
        val existing = rule(
            id = "rule_9",
            trigger = "refund",
            response = "We will refund",
            matchType = AutoReplyMatchType.EXACT,
            priority = 7,
            enabled = false,
        )
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(existing)) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenEdit("rule_9")
        val form = vm.uiState.value.form
        assertTrue(form.isOpen)
        assertTrue(form.isEditing)
        assertEquals("rule_9", form.editingRuleId)
        assertEquals("refund", form.triggerPattern)
        assertEquals("We will refund", form.responseTemplate)
        assertEquals(AutoReplyMatchType.EXACT, form.matchType)
        assertEquals("7", form.priority)
        assertFalse(form.enabled)
    }

    @Test
    fun openEdit_unknownRuleId_isNoOp() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenEdit("missing")
        assertFalse(vm.uiState.value.form.isOpen)
    }

    @Test
    fun submitForm_edit_callsUpdate_withRuleId_andReloads() = runTest {
        val existing = rule(id = "rule_9", trigger = "refund", response = "old")
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(existing)) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        val loadsBefore = repo.loadRulesCount

        vm.onOpenEdit("rule_9")
        vm.onResponseChange("new response")
        vm.onSubmitForm()
        advanceUntilIdle()

        assertEquals("rule_9", repo.updateCall?.ruleId)
        assertEquals("new response", repo.updateCall?.response)
        assertNull(repo.createCall)
        assertFalse(vm.uiState.value.form.isOpen)
        assertEquals(loadsBefore + 1, repo.loadRulesCount)
    }

    @Test
    fun submitForm_failure_keepsFormOpen_clearsSubmitting() = runTest {
        val repo = FakeBotsRepository().apply {
            rulesResult = ApiResult.Success(listOf(rule()))
            createResult = ApiResult.Failure(ApiError(500, "fail"))
        }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()

        vm.onOpenCreate()
        vm.onTriggerChange("t")
        vm.onResponseChange("r")
        vm.onSubmitForm()
        advanceUntilIdle()

        assertTrue(vm.uiState.value.form.isOpen)
        assertFalse(vm.uiState.value.form.isSubmitting)
    }

    // ---- Delete ----

    @Test
    fun delete_success_callsRepo_andReloads() = runTest {
        val repo = FakeBotsRepository().apply { rulesResult = ApiResult.Success(listOf(rule())) }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()
        val loadsBefore = repo.loadRulesCount

        vm.onDelete("rule_1")
        advanceUntilIdle()

        assertEquals(botId to "rule_1", repo.deletedRule)
        assertEquals(loadsBefore + 1, repo.loadRulesCount)
        assertFalse(vm.uiState.value.isMutating)
    }

    @Test
    fun delete_failure_snackbars_andClearsMutating() = runTest {
        val repo = FakeBotsRepository().apply {
            rulesResult = ApiResult.Success(listOf(rule()))
            deleteResult = ApiResult.Failure(ApiError(500, "fail"))
        }
        val vm = BotAutoReplyViewModel(repo, handle())
        advanceUntilIdle()

        val effects = mutableListOf<AutoReplyEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onDelete("rule_1")
        advanceUntilIdle()
        job.cancel()

        assertTrue(effects.filterIsInstance<AutoReplyEffect.ShowMessage>().isNotEmpty())
        assertFalse(vm.uiState.value.isMutating)
    }
}
