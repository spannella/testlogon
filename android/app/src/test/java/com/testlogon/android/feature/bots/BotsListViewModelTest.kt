package com.testlogon.android.feature.bots

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.bots.Bot
import com.testlogon.android.data.bots.BotStatus
import com.testlogon.android.data.bots.BotTemplate
import com.testlogon.android.data.bots.AutoReplyRule
import com.testlogon.android.data.bots.AutoReplyMatchType
import com.testlogon.android.data.bots.TemplateCategory
import com.testlogon.android.data.bots.BotsRepository
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
class BotsListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun bot(
        id: String = "bot_1",
        name: String = "Bot",
        status: BotStatus = BotStatus.ACTIVE,
    ) = Bot(
        id = id,
        name = name,
        description = "desc",
        personality = "p",
        status = status,
        messageCount = 3,
        createdAtSeconds = 1_700_000_000L,
    )

    /**
     * Inline fake backing all bots VMs. Each load/mutation returns a configurable [ApiResult];
     * mutation calls are recorded so tests can assert exact args + reload behaviour.
     */
    private class FakeBotsRepository : BotsRepository {
        var botsResult: ApiResult<List<Bot>> = ApiResult.Success(emptyList())
        var cache: List<Bot>? = null
        var createResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var statusResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var loadBotsCount = 0
        var createArgs: Triple<String, String?, String?>? = null
        var statusArgs: Pair<String, BotStatus>? = null
        var deletedBotId: String? = null
        var clearCount = 0

        override suspend fun loadBots(): ApiResult<List<Bot>> {
            loadBotsCount++
            return botsResult
        }

        override suspend fun createBot(
            name: String,
            description: String?,
            personality: String?,
        ): ApiResult<Unit> {
            createArgs = Triple(name, description, personality)
            return createResult
        }

        override suspend fun updateBotStatus(botId: String, status: BotStatus): ApiResult<Unit> {
            statusArgs = botId to status
            return statusResult
        }

        override suspend fun deleteBot(botId: String): ApiResult<Unit> {
            deletedBotId = botId
            return deleteResult
        }

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

        override fun cachedBots(): List<Bot>? = cache

        override fun clear() {
            clearCount++
        }
    }

    // ---- Load ----

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Success(listOf(bot())) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        assertEquals(BotsPhase.Content, vm.uiState.value.phase)
        assertEquals(1, vm.uiState.value.bots.size)
    }

    @Test
    fun load_success_empty_movesToEmpty() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Success(emptyList()) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        assertEquals(BotsPhase.Empty, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.bots.isEmpty())
    }

    @Test
    fun load_failure500_movesToError() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Failure(ApiError(500, "boom")) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        assertEquals(BotsPhase.Error, vm.uiState.value.phase)
        assertEquals("boom", vm.uiState.value.errorMessage)
        assertFalse(vm.uiState.value.isStale)
    }

    @Test
    fun load_networkError_withCache_showsStaleContent() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cache = listOf(bot())
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        assertEquals(BotsPhase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
        assertEquals(1, vm.uiState.value.bots.size)
    }

    @Test
    fun load_networkError_noCache_movesToOffline() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cache = null
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        assertEquals(BotsPhase.Offline, vm.uiState.value.phase)
        assertFalse(vm.uiState.value.isStale)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Failure(ApiError(401, "nope")) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        assertEquals(BotsPhase.SessionExpired, vm.uiState.value.phase)
    }

    // ---- Create ----

    @Test
    fun openCreate_thenFields_buildsSubmittableForm() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Success(listOf(bot())) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()

        vm.onOpenCreate()
        assertTrue(vm.uiState.value.create.isOpen)
        assertFalse(vm.uiState.value.create.canSubmit)

        vm.onNameChange("Helper")
        vm.onDescriptionChange("d")
        vm.onPersonalityChange("friendly")
        assertTrue(vm.uiState.value.create.canSubmit)
    }

    @Test
    fun submitCreate_success_callsRepo_reloads_closesForm_andSnackbars() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.Success(listOf(bot()))
            createResult = ApiResult.Success(Unit)
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadBotsCount

        val effects = mutableListOf<BotsListEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenCreate()
        vm.onNameChange("Helper")
        vm.onDescriptionChange("d")
        vm.onPersonalityChange("friendly")
        vm.onSubmitCreate()
        advanceUntilIdle()
        job.cancel()

        assertEquals(Triple("Helper", "d", "friendly"), repo.createArgs)
        assertFalse(vm.uiState.value.create.isOpen)
        assertEquals(loadsBefore + 1, repo.loadBotsCount)
        assertTrue(effects.filterIsInstance<BotsListEffect.ShowMessage>().isNotEmpty())
    }

    @Test
    fun submitCreate_failure_keepsFormOpen_andSnackbars() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.Success(listOf(bot()))
            createResult = ApiResult.Failure(ApiError(500, "fail"))
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()

        val effects = mutableListOf<BotsListEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }

        vm.onOpenCreate()
        vm.onNameChange("Helper")
        vm.onSubmitCreate()
        advanceUntilIdle()
        job.cancel()

        assertTrue(vm.uiState.value.create.isOpen)
        assertFalse(vm.uiState.value.create.isSubmitting)
        assertTrue(effects.filterIsInstance<BotsListEffect.ShowMessage>().isNotEmpty())
    }

    // ---- Status toggle ----

    @Test
    fun toggleStatus_active_pausesViaRepo_andReloads() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.Success(listOf(bot(status = BotStatus.ACTIVE)))
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadBotsCount

        vm.onToggleStatus("bot_1")
        advanceUntilIdle()

        assertEquals("bot_1" to BotStatus.PAUSED, repo.statusArgs)
        assertEquals(loadsBefore + 1, repo.loadBotsCount)
        assertFalse(vm.uiState.value.isMutating)
    }

    @Test
    fun toggleStatus_paused_activatesViaRepo() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.Success(listOf(bot(status = BotStatus.PAUSED)))
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()

        vm.onToggleStatus("bot_1")
        advanceUntilIdle()

        assertEquals("bot_1" to BotStatus.ACTIVE, repo.statusArgs)
    }

    @Test
    fun toggleStatus_unknownBotId_isNoOp() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Success(listOf(bot())) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()

        vm.onToggleStatus("missing")
        advanceUntilIdle()

        assertNull(repo.statusArgs)
    }

    // ---- Delete ----

    @Test
    fun delete_success_callsRepoDelete_andReloads() = runTest {
        val repo = FakeBotsRepository().apply { botsResult = ApiResult.Success(listOf(bot())) }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()
        val loadsBefore = repo.loadBotsCount

        vm.onDelete("bot_1")
        advanceUntilIdle()

        assertEquals("bot_1", repo.deletedBotId)
        assertEquals(loadsBefore + 1, repo.loadBotsCount)
        assertFalse(vm.uiState.value.isMutating)
    }

    @Test
    fun delete_failure401_movesToSessionExpired() = runTest {
        val repo = FakeBotsRepository().apply {
            botsResult = ApiResult.Success(listOf(bot()))
            deleteResult = ApiResult.Failure(ApiError(401, "nope"))
        }
        val vm = BotsListViewModel(repo)
        advanceUntilIdle()

        vm.onDelete("bot_1")
        advanceUntilIdle()

        assertEquals(BotsPhase.SessionExpired, vm.uiState.value.phase)
    }
}
