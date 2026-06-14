package com.testlogon.android.feature.broadcast.tipsconfig

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.BroadcastMonetizationRepository
import com.testlogon.android.data.broadcast.PrivateShowRequest
import com.testlogon.android.data.broadcast.PrivateShowSession
import com.testlogon.android.data.broadcast.PrivateShowSummary
import com.testlogon.android.data.broadcast.PrivateStatus
import com.testlogon.android.data.broadcast.TipConfig
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-315 — unit tests for [TipsConfigViewModel] (MainDispatcherRule + runCurrent; NO poll loop on this
 * surface). Covers load -> edit -> save (PATCH reflected), client validation blocking save (min>max +
 * out-of-bounds cents) with field errors, and a 422 save failure mapping to a saveError.
 */
class TipsConfigViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** Configurable fake monetization repo (only the tip-config methods matter here). */
    private class FakeRepo : BroadcastMonetizationRepository {
        var getResult: ApiResult<TipConfig> = ApiResult.Success(TipConfig(true, 100, 5_000))
        var saveResult: ApiResult<TipConfig> = ApiResult.Success(TipConfig(true, 200, 6_000))
        var saveCalls = 0
        var lastSaveMin: Long? = null
        var lastSaveMax: Long? = null

        override suspend fun getSessionTipConfig(sessionId: String): ApiResult<TipConfig> = getResult
        override suspend fun saveTipConfig(
            sessionId: String,
            enabled: Boolean?,
            minCents: Long?,
            maxCents: Long?,
        ): ApiResult<TipConfig> {
            saveCalls++
            lastSaveMin = minCents
            lastSaveMax = maxCents
            return saveResult
        }

        // Unused by these tests.
        override suspend fun listPrivateRequests(sessionId: String): ApiResult<List<PrivateShowRequest>> =
            ApiResult.Success(emptyList())
        override suspend fun getPrivateStatus(sessionId: String): ApiResult<PrivateStatus> =
            ApiResult.Success(PrivateStatus("idle", null, null, null, null, null, null, null, null, null))
        override suspend fun acceptPrivateRequest(
            sessionId: String,
            requestId: String,
            behavior: String,
        ): ApiResult<PrivateShowSession> =
            ApiResult.Success(PrivateShowSession("", "", "", null, null, 0, null))
        override suspend fun declinePrivateRequest(sessionId: String, requestId: String): ApiResult<Unit> =
            ApiResult.Success(Unit)
        override suspend fun endPrivateSession(
            sessionId: String,
            privateSessionId: String,
        ): ApiResult<PrivateShowSummary> =
            ApiResult.Success(PrivateShowSummary("", "", "", 0, 0, null))
    }

    private fun vm(repo: BroadcastMonetizationRepository, sessionId: String? = SESSION): TipsConfigViewModel {
        val saved = SavedStateHandle(
            if (sessionId != null) mapOf(TipsConfigViewModel.ARG_SESSION_ID to sessionId) else emptyMap(),
        )
        return TipsConfigViewModel(saved, repo)
    }

    @Test
    fun load_thenEdit_thenSave_reflectsPersisted() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()

        val loaded = vm.uiState.value as TipsConfigUiState.Editing
        assertTrue(loaded.enabled)
        assertEquals("1.00", loaded.minDollars)
        assertEquals("50.00", loaded.maxDollars)
        assertFalse(loaded.dirty)

        vm.onMinChange("2.00")
        vm.onMaxChange("60.00")
        runCurrent()
        val edited = vm.uiState.value as TipsConfigUiState.Editing
        assertTrue(edited.dirty)
        assertTrue(edited.canSave)

        repo.saveResult = ApiResult.Success(TipConfig(true, 200, 6_000))
        vm.onSave()
        runCurrent()

        assertEquals(1, repo.saveCalls)
        assertEquals(200L, repo.lastSaveMin)
        assertEquals(6_000L, repo.lastSaveMax)
        val saved = vm.uiState.value as TipsConfigUiState.Editing
        assertEquals("2.00", saved.minDollars)
        assertEquals("60.00", saved.maxDollars)
        assertFalse(saved.dirty)
    }

    @Test
    fun validation_minGreaterThanMax_blocksSave_withFieldError() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()

        vm.onMinChange("100.00")
        vm.onMaxChange("5.00")
        runCurrent()
        vm.onSave()
        runCurrent()

        assertEquals(0, repo.saveCalls)
        val state = vm.uiState.value as TipsConfigUiState.Editing
        assertEquals(TipFieldError.MIN_GREATER_THAN_MAX, state.fieldErrors[TipField.MAX])
    }

    @Test
    fun validation_outOfBoundsCents_blocksSave() = runTest {
        val repo = FakeRepo()
        val vm = vm(repo)
        runCurrent()

        // $0.50 -> 50 cents, below the 100-cent floor.
        vm.onMinChange("0.50")
        vm.onMaxChange("50.00")
        runCurrent()
        vm.onSave()
        runCurrent()

        assertEquals(0, repo.saveCalls)
        val state = vm.uiState.value as TipsConfigUiState.Editing
        assertEquals(TipFieldError.OUT_OF_RANGE, state.fieldErrors[TipField.MIN])
    }

    @Test
    fun save_422_mapsToSaveError() = runTest {
        val repo = FakeRepo()
        repo.saveResult = ApiResult.Failure(ApiError(422, "too small"))
        val vm = vm(repo)
        runCurrent()

        vm.onMinChange("2.00")
        runCurrent()
        vm.onSave()
        runCurrent()

        val state = vm.uiState.value as TipsConfigUiState.Editing
        assertEquals("too small", state.saveError)
    }

    @Test
    fun disabledTips_allowsSaveWithoutBoundValidation() = runTest {
        val repo = FakeRepo()
        repo.saveResult = ApiResult.Success(TipConfig(false, 100, 5_000))
        val vm = vm(repo)
        runCurrent()

        vm.onEnabledChange(false)
        runCurrent()
        vm.onSave()
        runCurrent()

        assertEquals(1, repo.saveCalls)
    }

    private companion object {
        const val SESSION = "bcs_1"
    }
}
