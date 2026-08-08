package com.testlogon.android.feature.sessions

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.SessionInfo
import com.testlogon.android.data.auth.SessionsRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class ActiveSessionsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo : SessionsRepository {
        var listResult: ApiResult<List<SessionInfo>> = ApiResult.Success(emptyList())
        var revokeResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var revokeOthersResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var current: String? = null
        var revokeCalls = 0
        var revokeOthersCalls = 0
        var cached: List<SessionInfo>? = null
        override suspend fun listSessions() = listResult
        override suspend fun revoke(sessionId: String): ApiResult<Unit> { revokeCalls++; return revokeResult }
        override suspend fun revokeOthers(): ApiResult<Unit> { revokeOthersCalls++; return revokeOthersResult }
        override fun currentSessionId() = current
        override fun cachedSessions(): List<SessionInfo>? = cached
    }

    private fun info(id: String, current: Boolean = false, lastSeen: Long = 0L) = SessionInfo(
        sessionId = id, isCurrentWire = current, createdAtWire = 0L, lastSeenAtWire = lastSeen,
        ipWire = "1.2.3.4", userAgentWire = "ua-$id", revoked = false, revokedAt = null,
    )

    private fun vm(repo: FakeRepo) = ActiveSessionsViewModel(repo)

    @Test
    fun load_marksExactlyOneCurrent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("a"), info("b", current = true), info("c")))
        val vm = vm(repo)
        advanceUntilIdle()
        assertEquals(1, vm.state.value.rows.count { it.isCurrent })
        assertTrue(vm.state.value.rows.first().isCurrent) // pinned to top
    }

    @Test
    fun load_fallbackToGetMeSessionId() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.current = "b"
        repo.listResult = ApiResult.Success(listOf(info("a"), info("b"), info("c")))
        val vm = vm(repo)
        advanceUntilIdle()
        val rows = vm.state.value.rows
        assertEquals(1, rows.count { it.isCurrent })
        assertTrue(rows.first { it.info.sessionId == "b" }.isCurrent)
    }

    @Test
    fun revokeOthers_disabled_whenNoCurrentResolved() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("a"), info("b")))
        val vm = vm(repo)
        advanceUntilIdle()
        assertFalse(vm.state.value.canRevokeOthers)
        vm.requestRevokeOthers()
        assertEquals(null, vm.state.value.confirm)
    }

    @Test
    fun revokeOne_optimisticRemove_staysRemovedOnSuccess() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("cur", current = true), info("a"), info("b")))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.requestRevoke("a")
        assertEquals(ConfirmTarget.RevokeOne("a"), vm.state.value.confirm)
        vm.confirm()
        advanceUntilIdle()
        assertTrue(vm.state.value.rows.none { it.info.sessionId == "a" })
        assertEquals(1, repo.revokeCalls)
    }

    @Test
    fun revokeOne_rollsBackOnFailure() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("cur", current = true), info("a"), info("b")))
        repo.revokeResult = ApiResult.Failure(ApiError(500, "boom"))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.requestRevoke("a")
        vm.confirm()
        advanceUntilIdle()
        assertTrue(vm.state.value.rows.any { it.info.sessionId == "a" })
        assertEquals("boom", vm.state.value.error)
    }

    @Test
    fun revokeOthers_removesAllNonCurrent() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("cur", current = true), info("a"), info("b")))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.requestRevokeOthers()
        vm.confirm()
        advanceUntilIdle()
        assertEquals(listOf("cur"), vm.state.value.rows.map { it.info.sessionId })
        assertEquals(1, repo.revokeOthersCalls)
    }

    @Test
    fun confirm_required_noApiCallWithoutConfirm() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("cur", current = true), info("a")))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.requestRevoke("a")
        vm.dismissConfirm()
        advanceUntilIdle()
        assertEquals(0, repo.revokeCalls)
        assertTrue(vm.state.value.rows.any { it.info.sessionId == "a" })
    }

    @Test
    fun failedFetch_withCache_servesStaleRows_noError() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.cached = listOf(info("cur", current = true), info("a"))
        repo.listResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        val vm = vm(repo)
        advanceUntilIdle()
        val s = vm.state.value
        assertTrue(s.isStale)
        assertEquals(null, s.error)
        assertEquals(2, s.rows.size)
    }

    @Test
    fun failedFetch_noCache_surfacesError() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.cached = null
        repo.listResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
        val vm = vm(repo)
        advanceUntilIdle()
        val s = vm.state.value
        assertFalse(s.isStale)
        assertTrue(s.error != null)
        assertTrue(s.rows.isEmpty())
    }

    @Test
    fun currentRow_cannotBeSingleRevoked() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        repo.listResult = ApiResult.Success(listOf(info("cur", current = true), info("a")))
        val vm = vm(repo)
        advanceUntilIdle()
        vm.requestRevoke("cur")
        assertEquals(null, vm.state.value.confirm)
    }
}
