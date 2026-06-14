package com.testlogon.android.feature.blocking

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockRelationship
import com.testlogon.android.core.model.blocking.BlockedUser
import com.testlogon.android.core.ui.safety.GuardPhase
import com.testlogon.android.data.blocking.BlockingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-388 - [BlockActionDelegate] forwards to [BlockingRepository], routes the staged action through
 * the shared guard, and treats re-block as benign (TC-AND-388-13; AC-2/AC-4, FR-4/FR-6).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BlockActionDelegateTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    /** Recording fake; records the call BEFORE returning, distinct helper names. */
    private class FakeBlockingRepo : BlockingRepository {
        private val ids = MutableStateFlow<Set<String>>(emptySet())
        override val blockedUserIds: StateFlow<Set<String>> = ids

        var blockResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var unblockResult: ApiResult<Unit> = ApiResult.Success(Unit)
        val blockCalls = mutableListOf<String>()
        val unblockCalls = mutableListOf<String>()

        override suspend fun block(userId: String): ApiResult<Unit> {
            blockCalls += userId
            if (blockResult is ApiResult.Success) ids.update { it + userId }
            return blockResult
        }

        override suspend fun unblock(userId: String): ApiResult<Unit> {
            unblockCalls += userId
            if (unblockResult is ApiResult.Success) ids.update { it - userId }
            return unblockResult
        }

        override suspend fun refreshBlockList(): ApiResult<List<BlockedUser>> =
            ApiResult.Success(emptyList())

        override suspend fun blockStatus(userId: String): ApiResult<BlockRelationship> =
            ApiResult.Success(BlockRelationship.Normal)

        override fun isBlocked(userId: String): Boolean = userId in ids.value

        override fun clear() = ids.update { emptySet() }
    }

    @Test
    fun directBlock_andUnblock_forwardToRepository() = runTest {
        val repo = FakeBlockingRepo()
        val delegate = BlockActionDelegate(repo)

        assertTrue(delegate.block("usr_x") is ApiResult.Success)
        assertTrue(delegate.unblock("usr_x") is ApiResult.Success)

        assertEquals(listOf("usr_x"), repo.blockCalls)
        assertEquals(listOf("usr_x"), repo.unblockCalls)
    }

    @Test
    fun reBlock_isBenign_anySuccessForwarded() = runTest {
        val repo = FakeBlockingRepo()
        val delegate = BlockActionDelegate(repo)

        assertTrue(delegate.block("usr_x") is ApiResult.Success)
        // Re-block of an already-blocked user is benign (repository maps any 200 -> Success).
        assertTrue(delegate.block("usr_x") is ApiResult.Success)
        assertEquals(listOf("usr_x", "usr_x"), repo.blockCalls)
    }

    @Test
    fun requestThenConfirm_routesBlockThroughGuard() = runTest {
        val repo = FakeBlockingRepo()
        val delegate = BlockActionDelegate(repo)

        assertEquals(GuardPhase.Idle, delegate.guard.phase.value)
        delegate.requestBlock("usr_x")
        assertTrue(delegate.guard.phase.value is GuardPhase.Confirming)

        val result = delegate.confirm()
        assertTrue(result is ApiResult.Success)
        assertTrue(delegate.guard.phase.value is GuardPhase.Submitting)
        assertEquals(listOf("usr_x"), repo.blockCalls)
    }

    @Test
    fun doubleConfirm_submitsExactlyOnce() = runTest {
        val repo = FakeBlockingRepo()
        val delegate = BlockActionDelegate(repo)
        delegate.requestUnblock("usr_x")

        val first = delegate.confirm()
        val second = delegate.confirm()

        assertTrue(first is ApiResult.Success)
        // Re-entrancy guard: a second confirm while Submitting is a no-op.
        assertNull(second)
        assertEquals(listOf("usr_x"), repo.unblockCalls)
    }

    @Test
    fun confirmFromIdle_isNoOp() = runTest {
        val repo = FakeBlockingRepo()
        val delegate = BlockActionDelegate(repo)

        assertNull(delegate.confirm())
        assertTrue(repo.blockCalls.isEmpty())
        assertTrue(repo.unblockCalls.isEmpty())
    }

    @Test
    fun cancel_unwindsConfirming() = runTest {
        val repo = FakeBlockingRepo()
        val delegate = BlockActionDelegate(repo)
        delegate.requestBlock("usr_x")
        assertTrue(delegate.guard.phase.value is GuardPhase.Confirming)

        delegate.cancel()
        assertEquals(GuardPhase.Idle, delegate.guard.phase.value)
        assertTrue(repo.blockCalls.isEmpty())
    }

    @Test
    fun confirm_failurePropagates() = runTest {
        val repo = FakeBlockingRepo().apply { blockResult = ApiResult.Failure(ApiError(500, "x")) }
        val delegate = BlockActionDelegate(repo)
        delegate.requestBlock("usr_x")

        val result = delegate.confirm()
        assertTrue(result is ApiResult.Failure)
        assertEquals(listOf("usr_x"), repo.blockCalls)
    }
}
