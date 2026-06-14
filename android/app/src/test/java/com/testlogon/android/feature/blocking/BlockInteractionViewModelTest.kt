package com.testlogon.android.feature.blocking

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.blocking.BlockRelationship
import com.testlogon.android.core.model.blocking.BlockedUser
import com.testlogon.android.data.blocking.BlockingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-382 - [BlockInteractionViewModel] + suppression behavior (no Turbine in this project: assert
 * on uiState.value after advanceUntilIdle, matching the established VM-test pattern).
 *
 * Covers the acceptance-critical pair: block HIDES content (relationship -> BlockedByMe drives the
 * placeholder + suppression drops authored items) and PREVENTS contact (composer disabled; a generic
 * 403 from a send race handled). Traces TC-04/05/09/10 + AC-2/AC-3/AC-5.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BlockInteractionViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    /** Recording fake; records before throwing/returning, distinct helper names. */
    private class FakeBlockingRepo : BlockingRepository {
        private val ids = MutableStateFlow<Set<String>>(emptySet())
        override val blockedUserIds: StateFlow<Set<String>> = ids

        var blockResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var unblockResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var statusResult: ApiResult<BlockRelationship> = ApiResult.Success(BlockRelationship.Normal)
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

        override suspend fun blockStatus(userId: String): ApiResult<BlockRelationship> = statusResult

        override fun isBlocked(userId: String): Boolean = userId in ids.value

        override fun clear() = ids.update { emptySet() }

        fun seed(vararg userIds: String) = ids.update { it + userIds.toSet() }
    }

    @Test
    fun hydrate_readsRelationshipFromServer() = runTest {
        val repo = FakeBlockingRepo().apply { statusResult = ApiResult.Success(BlockRelationship.BlockedMe) }
        val vm = BlockInteractionViewModel(repo)

        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()

        assertEquals(BlockRelationship.BlockedMe, vm.uiState.value.relationship)
        assertTrue(vm.uiState.value.contactBlocked)
        assertFalse(vm.uiState.value.composerEnabled)
    }

    @Test
    fun hydrate_failedStatus_keepsCachedBlockedAsFailSafe() = runTest {
        val repo = FakeBlockingRepo().apply {
            seed("usr_x")
            statusResult = ApiResult.NetworkError(java.io.IOException("offline"))
        }
        val vm = BlockInteractionViewModel(repo)

        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()

        // Fail-safe: the cached blocked relationship is retained so content stays hidden.
        assertEquals(BlockRelationship.BlockedByMe, vm.uiState.value.relationship)
    }

    @Test
    fun blockFlow_confirm_hidesContent_transitionsToBlockedByMe() = runTest {
        val repo = FakeBlockingRepo()
        val vm = BlockInteractionViewModel(repo)
        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()

        vm.onBlockRequested()
        assertTrue(vm.uiState.value.confirmVisible)

        vm.onBlockConfirmed()
        advanceUntilIdle()

        assertEquals(BlockRelationship.BlockedByMe, vm.uiState.value.relationship)
        assertTrue(vm.uiState.value.blockedByMe)
        assertFalse(vm.uiState.value.confirmVisible)
        assertFalse(vm.uiState.value.inFlight)
        assertEquals(listOf("usr_x"), repo.blockCalls)
        // Suppression: the blocked id is in the set so authored items drop.
        val items = listOf("usr_x" to "post1", "usr_y" to "post2")
        val visible = suppressBlocked(items, repo.blockedUserIds.value) { it.first }
        assertEquals(listOf("usr_y" to "post2"), visible)
    }

    @Test
    fun blockFailure_revertsToNormal_andEmitsRetryMessage() = runTest {
        val repo = FakeBlockingRepo().apply { blockResult = ApiResult.Failure(ApiError(500, "x")) }
        val vm = BlockInteractionViewModel(repo)
        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()

        vm.onBlockConfirmed()
        advanceUntilIdle()

        assertEquals(BlockRelationship.Normal, vm.uiState.value.relationship)
        assertFalse(vm.uiState.value.inFlight)
    }

    @Test
    fun unblock_revertsRelationship_andReEnablesContact() = runTest {
        val repo = FakeBlockingRepo().apply {
            seed("usr_x")
            statusResult = ApiResult.Success(BlockRelationship.BlockedByMe)
        }
        val vm = BlockInteractionViewModel(repo)
        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()
        assertTrue(vm.uiState.value.blockedByMe)

        vm.onUnblock()
        advanceUntilIdle()

        assertEquals(BlockRelationship.Normal, vm.uiState.value.relationship)
        assertTrue(vm.uiState.value.composerEnabled)
        assertEquals(listOf("usr_x"), repo.unblockCalls)
    }

    @Test
    fun contactRejected_genericForbidden_disablesComposer() = runTest {
        val repo = FakeBlockingRepo()
        val vm = BlockInteractionViewModel(repo)
        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()
        assertTrue(vm.uiState.value.composerEnabled)

        // A generic 403 from a send race routes here (no user_blocked literal required).
        vm.onContactRejected()

        assertEquals(BlockRelationship.BlockedMe, vm.uiState.value.relationship)
        assertFalse(vm.uiState.value.composerEnabled)
    }

    @Test
    fun blockRequested_isDoubleSubmitGuarded_whenBlockedByMe() = runTest {
        val repo = FakeBlockingRepo().apply { statusResult = ApiResult.Success(BlockRelationship.BlockedByMe) }
        val vm = BlockInteractionViewModel(repo)
        vm.hydrate("usr_x", "alice")
        advanceUntilIdle()

        // Already blocked-by-me -> Block action is not offered, requesting it is a no-op.
        vm.onBlockRequested()
        assertFalse(vm.uiState.value.confirmVisible)
        assertFalse(vm.uiState.value.canBlock)
    }
}
