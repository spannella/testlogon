package com.testlogon.android.feature.delegates

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.delegates.DelegationStateStore
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.delegates.ManagingCreator
import com.testlogon.android.core.network.delegates.ManagedCreatorOut
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.delegates.data.DelegateBroadcastRepository
import com.testlogon.android.feature.delegates.data.DelegateFeedRepository
import com.testlogon.android.feature.delegates.data.DelegateMessagingRepository
import com.testlogon.android.feature.delegates.data.DelegationContextProvider
import com.testlogon.android.feature.delegates.data.DelegationRepositoryImpl
import com.testlogon.android.feature.delegates.testing.FakeDelegateBroadcastApi
import com.testlogon.android.feature.delegates.testing.FakeDelegateFeedApi
import com.testlogon.android.feature.delegates.testing.FakeDelegateMessagingApi
import com.testlogon.android.feature.delegates.testing.FakeDelegatesApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-360 - unit tests for the delegate-PATH overlay repositories + the [DelegationContextProvider].
 *
 * Covers: an action whose permission is ABSENT returns PermissionDenied and the delegate API is NOT called;
 * a permitted action with an active creator calls the delegate path WITH the activeCreatorId; an action
 * with no active context fails "not in delegate mode"; a 403 from the server triggers AUTO-EXIT (the
 * managingCreator flag clears when the delegation is gone); and enterAsCreator resolves the active
 * permissions from managedCreators. FAKE delegate APIs (no Moshi) + the REAL in-memory DelegationStateStore.
 * runCurrent (never advanceUntilIdle); the provider's hot StateFlow is shared on the test backgroundScope.
 */
class DelegateRepositoriesTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    /** Builds the AND-359 repo + the AND-360 provider over a shared store, on the given [scope]. */
    private fun fixtures(
        feedApi: FakeDelegateFeedApi = FakeDelegateFeedApi(),
        messagingApi: FakeDelegateMessagingApi = FakeDelegateMessagingApi(),
        broadcastApi: FakeDelegateBroadcastApi = FakeDelegateBroadcastApi(),
        delegatesApi: FakeDelegatesApi = FakeDelegatesApi(),
        store: DelegationStateStore = DelegationStateStore(),
        scope: CoroutineScope,
    ): Fixtures {
        val delegationRepository = DelegationRepositoryImpl(delegatesApi, store, errorParser)
        val provider = DelegationContextProvider(
            delegationRepository,
            store,
            com.testlogon.android.core.network.delegates.DelegateRoutingStore(),
            scope,
        )
        return Fixtures(
            store = store,
            delegatesApi = delegatesApi,
            provider = provider,
            feed = DelegateFeedRepository(feedApi, provider, delegationRepository, errorParser),
            messaging = DelegateMessagingRepository(messagingApi, provider, delegationRepository, errorParser),
            broadcast = DelegateBroadcastRepository(broadcastApi, provider, delegationRepository, errorParser),
            feedApi = feedApi,
            messagingApi = messagingApi,
            broadcastApi = broadcastApi,
        )
    }

    private class Fixtures(
        val store: DelegationStateStore,
        val delegatesApi: FakeDelegatesApi,
        val provider: DelegationContextProvider,
        val feed: DelegateFeedRepository,
        val messaging: DelegateMessagingRepository,
        val broadcast: DelegateBroadcastRepository,
        val feedApi: FakeDelegateFeedApi,
        val messagingApi: FakeDelegateMessagingApi,
        val broadcastApi: FakeDelegateBroadcastApi,
    )

    private fun managing(vararg permissions: String) =
        ManagingCreator(creatorId = "cr_1", label = "Acme", permissions = permissions.toList())

    @Test
    fun feedCreate_withoutPermission_returnsPermissionDenied_andDoesNotCallApi() = runTest {
        val f = fixtures(scope = backgroundScope)
        f.store.setManagingCreator(managing("feed_read")) // read but NOT feed_post
        runCurrent()

        val result = f.feed.createPost("hello")

        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
        assertEquals("delegate_permission_denied", result.error.code)
        // CRITICAL: the API was NOT called
        assertTrue(f.feedApi.createPostCalls.isEmpty())
    }

    @Test
    fun feedCreate_withPermission_callsDelegatePath_withActiveCreatorId() = runTest {
        val f = fixtures(scope = backgroundScope)
        f.store.setManagingCreator(managing("feed_post"))
        runCurrent()

        val result = f.feed.createPost("hello")

        assertTrue(result is ApiResult.Success)
        assertEquals(1, f.feedApi.createPostCalls.size)
        assertEquals("cr_1", f.feedApi.createPostCalls.single().first)
        assertEquals("hello", f.feedApi.createPostCalls.single().second.text)
    }

    @Test
    fun feedList_withoutPermission_doesNotCallApi() = runTest {
        val f = fixtures(scope = backgroundScope)
        f.store.setManagingCreator(managing("feed_post")) // post but NOT feed_read
        runCurrent()

        val result = f.feed.listPosts()

        assertTrue(result is ApiResult.Failure)
        assertTrue(f.feedApi.listPostsCalls.isEmpty())
    }

    @Test
    fun messagingSend_withoutDelegateMode_failsNotInDelegateMode_andDoesNotCallApi() = runTest {
        val f = fixtures(scope = backgroundScope)
        // NOT in delegate mode (no managingCreator set)
        runCurrent()

        val result = f.messaging.send("c_1", "hi")

        assertTrue(result is ApiResult.Failure)
        assertEquals("not_in_delegate_mode", (result as ApiResult.Failure).error.code)
        assertTrue(f.messagingApi.sendCalls.isEmpty())
    }

    @Test
    fun messagingSend_withPermission_callsDelegatePath() = runTest {
        val f = fixtures(scope = backgroundScope)
        f.store.setManagingCreator(managing("chat_respond"))
        runCurrent()

        val result = f.messaging.send("c_7", "hi")

        assertTrue(result is ApiResult.Success)
        assertEquals("cr_1", f.messagingApi.sendCalls.single().first)
        assertEquals("c_7", f.messagingApi.sendCalls.single().second)
    }

    @Test
    fun broadcastStart_withoutControl_doesNotCallApi() = runTest {
        val f = fixtures(scope = backgroundScope)
        f.store.setManagingCreator(managing("broadcast_moderate")) // moderate but NOT control
        runCurrent()

        val result = f.broadcast.startSession("sess_1")

        assertTrue(result is ApiResult.Failure)
        assertTrue(f.broadcastApi.startCalls.isEmpty())
    }

    @Test
    fun forbidden403_whenDelegationGone_autoExitsDelegateMode() = runTest {
        // The delegate has feed_post, so the gate passes and the API is called - but the server returns 403.
        val feedApi = FakeDelegateFeedApi(throwHttp = 403)
        // managedCreators no longer lists cr_1 (revoked) -> auto-exit should clear the flag.
        val delegatesApi = FakeDelegatesApi(managed = emptyList())
        val f = fixtures(feedApi = feedApi, delegatesApi = delegatesApi, scope = backgroundScope)
        f.store.setManagingCreator(managing("feed_post"))
        runCurrent()

        val result = f.feed.createPost("hello")

        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
        // the API WAS called (recorded before throwing), then auto-exit re-fetched + cleared the flag
        assertEquals(1, feedApi.createPostCalls.size)
        runCurrent()
        assertNull(f.store.managingCreator.value)
    }

    @Test
    fun forbidden403_whenStillManaged_doesNotAutoExit() = runTest {
        val feedApi = FakeDelegateFeedApi(throwHttp = 403)
        // cr_1 is still actively managed -> a transient 403 must NOT eject the delegate.
        val delegatesApi = FakeDelegatesApi(
            managed = listOf(ManagedCreatorOut(creatorId = "cr_1", status = "active")),
        )
        val f = fixtures(feedApi = feedApi, delegatesApi = delegatesApi, scope = backgroundScope)
        f.store.setManagingCreator(managing("feed_post"))
        runCurrent()

        f.feed.createPost("hello")
        runCurrent()

        assertEquals("cr_1", f.store.managingCreator.value?.creatorId)
    }

    @Test
    fun enterAsCreator_resolvesActivePermissions_fromManagedCreators() = runTest {
        val delegatesApi = FakeDelegatesApi(
            managed = listOf(
                ManagedCreatorOut(
                    creatorId = "cr_1",
                    permissions = listOf("feed_post", "chat_read"),
                    status = "active",
                    label = "Acme",
                ),
            ),
        )
        val f = fixtures(delegatesApi = delegatesApi, scope = backgroundScope)

        val result = f.provider.enterAsCreator("cr_1")
        runCurrent() // let the hot context StateFlow observe the new selection

        assertTrue(result is ApiResult.Success)
        val ctx = (result as ApiResult.Success).data
        assertEquals("cr_1", ctx.creatorId)
        assertEquals("Acme", ctx.creatorName)
        assertTrue(f.feed.canPost())
        assertTrue(f.messaging.canRead())
        assertTrue(!f.messaging.canRespond())
    }

    @Test
    fun enterAsCreator_inactiveStatus_grantsNoPermissions() = runTest {
        val delegatesApi = FakeDelegatesApi(
            managed = listOf(
                ManagedCreatorOut(
                    creatorId = "cr_1",
                    permissions = listOf("feed_post"),
                    status = "pending", // not active -> no granted permissions
                    label = "Acme",
                ),
            ),
        )
        val f = fixtures(delegatesApi = delegatesApi, scope = backgroundScope)

        val result = f.provider.enterAsCreator("cr_1")
        runCurrent() // let the hot context StateFlow observe the new selection

        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.permissions.none { it.name == "FEED_POST" })
        assertTrue(!f.feed.canPost())
    }
}
