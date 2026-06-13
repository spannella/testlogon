package com.testlogon.android.feature.delegates

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.delegates.DelegationStateStore
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.delegates.ManagedCreatorOut
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.delegates.data.DelegationRepositoryImpl
import com.testlogon.android.feature.delegates.testing.FakeDelegatesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-359 - unit tests for [DelegationRepositoryImpl].
 *
 * Covers: managedCreators DTO -> domain mapping + HttpException -> Failure (the ONLY network call); ENTER
 * writes the managingCreator flag and returns Success(ManagingCreator) WITHOUT touching the network
 * (asserted via the fake's networkCallCount); EXIT clears the flag locally; and the activeCreatorId
 * path-scoping seam reflects the live state. Uses the FAKE DelegatesApi (no Moshi) + the REAL in-memory
 * DelegationStateStore; the [ApiErrorParser] needs only a Map adapter so a plain Moshi suffices.
 */
class DelegationRepositoryTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(
        api: FakeDelegatesApi,
        store: DelegationStateStore = DelegationStateStore(),
    ) = DelegationRepositoryImpl(api, store, errorParser)

    @Test
    fun managedCreators_mapsDtoToDomain() = runTest {
        val api = FakeDelegatesApi(
            managed = listOf(
                ManagedCreatorOut(
                    creatorId = "cr_1",
                    permissions = listOf("read", "post"),
                    preset = "editor",
                    status = "active",
                    label = "Acme",
                    acceptedAt = "2026-01-01",
                ),
                ManagedCreatorOut(creatorId = "cr_2"),
            ),
        )

        val result = repo(api).managedCreators()

        assertTrue(result is ApiResult.Success)
        val managed = (result as ApiResult.Success).data
        assertEquals(2, managed.size)
        assertEquals("cr_1", managed[0].creatorId)
        assertEquals(listOf("read", "post"), managed[0].permissions)
        assertEquals("Acme", managed[0].label)
        assertEquals(emptyList<String>(), managed[1].permissions)
    }

    @Test
    fun managedCreators_httpError_mapsToFailure_preservingStatus() = runTest {
        val api = FakeDelegatesApi(throwHttp = 403)
        val result = repo(api).managedCreators()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun enter_writesManagingCreator_andSucceeds_withNoNetworkCall() = runTest {
        val api = FakeDelegatesApi()
        val store = DelegationStateStore()
        val repository = repo(api, store)

        val result = repository.enter("cr_1", label = "Acme", permissions = listOf("read"))

        assertTrue(result is ApiResult.Success)
        val managing = (result as ApiResult.Success).data
        assertEquals("cr_1", managing.creatorId)
        assertEquals("Acme", managing.label)
        assertEquals(listOf("read"), managing.permissions)
        // the flag is written locally AND observable via the store / repo StateFlow
        assertEquals(managing, store.managingCreator.value)
        assertEquals(managing, repository.managingCreator.value)
        // CRITICAL: ENTER did NOT hit the network
        assertEquals(0, api.networkCallCount)
    }

    @Test
    fun exit_clearsManagingCreator_withNoNetworkCall() = runTest {
        val api = FakeDelegatesApi()
        val store = DelegationStateStore()
        val repository = repo(api, store)
        repository.enter("cr_1", label = "Acme")

        val result = repository.exit()

        assertTrue(result is ApiResult.Success)
        assertNull(store.managingCreator.value)
        assertNull(repository.managingCreator.value)
        // CRITICAL: EXIT did NOT hit the network either
        assertEquals(0, api.networkCallCount)
    }

    @Test
    fun activeCreatorId_reflectsLiveState() = runTest {
        val api = FakeDelegatesApi()
        val repository = repo(api)

        assertNull(repository.activeCreatorId())
        repository.enter("cr_42", label = null)
        assertEquals("cr_42", repository.activeCreatorId())
        repository.exit()
        assertNull(repository.activeCreatorId())
        // none of the path-scoping seam interactions hit the network
        assertEquals(0, api.networkCallCount)
    }
}
