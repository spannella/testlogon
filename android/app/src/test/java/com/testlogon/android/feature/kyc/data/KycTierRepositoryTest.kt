package com.testlogon.android.feature.kyc.data

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycCaseCreateRequest
import com.testlogon.android.core.model.kyc.KycCaseDraftPatchRequest
import com.testlogon.android.core.model.kyc.KycCaseEnvelope
import com.testlogon.android.core.model.kyc.KycCaseListEnvelope
import com.testlogon.android.core.model.kyc.KycEstimatedWaitEnvelope
import com.testlogon.android.core.model.kyc.KycFileAttachmentRequest
import com.testlogon.android.core.model.kyc.KycReadinessEnvelope
import com.testlogon.android.core.model.kyc.KycSubmitCaseRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.feature.kyc.model.TierStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.time.Instant

/**
 * AND-320 — contract tests for [KycTierRepositoryImpl].
 *
 * Uses a fake [KycApi] returning okhttp3.ResponseBody from JSON strings + a plain Moshi (the tier DTOs
 * use @JsonClass(generateAdapter = true) codegen, so generated adapters register automatically — no
 * moshi-kotlin reflection needed) + an in-memory [KycTierStore]. The case endpoints are unused here.
 */
class KycTierRepositoryTest {

    private val moshi: Moshi = Moshi.Builder().build()

    private val errorParser = ApiErrorParser(moshi)

    /** In-memory KycTierStore. */
    private class FakeStore : KycTierStore {
        val flow = MutableStateFlow<TierStatus?>(null)
        var written: TierStatus? = null
        override fun observe(): Flow<TierStatus?> = flow
        override suspend fun read(): TierStatus? = flow.value
        override suspend fun write(status: TierStatus) {
            written = status
            flow.value = status
        }
        override suspend fun clear() {
            written = null
            flow.value = null
        }
    }

    /** Fake KycApi: only the three tier endpoints are exercised; the case endpoints throw. */
    private class FakeApi(
        var tierMeBody: () -> ResponseBody = { json("{}") },
        var evaluateBody: () -> ResponseBody = { json("{}") },
        var requirementsBody: (String) -> ResponseBody = { json("{}") },
    ) : KycApi {
        var requirementsTargetArgs = mutableListOf<String>()
        var requirementsCalls = 0

        override suspend fun tierMe(): ResponseBody = tierMeBody()
        override suspend fun evaluateTier(): ResponseBody = evaluateBody()
        override suspend fun tierRequirements(targetTier: String): ResponseBody {
            requirementsCalls++
            requirementsTargetArgs += targetTier
            return requirementsBody(targetTier)
        }

        override suspend fun createCase(body: KycCaseCreateRequest): KycCaseEnvelope = error("unused")
        override suspend fun listCases(): KycCaseListEnvelope = error("unused")
        override suspend fun estimatedWait(): KycEstimatedWaitEnvelope = error("unused")
        override suspend fun getCase(caseId: String): KycCaseEnvelope = error("unused")
        override suspend fun patchDraft(caseId: String, body: KycCaseDraftPatchRequest): KycCaseEnvelope =
            error("unused")
        override suspend fun attachFile(caseId: String, body: KycFileAttachmentRequest): KycCaseEnvelope =
            error("unused")
        override suspend fun readiness(caseId: String): KycReadinessEnvelope = error("unused")
        override suspend fun submitCase(caseId: String, body: KycSubmitCaseRequest): KycCaseEnvelope =
            error("unused")
    }

    private fun repo(api: FakeApi, store: KycTierStore = FakeStore()) =
        KycTierRepositoryImpl(api, moshi, store, errorParser).also {
            it.now = { FIXED_NOW }
        }

    @Test
    fun refresh_parsesTierAndRequirements_targetIsCurrentPlusOne() = runTest {
        val api = FakeApi(
            tierMeBody = { json("""{"current_tier":1,"updated_at":1700000000,"history":[]}""") },
            requirementsBody = {
                json("""{"current_tier":1,"met":["email_verified"],"unmet":["phone_verified"],"eligible":false}""")
            },
        )
        val store = FakeStore()
        val result = repo(api, store).refreshTierStatus()

        val status = (result as ApiResult.Success).data
        assertEquals(1, status.current.level)
        assertEquals(2, status.target?.level)
        // Requirements were fetched with the INTEGER target path "2".
        assertEquals(listOf("2"), api.requirementsTargetArgs)
        // met first (true) then unmet (false).
        assertEquals(listOf("email_verified", "phone_verified"), status.requirements.map { it.key })
        assertEquals(listOf(true, false), status.requirements.map { it.met })
        assertFalse(status.eligibleForTarget)
        // Persisted to the store.
        assertEquals(status, store.written)
    }

    @Test
    fun refresh_atMaxTier_skipsRequirements_andTargetIsNull() = runTest {
        val api = FakeApi(
            tierMeBody = { json("""{"current_tier":4,"updated_at":null,"history":[]}""") },
        )
        val result = repo(api).refreshTierStatus()

        val status = (result as ApiResult.Success).data
        assertEquals(4, status.current.level)
        assertNull(status.target)
        assertTrue(status.requirements.isEmpty())
        assertEquals(0, api.requirementsCalls)
    }

    @Test
    fun evaluate_promotesWhenNewTierExceedsPrevious_andRefetchesRequirements() = runTest {
        val store = FakeStore()
        // Warm cache at tier 1 so promotion can be derived.
        store.write(
            TierStatus(
                current = com.testlogon.android.feature.kyc.model.Tier(1),
                updatedAt = null, history = emptyList(), target = null,
                requirements = emptyList(), eligibleForTarget = false, asOf = FIXED_NOW,
            ),
        )
        val api = FakeApi(
            evaluateBody = { json("""{"current_tier":2,"updated_at":1700000005,"history":[]}""") },
            requirementsBody = {
                json("""{"current_tier":2,"met":[],"unmet":["proof_of_address"],"eligible":false}""")
            },
        )
        val result = repo(api, store).evaluate()

        val evaluation = (result as ApiResult.Success).data
        assertTrue(evaluation.promoted)
        assertEquals(2, evaluation.tierStatus.current.level)
        assertEquals(3, evaluation.tierStatus.target?.level)
        // Re-fetched requirements for the NEW target ("3").
        assertEquals(listOf("3"), api.requirementsTargetArgs)
        assertEquals(listOf("proof_of_address"), evaluation.tierStatus.requirements.map { it.key })
    }

    @Test
    fun evaluate_noPromotionWhenTierUnchanged() = runTest {
        val store = FakeStore()
        store.write(
            TierStatus(
                current = com.testlogon.android.feature.kyc.model.Tier(1),
                updatedAt = null, history = emptyList(), target = null,
                requirements = emptyList(), eligibleForTarget = false, asOf = FIXED_NOW,
            ),
        )
        val api = FakeApi(
            evaluateBody = { json("""{"current_tier":1,"updated_at":null,"history":[]}""") },
            requirementsBody = { json("""{"current_tier":1,"met":[],"unmet":[],"eligible":false}""") },
        )
        val result = repo(api, store).evaluate()
        assertFalse((result as ApiResult.Success).data.promoted)
    }

    @Test
    fun refresh_httpError_mapsToFailure() = runTest {
        val api = FakeApi(tierMeBody = { throw http(403) })
        val result = repo(api).refreshTierStatus()
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun refresh_ioError_mapsToNetworkError() = runTest {
        val api = FakeApi(tierMeBody = { throw IOException("offline") })
        val result = repo(api).refreshTierStatus()
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun observeTierStatus_emitsStoreSnapshot() = runTest {
        val store = FakeStore()
        val snapshot = TierStatus(
            current = com.testlogon.android.feature.kyc.model.Tier(2),
            updatedAt = null, history = emptyList(), target = null,
            requirements = emptyList(), eligibleForTarget = false, asOf = FIXED_NOW,
        )
        store.write(snapshot)
        val api = FakeApi()
        assertEquals(snapshot, repo(api, store).observeTierStatus().first())
    }

    private companion object {
        val FIXED_NOW: Instant = Instant.ofEpochSecond(1_700_000_100)

        fun json(body: String): ResponseBody = body.toResponseBody("application/json".toMediaType())

        fun http(code: Int): HttpException =
            HttpException(Response.error<Any>(code, "{}".toResponseBody("application/json".toMediaType())))
    }
}
