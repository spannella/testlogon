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
import com.testlogon.android.feature.kyc.model.Tier
import com.testlogon.android.feature.kyc.model.TierStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.time.Instant

/**
 * AND-330 — ADDITIONAL contract tests for [KycTierRepositoryImpl] that lock down behavior NOT already
 * covered by [KycTierRepositoryTest] (AND-320): the evaluate write-through semantics on failure, the
 * promotion derivation when there is no warm cache, history epoch -> Instant mapping, the asOf clock seam,
 * out-of-range tier handling, and the malformed/empty-body parse-failure mapping.
 *
 * Mirrors [KycTierRepositoryTest] EXACTLY: a fake [KycApi] returning okhttp3.ResponseBody from JSON
 * strings + a plain Moshi (the tier DTOs use @JsonClass codegen so generated adapters auto-register) + an
 * in-memory KycTierStore. No new dependency; no MainDispatcherRule needed (the repo hops to Dispatchers.IO
 * and runTest awaits it).
 */
class KycTierRepositoryAdditionalTest {

    private val moshi: Moshi = Moshi.Builder().build()

    private val errorParser = ApiErrorParser(moshi)

    private class RecordingStore : KycTierStore {
        val flow = MutableStateFlow<TierStatus?>(null)
        var writes = 0
        override fun observe(): Flow<TierStatus?> = flow
        override suspend fun read(): TierStatus? = flow.value
        override suspend fun write(status: TierStatus) {
            writes++
            flow.value = status
        }
        override suspend fun clear() {
            flow.value = null
        }
    }

    private class StubApi(
        var tierMeBody: () -> ResponseBody = { body("{}") },
        var evaluateBody: () -> ResponseBody = { body("{}") },
        var requirementsBody: (String) -> ResponseBody = { body("{}") },
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

    private fun repo(api: StubApi, store: KycTierStore = RecordingStore()) =
        KycTierRepositoryImpl(api, moshi, store, errorParser).also { it.now = { FIXED_NOW } }

    @Test
    fun refresh_stampsAsOfFromClockSeam_andMapsHistoryEpochToInstant() = runTest {
        val api = StubApi(
            tierMeBody = {
                body(
                    """
                    {
                      "current_tier": 1,
                      "updated_at": 1700000000,
                      "history": [
                        { "from_tier": 0, "to_tier": 1, "changed_at": 1699999999,
                          "reason": "email_verified", "case_id": "case_7" }
                      ]
                    }
                    """.trimIndent(),
                )
            },
            requirementsBody = { body("""{"current_tier":1,"met":[],"unmet":["phone_verified"],"eligible":false}""") },
        )
        val status = (repo(api).refreshTierStatus() as ApiResult.Success).data

        assertEquals(FIXED_NOW, status.asOf)
        assertEquals(Instant.ofEpochSecond(1_700_000_000), status.updatedAt)
        assertEquals(1, status.history.size)
        val entry = status.history.first()
        assertEquals(0, entry.fromTier)
        assertEquals(1, entry.toTier)
        assertEquals(Instant.ofEpochSecond(1_699_999_999), entry.changedAt)
        assertEquals("email_verified", entry.reason)
        assertEquals("case_7", entry.caseId)
    }

    @Test
    fun evaluate_noPreviousCache_isNotPromoted_evenAtNonZeroTier() = runTest {
        val store = RecordingStore() // cold: nothing cached, so prev == null.
        val api = StubApi(
            evaluateBody = { body("""{"current_tier":3,"updated_at":null,"history":[]}""") },
            requirementsBody = { body("""{"current_tier":3,"met":[],"unmet":["proof_of_funds"],"eligible":true}""") },
        )
        val evaluation = (repo(api, store).evaluate() as ApiResult.Success).data

        assertTrue("prev==null must derive promoted=false", !evaluation.promoted)
        assertEquals(3, evaluation.tierStatus.current.level)
        // Write-through on success persists the new snapshot.
        assertEquals(1, store.writes)
    }

    @Test
    fun evaluate_onHttpFailure_leavesSnapshotIntact_noWriteThrough() = runTest {
        val store = RecordingStore()
        val warm = snapshot(level = 1)
        store.write(warm) // writes == 1 from seeding.
        val seededWrites = store.writes

        val api = StubApi(evaluateBody = { throw http(500) })
        val result = repo(api, store).evaluate()

        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
        // No additional write: the cached snapshot survives untouched.
        assertEquals(seededWrites, store.writes)
        assertSame(warm, store.read())
    }

    @Test
    fun evaluate_onNetworkFailure_leavesSnapshotIntact() = runTest {
        val store = RecordingStore()
        store.write(snapshot(level = 2))
        val seededWrites = store.writes

        val api = StubApi(evaluateBody = { throw IOException("offline") })
        val result = repo(api, store).evaluate()

        assertTrue(result is ApiResult.NetworkError)
        assertEquals(seededWrites, store.writes)
        assertEquals(2, store.read()?.current?.level)
    }

    @Test
    fun refresh_currentTierAboveMax_skipsRequirements_andTargetIsNull() = runTest {
        // Out-of-range / unknown tier (> MAX_TIER) is treated like the max tier: no target, no requirements.
        val api = StubApi(tierMeBody = { body("""{"current_tier":7,"updated_at":null,"history":[]}""") })
        val status = (repo(api).refreshTierStatus() as ApiResult.Success).data

        assertEquals(7, status.current.level)
        assertNull(status.target)
        assertTrue(status.requirements.isEmpty())
        assertEquals(0, api.requirementsCalls)
    }

    @Test
    fun refresh_malformedJson_mapsToParseFailure() = runTest {
        val api = StubApi(tierMeBody = { body("{ this is not json ") })
        val result = repo(api).refreshTierStatus()
        assertTrue(result is ApiResult.Failure)
    }

    @Test
    fun refresh_emptyBody_mapsToError_notCrash() = runTest {
        // An empty body makes the JSON reader hit EOF; the repo folds that into a non-Success ApiResult
        // (an EOFException is an IOException -> NetworkError) rather than throwing. The guarantee under test
        // is "no crash, not Success" — the exact error band (Failure vs NetworkError) is implementation detail.
        val api = StubApi(tierMeBody = { body("") })
        val result = repo(api).refreshTierStatus()
        assertTrue(result !is ApiResult.Success)
    }

    @Test
    fun refresh_writesSnapshot_exactlyOnceOnSuccess() = runTest {
        val store = RecordingStore()
        val api = StubApi(
            tierMeBody = { body("""{"current_tier":2,"updated_at":null,"history":[]}""") },
            requirementsBody = { body("""{"current_tier":2,"met":["a"],"unmet":["b"],"eligible":true}""") },
        )
        repo(api, store).refreshTierStatus()
        assertEquals(1, store.writes)
    }

    private companion object {
        val FIXED_NOW: Instant = Instant.ofEpochSecond(1_700_000_500)

        fun snapshot(level: Int): TierStatus = TierStatus(
            current = Tier(level),
            updatedAt = null,
            history = emptyList(),
            target = null,
            requirements = emptyList(),
            eligibleForTarget = false,
            asOf = FIXED_NOW,
        )

        fun body(json: String): ResponseBody = json.toResponseBody("application/json".toMediaType())

        fun http(code: Int): HttpException =
            HttpException(Response.error<Any>(code, "{}".toResponseBody("application/json".toMediaType())))
    }
}
