package com.testlogon.android.feature.broadcast.layout

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.broadcast.BroadcastInputEntity
import com.testlogon.android.core.data.broadcast.BroadcastLayoutEntity
import com.testlogon.android.core.data.broadcast.InputsDao
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.broadcast.InputsApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-311 — MockWebServer contract tests for [LayoutRepositoryImpl] (reuses the AND-310 [InputsApi]).
 *
 * Verifies the layout GET parse (mode / input_ids / primary_input_id / positions, incl. an unknown mode
 * staying a raw String the domain coerces to UNKNOWN in the UI layer), the setLayout POST body ({"mode": ...}
 * only — verb + path + mode asserted) returning the refreshed layout upserted to the cache, and 422 detail
 * mapping. Each request body is read ONCE.
 */
class LayoutRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    /** In-memory fake DAO (Room itself is exercised by InputsDaoTest); here we only verify the wire layer. */
    private class FakeInputsDao : InputsDao {
        val rows = MutableStateFlow<List<BroadcastInputEntity>>(emptyList())
        val layout = MutableStateFlow<BroadcastLayoutEntity?>(null)

        override fun observeBySession(sessionId: String): Flow<List<BroadcastInputEntity>> = rows
        override suspend fun getBySession(sessionId: String): List<BroadcastInputEntity> = rows.value
        override suspend fun upsertAll(rows: List<BroadcastInputEntity>) {
            this.rows.value = rows
        }
        override suspend fun deleteForSession(sessionId: String) {
            rows.value = emptyList()
        }
        override suspend fun replaceForSession(sessionId: String, rows: List<BroadcastInputEntity>) {
            this.rows.value = rows
        }
        override fun observeLayout(sessionId: String): Flow<BroadcastLayoutEntity?> = layout
        override suspend fun getLayout(sessionId: String): BroadcastLayoutEntity? = layout.value
        override suspend fun upsertLayout(layout: BroadcastLayoutEntity) {
            this.layout.value = layout
        }
    }

    private fun repo(dao: FakeInputsDao = FakeInputsDao()): Pair<LayoutRepositoryImpl, FakeInputsDao> {
        val retrofit = backend.retrofit(moshi)
        val impl = LayoutRepositoryImpl(
            api = retrofit.create(InputsApi::class.java),
            dao = dao,
            errorParser = ApiErrorParser(moshi),
        )
        return impl to dao
    }

    @Test
    fun refresh_parsesLayout_modePrimaryInputsPositions_unknownModeKept() = runTest {
        backend.enqueue(Fixtures.okBody(UNKNOWN_MODE_JSON))
        val (impl, dao) = repo()

        val result = impl.refresh("bcs_1")
        assertTrue(result is ApiResult.Success)
        val layout = (result as ApiResult.Success).data
        // Unknown wire mode is kept as the raw String on the domain (the UI coerces to UNKNOWN).
        assertEquals("hologram", layout.mode)
        assertEquals(LayoutModeUi.UNKNOWN, LayoutModeUi.fromWire(layout.mode))
        assertEquals("in_1", layout.primaryInputId)
        assertEquals(listOf("in_1", "in_2"), layout.inputIds)
        assertEquals(1, layout.positions.size)
        assertEquals("in_1", layout.positions.single().inputId)
        // The refreshed layout was upserted (positions are NOT persisted — entity carries mode/primary/ids).
        assertEquals("hologram", dao.layout.value?.mode)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/layout", req.requestUrl?.encodedPath)
    }

    @Test
    fun setLayout_postsModeOnly_returnsRefreshedLayout_upserted() = runTest {
        backend.enqueue(Fixtures.okBody(PIP_JSON))
        val (impl, dao) = repo()

        val result = impl.setLayout("bcs_1", mode = "pip")
        assertTrue(result is ApiResult.Success)
        assertEquals("pip", (result as ApiResult.Success).data.mode)
        assertEquals("pip", dao.layout.value?.mode)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/layout", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("pip", body["mode"])
        // The web client (and this port) sends only {mode}; nulls are omitted by Moshi.
        assertNull(body["primary_input_id"])
        assertNull(body["input_ids"])
    }

    @Test
    fun setLayout_422_mapsToFailureWithStatus() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","mode"],"msg":"bad mode","type":"value_error"}]""",
                422,
            ),
        )
        val (impl, _) = repo()

        val result = impl.setLayout("bcs_1", mode = "single")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
    }

    private companion object {
        const val UNKNOWN_MODE_JSON = """
            {"mode":"hologram","primary_input_id":"in_1","input_ids":["in_1","in_2"],
             "positions":[{"input_id":"in_1","x":0,"y":0,"width":1280,"height":720,"z_index":0}]}
        """

        const val PIP_JSON = """
            {"mode":"pip","primary_input_id":"in_1","input_ids":["in_1","in_2"],"positions":[]}
        """
    }
}
