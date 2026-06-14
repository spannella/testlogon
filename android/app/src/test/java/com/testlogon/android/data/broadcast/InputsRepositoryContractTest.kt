package com.testlogon.android.data.broadcast

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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-310 — MockWebServer contract tests for [InputsRepositoryImpl]. Verifies the inputs LIST parse
 * (unknown input_type -> UNKNOWN, null connected_at / ingest_url, wrapper fields), the activate POST (empty
 * body) then refetch, the layout switch (required mode + primary_input_id) and client-derived program, and
 * 422 detail mapping. Each request body is read ONCE.
 */
class InputsRepositoryContractTest {

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

    private fun repo(dao: InputsDao = FakeInputsDao()): InputsRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return InputsRepositoryImpl(
            api = retrofit.create(InputsApi::class.java),
            dao = dao,
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun refresh_parsesListEnvelope_unknownType_nullFields() = runTest {
        backend.enqueue(Fixtures.okBody(LIST_JSON))
        val result = repo().refresh("bcs_1")
        assertTrue(result is ApiResult.Success)
        val inputs = (result as ApiResult.Success).data
        assertEquals(2, inputs.size)

        val primary = inputs.first { it.inputId == "in_1" }
        assertEquals("primary", primary.inputType)
        assertEquals(com.testlogon.android.data.broadcast.InputType.PRIMARY, primary.inputTypeEnum)
        assertTrue(primary.isLive)
        assertEquals(1_700_000_000L, primary.connectedAt)

        val weird = inputs.first { it.inputId == "in_2" }
        // Unknown wire input_type coerces to UNKNOWN (never throws).
        assertEquals(com.testlogon.android.data.broadcast.InputType.UNKNOWN, weird.inputTypeEnum)
        assertFalse(weird.isLive)
        assertNull(weird.connectedAt)
        assertNull(weird.ingestUrl)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/inputs", req.requestUrl?.encodedPath)
    }

    @Test
    fun setActive_activate_postsEmptyBody_thenRefetchesList() = runTest {
        // 1) activate -> { ok: true }   2) refetch list.
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        backend.enqueue(Fixtures.okBody(LIST_JSON))

        val result = repo().setActive("bcs_1", "in_1", active = true)
        assertTrue(result is ApiResult.Success)
        assertEquals(2, (result as ApiResult.Success).data.size)

        val activate = backend.takeRequest()
        assertEquals("POST", activate.method)
        assertEquals("/broadcast/sessions/bcs_1/inputs/in_1/activate", activate.requestUrl?.encodedPath)
        assertTrue(activate.bodyJson().isEmpty())

        val list = backend.takeRequest()
        assertEquals("GET", list.method)
        assertEquals("/broadcast/sessions/bcs_1/inputs", list.requestUrl?.encodedPath)
    }

    @Test
    fun setActive_deactivate_postsToDeactivatePath() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        backend.enqueue(Fixtures.okBody(LIST_JSON))
        val result = repo().setActive("bcs_1", "in_1", active = false)
        assertTrue(result is ApiResult.Success)

        val deactivate = backend.takeRequest()
        assertEquals("/broadcast/sessions/bcs_1/inputs/in_1/deactivate", deactivate.requestUrl?.encodedPath)
    }

    @Test
    fun setProgram_postsLayoutWithModeAndPrimary_derivesProgram() = runTest {
        backend.enqueue(Fixtures.okBody(LAYOUT_JSON))
        val result = repo().setProgram("bcs_1", "in_1", mode = "single")
        assertTrue(result is ApiResult.Success)
        val layout = (result as ApiResult.Success).data
        assertEquals("single", layout.mode)
        assertEquals("in_1", layout.primaryInputId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/layout", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("single", body["mode"])
        assertEquals("in_1", body["primary_input_id"])
    }

    @Test
    fun refreshLayout_getsLayout() = runTest {
        backend.enqueue(Fixtures.okBody(LAYOUT_JSON))
        val result = repo().refreshLayout("bcs_1")
        assertTrue(result is ApiResult.Success)
        assertEquals("in_1", (result as ApiResult.Success).data.primaryInputId)
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/layout", req.requestUrl?.encodedPath)
    }

    @Test
    fun refresh_422_mapsToFailureWithStatus() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["path","session_id"],"msg":"not found","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().refresh("bcs_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    private companion object {
        const val LIST_JSON = """
            {"session_id":"bcs_1","count":2,"max_inputs":4,"inputs":[
              {"input_id":"in_1","session_id":"bcs_1","input_type":"primary","label":"Host camera",
               "is_live":true,"ingest_url":"rtmps://ingest.testlogon.dev/app","stream_key_ref":"ref_1",
               "position":0,"connected_at":1700000000,"created_by":"usr_42",
               "created_at":"2026-06-05T22:00:00Z","updated_at":"2026-06-05T22:05:00Z"},
              {"input_id":"in_2","session_id":"bcs_1","input_type":"hologram","label":"Mystery",
               "is_live":false,"position":1,"created_by":"usr_42",
               "created_at":"2026-06-05T22:00:00Z","updated_at":"2026-06-05T22:00:00Z"}
            ]}
        """

        const val LAYOUT_JSON = """
            {"mode":"single","primary_input_id":"in_1","input_ids":["in_1","in_2"],
             "positions":[{"input_id":"in_1","x":0,"y":0,"width":1280,"height":720,"z_index":0}]}
        """
    }
}
