package com.testlogon.android.data.call

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ErrorDetailMapper
import com.testlogon.android.core.network.error.ApiErrorParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-306 — FastAPI `detail` ERROR-DECODE coverage against the REAL [ApiErrorParser].
 *
 * The existing core-network ApiErrorParserTest exercises parseDetail()/fromThrowable() in isolation; it
 * does NOT assert the END-TO-END HttpException -> typed [ApiError] path for the three FastAPI `detail`
 * shapes a CALL/SIGNALING failure actually returns. This test fills that gap by feeding the parser real
 * Retrofit [HttpException]s (built from error [Response]s, the same shape the call repos catch in their
 * `call {}` wrapper) and asserting status + code + user-facing message for each shape:
 *   (a) string detail          -> message passthrough, no code
 *   (b) FastAPI 422 array      -> joined validation msgs, no code
 *   (c) coded object {code,msg} -> code surfaced; message falls back to GENERIC for an unknown app code
 *
 * The parser is constructed exactly as CallRepositoryContractTest does: ApiErrorParser(plain Moshi). Note
 * there is NO CallSignalingErrorOut DTO in the tree (the signaling error surfaces only as the generic
 * FastAPI `{code,message}` object), so the {code:"peer_busy",message:...} shape is the real wire form.
 */
class ApiErrorDecodeTest {

    private val moshi: Moshi = Moshi.Builder().build()
    private val parser = ApiErrorParser(moshi)

    private val jsonMedia = "application/json".toMediaType()

    /** Builds a real Retrofit HttpException carrying a FastAPI `{"detail": <detailJson>}` error body. */
    private fun httpError(status: Int, detailJson: String): HttpException {
        val body = """{"detail":$detailJson}""".toResponseBody(jsonMedia)
        return HttpException(Response.error<Any>(status, body))
    }

    // ─── (a) string detail ────────────────────────────────────────────────────────────────────────

    @Test
    fun stringDetail_mapsStatusAndMessage_noCode() {
        val error: ApiError = parser.from(httpError(409, "\"not in call\""))
        assertEquals(409, error.status)
        assertEquals("not in call", error.message)
        assertNull(error.code)
    }

    // ─── (b) FastAPI 422 validation array ──────────────────────────────────────────────────────────

    @Test
    fun validationArrayDetail_422_joinsMsgs_noCode() {
        val error = parser.from(
            httpError(
                422,
                """[{"loc":["body","callee_user_id"],"msg":"field required","type":"value_error.missing"},
                   {"loc":["body","call_id"],"msg":"field required","type":"value_error.missing"}]""",
            ),
        )
        assertEquals(422, error.status)
        // ErrorDetailMapper joins every item's msg with ", ".
        assertEquals("field required, field required", error.message)
        assertNull(error.code)
    }

    @Test
    fun validationArrayDetail_singleItem_surfacesThatMsg() {
        val error = parser.from(
            httpError(422, """[{"loc":["body","nonce"],"msg":"invalid nonce","type":"value_error"}]"""),
        )
        assertEquals(422, error.status)
        assertEquals("invalid nonce", error.message)
    }

    // ─── (c) coded object {code, message} (the CallSignalingErrorOut-shaped wire form) ──────────────

    @Test
    fun codedObjectDetail_peerBusy_surfacesCode_messageFallsBackForUnknownAppCode() {
        val error = parser.from(
            httpError(409, """{"code":"peer_busy","message":"callee busy"}"""),
        )
        assertEquals(409, error.status)
        // peer_busy is not in ErrorDetailMapper.codeMessages, so the user-facing message degrades to the
        // generic copy (the mapper intentionally does NOT surface an unknown code's backend message).
        assertEquals(ErrorDetailMapper.GENERIC, error.message)
        // ...but the machine-readable code IS extracted, so callers can branch on it.
        assertEquals("peer_busy", error.code)
    }

    @Test
    fun codedObjectDetail_knownAppCode_surfacesCuratedCopy() {
        val error = parser.from(httpError(403, """{"code":"role_required"}"""))
        assertEquals(403, error.status)
        assertEquals("role_required", error.code)
        assertEquals(ErrorDetailMapper.codeMessages.getValue("role_required"), error.message)
    }

    // ─── totality: malformed / empty bodies never throw ────────────────────────────────────────────

    @Test
    fun malformedErrorBody_degradesToGeneric_neverThrows() {
        val body = "<html>502 Bad Gateway</html>".toResponseBody("text/html".toMediaType())
        val error = parser.from(HttpException(Response.error<Any>(502, body)))
        assertEquals(502, error.status)
        assertEquals(ErrorDetailMapper.GENERIC, error.message)
        assertNull(error.code)
    }

    @Test
    fun emptyErrorBody_degradesToGeneric() {
        val error = parser.from(HttpException(Response.error<Any>(500, "".toResponseBody(jsonMedia))))
        assertEquals(500, error.status)
        assertEquals(ErrorDetailMapper.GENERIC, error.message)
    }

    @Test
    fun rawBody_isPreservedForDiagnostics() {
        val error = parser.from(httpError(409, "\"not in call\""))
        // The parser stashes the raw body so callers can log the unredacted server payload.
        assertTrue((error.raw as? String)?.contains("not in call") == true)
    }
}
