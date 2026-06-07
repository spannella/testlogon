package com.testlogon.android.core.network.error

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ErrorDetailMapper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.IOException
import java.net.SocketTimeoutException

class ApiErrorParserTest {

    private val parser = ApiErrorParser(Moshi.Builder().add(KotlinJsonAdapterFactory()).build())

    @Test
    fun `parses string detail`() {
        assertEquals("Invalid challenge", parser.parseDetail("""{"detail":"Invalid challenge"}"""))
    }

    @Test
    fun `parses coded detail`() {
        val detail = parser.parseDetail("""{"detail":{"code":"role_required"}}""")
        assertEquals("role_required", ErrorDetailMapper.extractCode(detail))
    }

    @Test
    fun `malformed and empty bodies are total`() {
        assertNull(parser.parseDetail(null))
        assertNull(parser.parseDetail(""))
        assertNull(parser.parseDetail("not json"))
        assertNull(parser.parseDetail("<html>502</html>"))
    }

    @Test
    fun `transport throwable maps to network sentinel`() {
        val error = parser.fromThrowable(SocketTimeoutException())
        assertEquals(ApiError.STATUS_NETWORK, error.status)
        assertEquals(ErrorDetailMapper.OFFLINE, error.message)
    }

    @Test
    fun `generic IOException maps to network sentinel`() {
        val error = parser.fromThrowable(IOException("reset"))
        assertEquals(ApiError.STATUS_NETWORK, error.status)
    }
}
