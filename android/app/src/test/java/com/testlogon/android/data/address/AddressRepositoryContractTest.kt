package com.testlogon.android.data.address

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-214 / AND-217 — contract tests for [AddressRepositoryImpl] against the verified endpoints:
 * GET ui/addresses (bare array), POST ui/addresses (200 + AddressOut), PUT ui/addresses/primary.
 */
class AddressRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): AddressRepositoryImpl {
        val api = backend.retrofit(moshi).create(AddressApi::class.java)
        return AddressRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun listAddresses_parsesBareArray_andPrimaryFlag() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"address_id":"addr_1","name":"Ada Lovelace","line1":"5 Analytical Way","city":"London",
                   "state":"LDN","postal_code":"EC1A 1BB","country":"GB","is_primary_mailing":true,
                   "created_at":1717600000,"updated_at":1717600000},
                  {"address_id":"addr_2","line1":"10 Down","city":"London","is_primary_mailing":false}
                ]
                """.trimIndent(),
            ),
        )
        val result = repo().listAddresses()
        assertTrue(result is ApiResult.Success)
        val addresses = (result as ApiResult.Success).data
        assertEquals(2, addresses.size)
        assertEquals("addr_1", addresses[0].addressId)
        assertEquals("Ada Lovelace", addresses[0].name)
        assertEquals("LDN", addresses[0].state)
        assertTrue(addresses[0].isPrimaryMailing)
        assertFalse(addresses[1].isPrimaryMailing)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/addresses", req.requestUrl?.encodedPath)
    }

    @Test
    fun createAddress_posts200_andSendsAddressInFields() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"address_id":"addr_new","name":"Ada","line1":"5 Analytical Way","is_primary_mailing":false}""",
            ),
        )
        val result = repo().createAddress(AddressDraft(name = "Ada", line1 = "5 Analytical Way"))
        assertTrue(result is ApiResult.Success)
        assertEquals("addr_new", (result as ApiResult.Success).data.addressId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/addresses", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"line1\":\"5 Analytical Way\""))
        assertTrue(body.contains("\"name\":\"Ada\""))
        // No fabricated fields (full_name / region / phone / is_default).
        assertFalse(body.contains("full_name"))
        assertFalse(body.contains("region"))
        assertFalse(body.contains("phone"))
        assertFalse(body.contains("is_default"))
    }

    @Test
    fun setPrimary_putsAddressIdBody() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"address_id":"addr_2","is_primary_mailing":true}"""),
        )
        val result = repo().setPrimary("addr_2")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isPrimaryMailing)

        val req = backend.takeRequest()
        assertEquals("PUT", req.method)
        assertEquals("/ui/addresses/primary", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"address_id\":\"addr_2\""))
    }

    @Test
    fun createAddress_422_isFailureWithRawBody() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","line1"],"msg":"field required","type":"value_error"}]""", 422),
        )
        val result = repo().createAddress(AddressDraft(line1 = "x"))
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        // raw body retained so the VM can project per-field errors.
        assertTrue((result.error.raw as? String)?.contains("line1") == true)
    }
}
