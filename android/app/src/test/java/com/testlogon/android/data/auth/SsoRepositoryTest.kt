package com.testlogon.android.data.auth

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.InMemoryCookieJar
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`

/** AND-063 — SsoRepository: discovery parsing + authorization-URL construction. */
class SsoRepositoryTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = Moshi.Builder().build()
    private val cookieJar = InMemoryCookieJar()

    private fun settings(baseUrl: String): SettingsStore =
        mock(SettingsStore::class.java).also { `when`(it.baseUrl).thenReturn(baseUrl) }

    private fun repo(baseUrl: String = "http://18.222.237.167:8000/"): SsoRepositoryImpl {
        val api = backend.retrofit(moshi, client = defaultTestClient(cookieJar)).create(AuthApi::class.java)
        return SsoRepositoryImpl(api, FakeAuthRepository(), settings(baseUrl), ApiErrorParser(moshi))
    }

    @Test
    fun getSsoInfo_parsesFields_andSendsTenantQuery() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"sso_available":true,"sso_only":true,""" +
                    """"sso_login_url":"http://host/saml/login?tenant=acme",""" +
                    """"provider_display_name":"Acme SSO","provider_protocol":"saml"}""",
            ),
        )
        val r = repo().getSsoInfo("acme")
        assertTrue(r is ApiResult.Success)
        val info = (r as ApiResult.Success).data
        assertTrue(info.ssoOnly)
        assertTrue(info.ssoAvailable)
        assertEquals("Acme SSO", info.providerDisplayName)

        val req = backend.takeRequest()
        assertEquals("/ui/sso/info", req.requestUrl?.encodedPath)
        assertEquals("acme", req.requestUrl?.queryParameter("tenant"))
    }

    @Test
    fun authorizeUrl_usesSsoLoginUrlVerbatim_whenPresent() {
        val r = repo()
        val info = SsoInfo(true, true, "https://idp.example.com/saml/login?tenant=acme", "Acme", "saml")
        val url = r.authorizeUrl(info, tenant = "default")
        assertEquals("https://idp.example.com/saml/login?tenant=acme", url)
    }

    @Test
    fun authorizeUrl_fallsBackToSamlLogin_withTenantOnly_noStateOrReturnUrl() {
        val r = repo(baseUrl = "http://18.222.237.167:8000/")
        val url = r.authorizeUrl(info = null, tenant = "acme")
        assertEquals("http://18.222.237.167:8000/saml/login?tenant=acme", url)
        assertFalse(url.contains("state"))
        assertFalse(url.contains("return_url"))
    }

    @Test
    fun getSsoInfo_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error(""""bad tenant"""", 422))
        val r = repo().getSsoInfo("x")
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
        backend.takeRequest()
    }
}
