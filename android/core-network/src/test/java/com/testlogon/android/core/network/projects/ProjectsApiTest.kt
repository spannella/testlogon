package com.testlogon.android.core.network.projects

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

/**
 * AND-376 - hermetic request-shape / decode tests for the AND-374 [ProjectsApi] (mirrors the AND-371
 * TicketsApiTest, which the existing AND-374 suite had no equivalent of).
 *
 * Everything is hermetic: MockWebServer only, a production-style Moshi (BigDecimalAdapter + the reflective
 * KotlinJsonAdapterFactory, like NetworkModule.provideMoshi - no enum adapter needed since `provider` decodes
 * as a raw String), and runTest. No real dev host (AC-9). These tests pin the CORRECTED §5 / §16 contract:
 * the paths are v1/projects (NOT /projects or /ui/projects); the list cursor query/field is `cursor`; the
 * Drive OAuth start has an EMPTY request body and the callback returns a CREDENTIAL (NOT a project). KDoc
 * avoids the comment-terminator pair.
 */
class ProjectsApiTest {

    private lateinit var server: MockWebServer

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun projectsApi(): ProjectsApi = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .client(OkHttpClient())
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(ProjectsApi::class.java)

    private fun jsonResponse(body: String, code: Int = 200) =
        MockResponse().setResponseCode(code).setHeader("Content-Type", "application/json").setBody(body)

    @Before
    fun setUp() {
        server = MockWebServer().apply { start() }
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ---- listProjects: list envelope { items, cursor }, relative path v1/projects, default limit query ----

    @Test
    fun listProjects_decodesListEnvelope_relativePath_defaultLimit_noCursorByDefault() = runTest {
        server.enqueue(
            jsonResponse(
                """{"items":[
                     {"id":"prj_1","owner":"usr_9","name":"Demo","tags":["t"],
                      "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z"},
                     {"id":"prj_2","owner":"usr_9","name":"Other",
                      "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z"}
                   ],"cursor":"cur_2"}""",
            ),
        )

        val envelope = projectsApi().listProjects()

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        // CORRECTED path: v1/projects (NOT /projects or /ui/projects)
        assertEquals("/v1/projects", recorded.requestUrl?.encodedPath)
        // default limit query is sent; no cursor (Retrofit drops the null @Query)
        assertEquals("20", recorded.requestUrl?.queryParameter("limit"))
        assertNull(recorded.requestUrl?.queryParameter("cursor"))
        assertEquals(2, envelope.items.size)
        assertEquals("prj_1", envelope.items[0].id)
        assertEquals(listOf("t"), envelope.items[0].tags)
        // continuation key is `cursor` (NOT next_cursor)
        assertEquals("cur_2", envelope.cursor)
        // sparse project: tags / settings default to empty
        assertTrue(envelope.items[1].tags.isEmpty())
        assertTrue(envelope.items[1].settings.isEmpty())
    }

    @Test
    fun listProjects_passesCursorAndLimitQueries_whenProvided() = runTest {
        server.enqueue(jsonResponse("""{"items":[],"cursor":null}"""))

        val envelope = projectsApi().listProjects(cursor = "cur_1", limit = 5)

        val recorded = server.takeRequest()
        assertEquals("/v1/projects", recorded.requestUrl?.encodedPath)
        assertEquals("cur_1", recorded.requestUrl?.queryParameter("cursor"))
        assertEquals("5", recorded.requestUrl?.queryParameter("limit"))
        assertTrue(envelope.items.isEmpty())
        assertNull(envelope.cursor)
    }

    // ---- getProject: BARE ProjectOut (no envelope), {projectId} path ----

    @Test
    fun getProject_decodesBareProject_substitutesProjectIdPath() = runTest {
        server.enqueue(
            jsonResponse(
                """{"id":"prj_1","owner":"usr_9","name":"Demo","description":"d",
                     "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z"}""",
            ),
        )

        val project = projectsApi().getProject("prj_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/projects/prj_1", recorded.requestUrl?.encodedPath)
        // bare object, not wrapped in an envelope
        assertEquals("prj_1", project.id)
        assertEquals("Demo", project.name)
        assertEquals("2026-06-01T09:15:00Z", project.updatedAt)
    }

    // ---- getProjectDetail: { project, files[], cursor }, {projectId} path, limit + cursor queries ----

    @Test
    fun getProjectDetail_decodesEnvelope_substitutesPath_passesLimitAndCursor() = runTest {
        server.enqueue(
            jsonResponse(
                """{"project":{"id":"prj_1","owner":"usr_9","name":"Demo",
                     "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z"},
                   "files":[{"id":"f1","provider":"google_drive","provider_ref":"gd_1"}],
                   "cursor":"cur_files"}""",
            ),
        )

        val envelope = projectsApi().getProjectDetail("prj_1", limit = 10, cursor = "c0")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/projects/prj_1/detail", recorded.requestUrl?.encodedPath)
        assertEquals("10", recorded.requestUrl?.queryParameter("limit"))
        assertEquals("c0", recorded.requestUrl?.queryParameter("cursor"))
        assertEquals("prj_1", envelope.project.id)
        // files decode leniently (raw maps); provider lives on the file, not the project
        assertEquals(1, envelope.files.size)
        assertEquals("google_drive", envelope.files[0]["provider"])
        assertEquals("cur_files", envelope.cursor)
    }

    // ---- startGoogleDrive: account-scoped POST, EMPTY body, returns ProviderOAuthStartOut ----

    @Test
    fun startGoogleDrive_postsEmptyBody_toAccountScopedPath_decodesStartOut() = runTest {
        server.enqueue(
            jsonResponse(
                """{"provider":"google_drive",
                     "authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?x=1",
                     "state":"st_1","expires_at":"2026-06-06T12:10:00Z"}""",
            ),
        )

        val start = projectsApi().startGoogleDrive()

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        // account-scoped (NO {projectId} segment)
        assertEquals("/v1/projects/providers/google_drive/oauth/start", recorded.requestUrl?.encodedPath)
        // the start request body is EMPTY (no redirect_uri)
        assertEquals(0L, recorded.bodySize)
        assertEquals("st_1", start.state)
        assertTrue(start.authorizationUrl.startsWith("https://accounts.google.com"))
    }

    // ---- completeGoogleDrive: POST {code,state}, returns a CREDENTIAL (NOT a project) ----

    @Test
    fun completeGoogleDrive_postsCodeAndState_decodesCredential() = runTest {
        server.enqueue(
            jsonResponse(
                """{"provider":"google_drive",
                     "scopes":["https://www.googleapis.com/auth/drive.readonly"],
                     "created_at":"2026-06-06T12:10:00Z","updated_at":"2026-06-06T12:10:00Z"}""",
            ),
        )

        val credential = projectsApi().completeGoogleDrive(
            ProviderOAuthCallbackIn(code = "4/abc", state = "st_1"),
        )

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/v1/projects/providers/google_drive/oauth/callback", recorded.requestUrl?.encodedPath)
        val sentBody = recorded.body.readUtf8()
        assertTrue(sentBody.contains(""""code":"4/abc""""))
        assertTrue(sentBody.contains(""""state":"st_1""""))
        // the response is a CREDENTIAL (provider + scopes), NOT a project
        assertEquals("google_drive", credential.provider)
        assertEquals(listOf("https://www.googleapis.com/auth/drive.readonly"), credential.scopes)
    }

    // ---- getProviderCredential: {provider} path, optional org query ----

    @Test
    fun getProviderCredential_substitutesProviderPath_passesOrgQuery() = runTest {
        server.enqueue(jsonResponse("""{"provider":"google_drive"}"""))

        projectsApi().getProviderCredential(ProjectProviders.GOOGLE_DRIVE, org = "org_1")

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/v1/projects/providers/google_drive/credentials", recorded.requestUrl?.encodedPath)
        assertEquals("org_1", recorded.requestUrl?.queryParameter("org"))
    }

    @Test
    fun getProviderCredential_404_surfacesAsHttpException_forNotConnectedMapping() = runTest {
        server.enqueue(MockResponse().setResponseCode(404))

        val error = runCatching {
            projectsApi().getProviderCredential(ProjectProviders.GOOGLE_DRIVE)
        }.exceptionOrNull()

        val recorded = server.takeRequest()
        assertEquals("/v1/projects/providers/google_drive/credentials", recorded.requestUrl?.encodedPath)
        // a 404 here is the wire signal the repository folds to "not connected"
        assertTrue(error is HttpException)
        assertEquals(404, (error as HttpException).code())
    }

    // ---- error surfaces ----

    @Test
    fun getProject_404_surfacesAsHttpException() = runTest {
        server.enqueue(MockResponse().setResponseCode(404))

        val error = runCatching { projectsApi().getProject("missing") }.exceptionOrNull()

        assertTrue(error is HttpException)
        assertEquals(404, (error as HttpException).code())
    }

    @Test
    fun listProjects_500_surfacesAsHttpException() = runTest {
        server.enqueue(MockResponse().setResponseCode(500))

        val error = runCatching { projectsApi().listProjects() }.exceptionOrNull()

        assertTrue(error is HttpException)
        assertEquals(500, (error as HttpException).code())
    }
}
