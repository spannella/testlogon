package com.testlogon.android.feature.projects

import androidx.paging.PagingSource
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.projects.ProviderCallbackParams
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.projects.ProjectDetailEnvelope
import com.testlogon.android.core.network.projects.ProjectListEnvelope
import com.testlogon.android.core.network.projects.ProjectOut
import com.testlogon.android.feature.projects.data.ProjectsPagingSource
import com.testlogon.android.feature.projects.data.ProjectsRepository
import com.testlogon.android.feature.projects.data.ProjectsRepositoryImpl
import com.testlogon.android.feature.projects.testing.FakeProjectsApi
import com.testlogon.android.feature.projects.testing.FakeProjectsApi.Companion.sampleCredentialOut
import com.testlogon.android.feature.projects.testing.FakeProjectsApi.Companion.sampleProjectOut
import com.testlogon.android.feature.projects.testing.FakeProjectsApi.Companion.sampleStartOut
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-374 - tests for [ProjectsRepositoryImpl]: getProjectDetail unwraps { project, files[] } (files ignored),
 * startGoogleDrive maps all four start fields, completeGoogleDrive posts {code,state} + returns a credential
 * (NOT a project), isDriveConnected maps a 200 -> connected and a 404/error -> NOT connected (a normal state).
 * Plus a direct [ProjectsPagingSource].load() test (cursor field is `cursor`, blank-cursor termination,
 * http-error -> Error). Recording fakes record the @Path / @Query / @Body BEFORE throwing.
 */
class ProjectsRepositoryTest {

    private fun repo(api: FakeProjectsApi) = ProjectsRepositoryImpl(
        api = api,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun getProjectDetail_unwrapsProject_ignoresFiles() = runTest {
        val api = FakeProjectsApi(
            detail = {
                ProjectDetailEnvelope(
                    project = sampleProjectOut("p1"),
                    files = listOf(mapOf("id" to "f1"), mapOf("id" to "f2")),
                    cursor = "next",
                )
            },
        )
        val result = repo(api).getProjectDetail("p1")

        assertTrue(result is ApiResult.Success)
        val project = (result as ApiResult.Success).data
        assertEquals("p1", project.id)
        assertEquals("usr_1", project.owner)
        assertEquals(listOf("a", "b"), project.tags)
        assertEquals("2026-05-30T12:01:02Z", project.updatedAt)
        assertEquals(Triple("p1", 20, null), api.getProjectDetailArgs.single())
    }

    @Test
    fun getProjectDetail_401_isFailureWithStatus401_recordedBeforeThrow() = runTest {
        val api = FakeProjectsApi(detail = { throw FakeProjectsApi.httpProjectError(401) })
        val result = repo(api).getProjectDetail("p1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        assertEquals(1, api.getProjectDetailArgs.size)
    }

    @Test
    fun startGoogleDrive_mapsAllFourFields() = runTest {
        val api = FakeProjectsApi(start = { sampleStartOut(state = "st_X") })
        val result = repo(api).startGoogleDrive()
        assertTrue(result is ApiResult.Success)
        val start = (result as ApiResult.Success).data
        assertEquals("google_drive", start.provider)
        assertEquals("st_X", start.state)
        assertTrue(start.authorizationUrl.startsWith("https://accounts.google.com"))
        assertEquals("2026-06-06T12:10:00Z", start.expiresAt)
        assertEquals(1, api.startCallCount)
    }

    @Test
    fun completeGoogleDrive_postsCodeAndState_returnsCredentialConnected() = runTest {
        val api = FakeProjectsApi(callback = { sampleCredentialOut() })
        val result = repo(api).completeGoogleDrive(ProviderCallbackParams(code = "4/abc", state = "st_1"))
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.connected)
        val body = api.callbackArgs.single()
        assertEquals("4/abc", body.code)
        assertEquals("st_1", body.state)
    }

    @Test
    fun completeGoogleDrive_blankCodeOrState_doesNotPost() = runTest {
        val api = FakeProjectsApi()
        val result = repo(api).completeGoogleDrive(ProviderCallbackParams(code = null, state = "st_1"))
        assertTrue(result is ApiResult.Success)
        assertFalse((result as ApiResult.Success).data.connected)
        assertTrue(api.callbackArgs.isEmpty())
    }

    @Test
    fun isDriveConnected_200_isConnected() = runTest {
        val api = FakeProjectsApi(credential = { sampleCredentialOut() })
        val result = repo(api).isDriveConnected()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.connected)
        assertEquals("google_drive" to null, api.credentialArgs.single())
    }

    @Test
    fun isDriveConnected_404_isNotConnected_notAnError() = runTest {
        val api = FakeProjectsApi(credential = { throw FakeProjectsApi.httpProjectError(404) })
        val result = repo(api).isDriveConnected()
        assertTrue(result is ApiResult.Success)
        assertFalse((result as ApiResult.Success).data.connected)
    }

    @Test
    fun pagingSource_firstPage_mapsItems_andNextKeyFromCursor() = runTest {
        val api = FakeProjectsApi(
            projects = {
                ProjectListEnvelope(
                    items = listOf(sampleProjectOut("p1"), sampleProjectOut("p2")),
                    cursor = "cur2",
                )
            },
        )
        val source = ProjectsPagingSource(api, ProjectsRepository.PAGE_SIZE)
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("p1", "p2"), page.data.map { it.id })
        assertNull(page.prevKey)
        assertEquals("cur2", page.nextKey)
        assertEquals(null to 20, api.listProjectsArgs.single())
    }

    @Test
    fun pagingSource_blankCursor_endsPagination() = runTest {
        val api = FakeProjectsApi(
            projects = { ProjectListEnvelope(items = listOf(sampleProjectOut("p1")), cursor = "") },
        )
        val page = ProjectsPagingSource(api, ProjectsRepository.PAGE_SIZE)
            .load(PagingSource.LoadParams.Refresh(null, 20, false)) as PagingSource.LoadResult.Page
        assertNull(page.nextKey)
    }

    @Test
    fun pagingSource_httpError_becomesLoadResultError() = runTest {
        val api = FakeProjectsApi(projects = { throw FakeProjectsApi.httpProjectError(500) })
        val result = ProjectsPagingSource(api, ProjectsRepository.PAGE_SIZE)
            .load(PagingSource.LoadParams.Refresh(null, 20, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }

    @Test
    fun pagingSource_usesCursorKey_onAppend() = runTest {
        val api = FakeProjectsApi(
            projects = { ProjectListEnvelope(items = listOf(sampleProjectOut("p3")), cursor = null) },
        )
        ProjectsPagingSource(api, ProjectsRepository.PAGE_SIZE)
            .load(PagingSource.LoadParams.Append("cur2", 20, false))
        assertEquals("cur2" to 20, api.listProjectsArgs.single())
    }

    @Test
    fun ignoreUnusedHelper() {
        // keep the ProjectOut import referenced (used implicitly by the sample builders).
        val p: ProjectOut = sampleProjectOut("x")
        assertEquals("x", p.id)
    }
}
