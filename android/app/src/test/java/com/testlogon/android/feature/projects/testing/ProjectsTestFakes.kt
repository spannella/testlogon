package com.testlogon.android.feature.projects.testing

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.projects.DriveConnection
import com.testlogon.android.core.model.projects.Project
import com.testlogon.android.core.model.projects.ProviderCallbackParams
import com.testlogon.android.core.model.projects.ProviderStart
import com.testlogon.android.core.network.projects.ProjectDetailEnvelope
import com.testlogon.android.core.network.projects.ProjectListEnvelope
import com.testlogon.android.core.network.projects.ProjectOut
import com.testlogon.android.core.network.projects.ProjectsApi
import com.testlogon.android.core.network.projects.ProviderCredentialOut
import com.testlogon.android.core.network.projects.ProviderOAuthCallbackIn
import com.testlogon.android.core.network.projects.ProviderOAuthStartOut
import com.testlogon.android.feature.projects.data.ProjectsRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-374 - in-memory fakes for the projects unit tests.
 *
 * The :app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * [ProjectsApi] (no Moshi). Each call RECORDS its args / call-count BEFORE honouring a configured throw, so a
 * test can assert the @Path / @Query / @Body was passed even when the call fails. Helper / recording names are
 * distinct (the -Project- infix) and never shadow an interface method. Mirrors the AND-372 FakeTicketsApi.
 */
class FakeProjectsApi(
    var projects: () -> ProjectListEnvelope = { ProjectListEnvelope(items = emptyList(), cursor = null) },
    var detail: () -> ProjectDetailEnvelope = {
        ProjectDetailEnvelope(project = sampleProjectOut("p1"), files = emptyList(), cursor = null)
    },
    var project: () -> ProjectOut = { sampleProjectOut("p1") },
    var start: () -> ProviderOAuthStartOut = { sampleStartOut() },
    var callback: () -> ProviderCredentialOut = { sampleCredentialOut() },
    var credential: () -> ProviderCredentialOut = { sampleCredentialOut() },
) : ProjectsApi {

    val listProjectsArgs = mutableListOf<Pair<String?, Int>>()
    val getProjectIds = mutableListOf<String>()
    val getProjectDetailArgs = mutableListOf<Triple<String, Int, String?>>()
    var startCallCount = 0
    val callbackArgs = mutableListOf<ProviderOAuthCallbackIn>()
    val credentialArgs = mutableListOf<Pair<String, String?>>()

    override suspend fun listProjects(cursor: String?, limit: Int): ProjectListEnvelope {
        listProjectsArgs += cursor to limit
        return projects()
    }

    val createProjectArgs = mutableListOf<com.testlogon.android.core.network.projects.ProjectCreateIn>()

    override suspend fun createProject(body: com.testlogon.android.core.network.projects.ProjectCreateIn): ProjectOut {
        createProjectArgs += body
        return project()
    }

    override suspend fun getProject(projectId: String): ProjectOut {
        getProjectIds += projectId
        return project()
    }

    override suspend fun getProjectDetail(projectId: String, limit: Int, cursor: String?): ProjectDetailEnvelope {
        getProjectDetailArgs += Triple(projectId, limit, cursor)
        return detail()
    }

    override suspend fun startGoogleDrive(): ProviderOAuthStartOut {
        startCallCount++
        return start()
    }

    override suspend fun completeGoogleDrive(body: ProviderOAuthCallbackIn): ProviderCredentialOut {
        callbackArgs += body
        return callback()
    }

    override suspend fun getProviderCredential(provider: String, org: String?): ProviderCredentialOut {
        credentialArgs += provider to org
        return credential()
    }

    companion object {
        fun httpProjectError(status: Int): HttpException = HttpException(
            Response.error<Any>(
                status,
                """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
            ),
        )

        fun sampleProjectOut(id: String): ProjectOut = ProjectOut(
            id = id,
            owner = "usr_1",
            name = "Project $id",
            description = "desc $id",
            tags = listOf("a", "b"),
            settings = emptyMap(),
            createdAt = "2026-05-01T10:00:00Z",
            updatedAt = "2026-05-30T12:01:02Z",
        )

        fun sampleStartOut(state: String = "st_1"): ProviderOAuthStartOut = ProviderOAuthStartOut(
            provider = "google_drive",
            authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth?x=1",
            state = state,
            expiresAt = "2026-06-06T12:10:00Z",
        )

        fun sampleCredentialOut(): ProviderCredentialOut = ProviderCredentialOut(
            provider = "google_drive",
            org = null,
            scopes = listOf("https://www.googleapis.com/auth/drive.readonly"),
            metadata = emptyMap(),
            createdAt = "2026-06-06T12:10:00Z",
            updatedAt = "2026-06-06T12:10:00Z",
        )
    }
}

/**
 * AND-374 - a fake [ProjectsRepository] for the ViewModel tests. The detail / connection / start / callback
 * results are independently swappable so a test can vary a second (refresh) read. The paged list returns empty
 * PagingData (the detail VM under test does not page). Recording helpers let a test assert the calls.
 */
class FakeProjectsRepo(
    var detailResult: ApiResult<Project> = ApiResult.Success(sampleProject("p1")),
    var driveConnectedResult: ApiResult<DriveConnection> = ApiResult.Success(DriveConnection(connected = false)),
    var startResult: ApiResult<ProviderStart> = ApiResult.Success(
        ProviderStart(provider = "google_drive", authorizationUrl = "https://auth", state = "st_1"),
    ),
    var callbackResult: ApiResult<DriveConnection> = ApiResult.Success(DriveConnection(connected = true)),
) : ProjectsRepository {

    var getProjectDetailCallCount = 0
    var startCallCount = 0
    val callbackArgs = mutableListOf<ProviderCallbackParams>()
    var isDriveConnectedCallCount = 0

    override fun projectsPager(): Flow<PagingData<Project>> = flowOf(PagingData.empty())

    var createProjectResult: ApiResult<Project>? = null

    override suspend fun createProject(
        name: String,
        description: String?,
        tags: List<String>,
    ): ApiResult<Project> = createProjectResult ?: error("no createProjectResult configured")

    override suspend fun getProjectDetail(projectId: String): ApiResult<Project> {
        getProjectDetailCallCount++
        return detailResult
    }

    override suspend fun startGoogleDrive(): ApiResult<ProviderStart> {
        startCallCount++
        return startResult
    }

    override suspend fun completeGoogleDrive(params: ProviderCallbackParams): ApiResult<DriveConnection> {
        callbackArgs += params
        return callbackResult
    }

    override suspend fun isDriveConnected(): ApiResult<DriveConnection> {
        isDriveConnectedCallCount++
        return driveConnectedResult
    }

    companion object {
        fun failure(status: Int = 500): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))

        fun sampleProject(id: String): Project = Project(
            id = id,
            owner = "usr_1",
            name = "Project $id",
            description = "desc $id",
            tags = listOf("a", "b"),
            createdAt = "2026-05-01T10:00:00Z",
            updatedAt = "2026-05-30T12:01:02Z",
        )
    }
}
