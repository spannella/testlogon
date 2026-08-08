package com.testlogon.android.data.stories

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * PAR-16 — immutable domain model for one Story Highlight group (a titled collection of a user's
 * pinned stories). Reuses [StorySegment] for the member stories so the highlights UI can render them
 * with the same mapping rules as the viewer.
 */
data class HighlightGroup(
    val id: String,
    val title: String,
    val coverUrl: String?,
    val stories: List<StorySegment>,
) {
    val storyCount: Int get() = stories.size
    /** First member story's media, used as a cover fallback when [coverUrl] is absent. */
    val coverFallbackUrl: String? get() = coverUrl ?: stories.firstOrNull()?.mediaUrl
}

internal fun HighlightGroupDto.toDomain(): HighlightGroup = HighlightGroup(
    id = highlightGroupId,
    title = title,
    coverUrl = coverUrl?.takeIf { it.isNotBlank() },
    stories = stories.map { it.toDomain() },
)

/**
 * PAR-16 — Story Highlights data layer over [HighlightsApi].
 *
 * A thin, stateless repository (no in-memory cache — the ViewModel owns UI state and re-reads after each
 * mutation). [highlights] reads a user's groups; [createGroup]/[deleteGroup]/[pin]/[unpin] mutate and
 * return the raw action result so the caller can re-read. Ownership is enforced server-side from the UI
 * session (a non-owner mutation returns 403, folded into [ApiResult.Failure]).
 */
interface HighlightsRepository {

    /** A user's highlight groups (each with its member stories). */
    suspend fun highlights(userId: String): ApiResult<List<HighlightGroup>>

    /** Create a highlight group for the current user; returns the new group id. */
    suspend fun createGroup(title: String, coverUrl: String?): ApiResult<String>

    /** Delete one of the current user's highlight groups. */
    suspend fun deleteGroup(groupId: String): ApiResult<Unit>

    /** Pin [storyId] into [groupId] (null = default/ungrouped). */
    suspend fun pin(storyId: String, groupId: String?): ApiResult<Unit>

    /** Unpin [storyId] from highlights. */
    suspend fun unpin(storyId: String): ApiResult<Unit>
}

@Singleton
class HighlightsRepositoryImpl @Inject constructor(
    private val api: HighlightsApi,
    private val errorParser: ApiErrorParser,
) : HighlightsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun highlights(userId: String): ApiResult<List<HighlightGroup>> =
        withContext(io) {
            call { api.getHighlights(userId) }.map { dto -> dto.groups.map { it.toDomain() } }
        }

    override suspend fun createGroup(title: String, coverUrl: String?): ApiResult<String> =
        withContext(io) {
            call {
                api.createGroup(
                    CreateHighlightGroupReqDto(
                        title = title.trim(),
                        coverUrl = coverUrl?.trim()?.ifBlank { null },
                    ),
                )
            }.map { it.highlightGroupId }
        }

    override suspend fun deleteGroup(groupId: String): ApiResult<Unit> = withContext(io) {
        call { api.deleteGroup(groupId) }.map { }
    }

    override suspend fun pin(storyId: String, groupId: String?): ApiResult<Unit> = withContext(io) {
        call {
            api.pin(storyId, AddStoryToHighlightReqDto(groupId = groupId?.trim()?.ifBlank { null }))
        }.map { }
    }

    override suspend fun unpin(storyId: String): ApiResult<Unit> = withContext(io) {
        call { api.unpin(storyId) }.map { }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
