package com.testlogon.android.data.broadcast.qna

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-284 — live Q&A data layer.
 *
 * [questions] loads the viewer-visible list (status=featured, server-sorted by votes desc) + the
 * dedicated featured endpoint, then de-duplicates the featured id out of the list. [ask] posts a new
 * question; [setUpvote] dispatches to POST/DELETE .../vote based on the intended target state and adopts
 * the server-returned vote_count (the wire has no per-viewer voted flag). All return [ApiResult].
 */
interface LiveQaRepository {

    suspend fun mode(sessionId: String): ApiResult<Boolean>

    suspend fun questions(sessionId: String): ApiResult<QaSnapshot>

    suspend fun ask(sessionId: String, text: String): ApiResult<QaQuestion>

    /** voted=true -> POST .../vote; voted=false -> DELETE .../vote. Returns the updated question. */
    suspend fun setUpvote(sessionId: String, questionId: String, voted: Boolean): ApiResult<QaQuestion>
}

@Singleton
class LiveQaRepositoryImpl @Inject constructor(
    private val api: LiveQaApi,
    private val errorParser: ApiErrorParser,
) : LiveQaRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun mode(sessionId: String): ApiResult<Boolean> = withContext(io) {
        when (val result = call { api.getMode(sessionId) }) {
            is ApiResult.Success -> ApiResult.Success(result.data?.qaModeEnabled ?: false)
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun questions(sessionId: String): ApiResult<QaSnapshot> = withContext(io) {
        val listResult = call { api.getQuestions(sessionId, status = LiveQaApi.STATUS_FEATURED) }
        val list = when (listResult) {
            is ApiResult.Success -> listResult.data?.questions?.map { it.toDomain() } ?: emptyList()
            is ApiResult.Failure -> return@withContext listResult
            is ApiResult.NetworkError -> return@withContext listResult
        }
        // Featured is a best-effort overlay; a missing/null body is tolerated (banner simply hidden).
        val featured = when (val f = call { api.getFeatured(sessionId) }) {
            is ApiResult.Success -> f.data?.takeIf { it.questionId.isNotBlank() }?.toDomain()
            else -> list.firstOrNull { it.featured }
        }
        val deduped = if (featured == null) list else list.filterNot { it.id == featured.id }
        ApiResult.Success(QaSnapshot(featured = featured, questions = deduped))
    }

    override suspend fun ask(sessionId: String, text: String): ApiResult<QaQuestion> = withContext(io) {
        when (val result = call { api.ask(sessionId, AskQuestionDto(text = text)) }) {
            is ApiResult.Success -> {
                val data = result.data
                    ?: return@withContext ApiResult.Failure(
                        errorParser.fromThrowable(JsonDataException("empty ask body")),
                    )
                ApiResult.Success(data.toDomain())
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override suspend fun setUpvote(
        sessionId: String,
        questionId: String,
        voted: Boolean,
    ): ApiResult<QaQuestion> = withContext(io) {
        val result = if (voted) {
            call { api.upvote(sessionId, questionId) }
        } else {
            call { api.removeUpvote(sessionId, questionId) }
        }
        when (result) {
            is ApiResult.Success -> {
                val data = result.data
                    ?: return@withContext ApiResult.Failure(
                        errorParser.fromThrowable(JsonDataException("empty vote body")),
                    )
                ApiResult.Success(data.toDomain())
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    private suspend fun <T> call(block: suspend () -> Response<T>): ApiResult<T?> = try {
        val response = block()
        if (response.isSuccessful) {
            ApiResult.Success(response.body())
        } else {
            ApiResult.Failure(errorParser.from(HttpException(response)))
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** AND-284 — provides [LiveQaApi] + binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object LiveQaApiModule {

    @Provides
    @Singleton
    fun provideLiveQaApi(retrofit: Retrofit): LiveQaApi =
        retrofit.create(LiveQaApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class LiveQaDataModule {

    @Binds
    @Singleton
    abstract fun bindLiveQaRepository(impl: LiveQaRepositoryImpl): LiveQaRepository
}
