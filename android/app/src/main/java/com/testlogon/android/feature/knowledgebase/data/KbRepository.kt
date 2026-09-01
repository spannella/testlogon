package com.testlogon.android.feature.knowledgebase.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kb.KbArticle
import com.testlogon.android.core.model.kb.KbArticleSummary
import com.testlogon.android.core.model.kb.KbCategory
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kb.KbApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * KB-AND-1 - READ-ONLY data layer for the Knowledge Base (help centre) surface, over the [KbApi] transport.
 *
 * Reads the AUTHENTICATED /kb/ endpoints (list / search / detail / categories) and maps the RAW DTO to the
 * core-model domain, folding into [ApiResult] via [call] (mirrors AND-372 TicketsRepository).
 *
 * DEGRADE-ON-404: the KB routes 404 when knowledge_base_enabled is off (flag defaults off). A 404 is NOT an
 * error surface here - the list / search / categories reads map a 404 to an EMPTY Success (the screen shows a
 * clean empty state), and the article detail read maps a 404 to Success(null) (the screen shows "not found").
 * Every OTHER HTTP status, malformed JSON, and transport failure still surfaces as Failure / NetworkError.
 *
 * NO mutations, NO Room cache, NO paging this wave (the KB list is a single bounded first-page GET; cursor
 * paging is DEFERRED - the cursor is threaded on the API but the repo takes the first page).
 */
interface KbRepository {

    /** GET published articles (optionally scoped to [categoryId]), mapped. 404 -> empty. */
    suspend fun listArticles(categoryId: String? = null): ApiResult<List<KbArticleSummary>>

    /** Full-text search, mapped. A blank query and a 404 both map to an empty Success. */
    suspend fun search(query: String): ApiResult<List<KbArticleSummary>>

    /** GET one full article, mapped. 404 -> Success(null) (flag off OR unknown id -> "not found"). */
    suspend fun getArticle(articleId: String): ApiResult<KbArticle?>

    /** GET the KB categories, mapped. 404 -> empty. */
    suspend fun listCategories(): ApiResult<List<KbCategory>>

    companion object {
        const val PAGE_LIMIT = 50
    }
}

@Singleton
class KbRepositoryImpl @Inject constructor(
    private val api: KbApi,
    private val errorParser: ApiErrorParser,
) : KbRepository {

    override suspend fun listArticles(categoryId: String?): ApiResult<List<KbArticleSummary>> =
        withContext(Dispatchers.IO) {
            callOr404Empty(emptyList()) {
                api.listArticles(categoryId = categoryId, limit = KbRepository.PAGE_LIMIT)
                    .items.map { it.toDomain() }
            }
        }

    override suspend fun search(query: String): ApiResult<List<KbArticleSummary>> =
        withContext(Dispatchers.IO) {
            val q = query.trim()
            if (q.isEmpty()) return@withContext ApiResult.Success(emptyList())
            callOr404Empty(emptyList()) {
                api.search(q = q, limit = KbRepository.PAGE_LIMIT).items.map { it.toDomain() }
            }
        }

    override suspend fun getArticle(articleId: String): ApiResult<KbArticle?> =
        withContext(Dispatchers.IO) {
            callOr404Empty<KbArticle?>(null) {
                api.getArticle(articleId).toDomain()
            }
        }

    override suspend fun listCategories(): ApiResult<List<KbCategory>> =
        withContext(Dispatchers.IO) {
            callOr404Empty(emptyList()) {
                api.listCategories().categories.map { it.toDomain() }
            }
        }

    /**
     * Folds a block into [ApiResult] with DEGRADE-ON-404: an HTTP 404 (KB flag off / unknown id) resolves to
     * Success([fallback]) instead of a Failure. Every other HTTP status -> Failure (via [ApiErrorParser],
     * preserving the code so a 401 still surfaces as Failure(status=401) for the VM's re-auth handoff);
     * malformed JSON -> Failure; transport failures -> NetworkError. Cancellation is re-thrown.
     */
    private suspend fun <T> callOr404Empty(fallback: T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == HTTP_NOT_FOUND) ApiResult.Success(fallback)
        else ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_NOT_FOUND = 404
    }
}
