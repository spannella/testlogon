package com.testlogon.android.data.taxdocs

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
 * AND-246 — tax-documents data layer over [TaxDocsApi].
 *
 * Wraps the list call in [ApiResult]: CancellationException is re-thrown; HTTP errors fold to Failure
 * (via [ApiErrorParser]); transport failures to NetworkError. DTOs are mapped to domain before returning.
 * The list is sorted newest-first by year (nulls last), then by created_at (AND-246 FR-1).
 *
 * [pdfUrl] builds the absolute `/ui/tax-documents/document/{year}/pdf` URL for opening in a Custom Tab /
 * browser (reusing the AND-243 InvoicePdfLauncher pattern), so the session cookies carry the download.
 */
interface TaxDocsRepository {

    /** All of the user's generated tax documents (newest-first). Idempotent GET. */
    suspend fun listTaxDocuments(): ApiResult<List<TaxDocument>>

    /** Absolute URL of the year's tax-document PDF, for opening in a browser / Custom Tab. */
    fun pdfUrl(year: Int): String
}

/**
 * AND-246 — supplies the runtime backend base URL (normalized to end with '/') for building the absolute
 * PDF URL, so the repository stays JVM-unit-testable without an Android Context. Mirrors AND-243's
 * InvoiceBaseUrlProvider seam.
 */
fun interface TaxDocsBaseUrlProvider {
    fun baseUrl(): String
}

@Singleton
class TaxDocsRepositoryImpl @Inject constructor(
    private val api: TaxDocsApi,
    private val errorParser: ApiErrorParser,
    private val baseUrlProvider: TaxDocsBaseUrlProvider,
) : TaxDocsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listTaxDocuments(): ApiResult<List<TaxDocument>> = withContext(io) {
        call { api.listTaxDocuments() }.map { dto ->
            dto.documents.map { it.toDomain() }
                .sortedWith(
                    compareByDescending<TaxDocument> { it.year ?: Int.MIN_VALUE }
                        .thenByDescending { it.createdAtEpochSeconds ?: 0L },
                )
        }
    }

    override fun pdfUrl(year: Int): String {
        val base = baseUrlProvider.baseUrl().let { if (it.endsWith("/")) it else "$it/" }
        return "${base}ui/tax-documents/document/$year/pdf"
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
