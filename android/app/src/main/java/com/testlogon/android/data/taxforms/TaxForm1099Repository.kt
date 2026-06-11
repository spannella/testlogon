package com.testlogon.android.data.taxforms

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
 * AND-247 — 1099-NEC data layer over [TaxForm1099Api].
 *
 * Wraps every call in [ApiResult] (matching data/invoices + data/taxdocs): CancellationException is
 * re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport failures to NetworkError.
 * DTOs are mapped to domain before returning (no raw DTOs leak out). The list is sorted newest tax-year
 * first (AND-247 FR-2).
 *
 * [downloadUrl] fetches the dedicated /download endpoint's JSON `download_url` (the bytes live there);
 * the URL is opened in a Custom Tab via the AND-243 InvoicePdfLauncher so the platform handles the PDF.
 * It is re-requested per download because the presigned link expires (AND-247 §7).
 */
interface TaxForm1099Repository {

    /** All of the user's 1099-NEC forms (newest tax-year first). Idempotent GET. */
    suspend fun list1099s(): ApiResult<List<Form1099>>

    /** A single year's 1099-NEC metadata. Idempotent GET. */
    suspend fun get1099(taxYear: Int): ApiResult<Form1099>

    /** Resolve the year's downloadable PDF URL (re-fetched per download; the link expires). */
    suspend fun downloadUrl(taxYear: Int): ApiResult<String>
}

@Singleton
class TaxForm1099RepositoryImpl @Inject constructor(
    private val api: TaxForm1099Api,
    private val errorParser: ApiErrorParser,
) : TaxForm1099Repository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list1099s(): ApiResult<List<Form1099>> = withContext(io) {
        call { api.list1099s() }.map { dto ->
            dto.items.map { it.toDomain() }.sortedByDescending { it.taxYear }
        }
    }

    override suspend fun get1099(taxYear: Int): ApiResult<Form1099> = withContext(io) {
        call { api.get1099(taxYear) }.map { it.toDomain() }
    }

    override suspend fun downloadUrl(taxYear: Int): ApiResult<String> = withContext(io) {
        call { api.download1099Url(taxYear) }.map { it.downloadUrl }
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
