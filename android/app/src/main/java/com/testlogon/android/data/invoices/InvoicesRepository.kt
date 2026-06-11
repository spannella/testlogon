package com.testlogon.android.data.invoices

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
 * AND-243 — invoices data layer over [InvoicesApi].
 *
 * Wraps every call in [ApiResult] (matching the billing/subscriptions repositories): CancellationException
 * is re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport failures to NetworkError.
 * DTOs are mapped to domain before returning (no raw DTOs leak out).
 *
 * GET reads (list/detail) are idempotent (the core-network RetryInterceptor handles bounded retry); the
 * email POST is non-idempotent and never auto-retried (the ViewModel guards against duplicate taps).
 * [pdfUrl] builds the absolute `/ui/invoices/{n}/pdf` URL for the Custom Tabs / browser PDF view-download.
 */
interface InvoicesRepository {

    /** One page of invoices (cursor pagination; null cursor = first page). Idempotent GET. */
    suspend fun getInvoices(cursor: String?, limit: Int): ApiResult<InvoicePage>

    /** A single invoice's full detail (line items + totals). Idempotent GET. */
    suspend fun getInvoice(invoiceNumber: String): ApiResult<InvoiceDetail>

    /**
     * AND-249 — the flat tax breakdown for an invoice (subtotal/tax/total), derived from [getInvoice]
     * (there is no dedicated tax endpoint). Idempotent GET.
     */
    suspend fun getInvoiceTax(invoiceNumber: String): ApiResult<InvoiceTax>

    /** Email a copy of the invoice (recipient is server-determined). Non-idempotent. */
    suspend fun emailInvoice(invoiceNumber: String): ApiResult<EmailInvoiceResult>

    /** Absolute URL of the invoice PDF, for opening in a browser / Custom Tab (carries session cookies). */
    fun pdfUrl(invoiceNumber: String): String
}

/**
 * AND-243 — supplies the runtime backend base URL (normalized to end with '/') for building the absolute
 * PDF URL, so the repository stays JVM-unit-testable without an Android Context (SettingsStore needs one).
 */
fun interface InvoiceBaseUrlProvider {
    fun baseUrl(): String
}

@Singleton
class InvoicesRepositoryImpl @Inject constructor(
    private val api: InvoicesApi,
    private val errorParser: ApiErrorParser,
    private val baseUrlProvider: InvoiceBaseUrlProvider,
) : InvoicesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getInvoices(cursor: String?, limit: Int): ApiResult<InvoicePage> =
        withContext(io) {
            call { api.listInvoices(cursor = cursor, limit = limit) }.map { it.toPage() }
        }

    override suspend fun getInvoice(invoiceNumber: String): ApiResult<InvoiceDetail> = withContext(io) {
        call { api.getInvoice(invoiceNumber) }.map { it.toDetail() }
    }

    override suspend fun getInvoiceTax(invoiceNumber: String): ApiResult<InvoiceTax> = withContext(io) {
        call { api.getInvoice(invoiceNumber) }.map { it.toDetail().toTax() }
    }

    override suspend fun emailInvoice(invoiceNumber: String): ApiResult<EmailInvoiceResult> =
        withContext(io) {
            call { api.emailInvoice(invoiceNumber) }.map { it.toDomain() }
        }

    override fun pdfUrl(invoiceNumber: String): String {
        // baseUrl is normalized to end with '/'; the path is relative (no leading slash).
        val base = baseUrlProvider.baseUrl().let { if (it.endsWith("/")) it else "$it/" }
        val encoded = java.net.URLEncoder.encode(invoiceNumber, "UTF-8")
        return "${base}ui/invoices/$encoded/pdf"
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
