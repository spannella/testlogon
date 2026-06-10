package com.testlogon.android.data.invoices

/**
 * AND-243 — framework-free invoices domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/billing, data/subscriptions):
 *  - Money is integer cents + ISO-4217 currency (the backend's `*_cents`). No BigDecimal.
 *  - Timestamps are epoch-seconds Longs (NOT java.time) so this stays JVM-unit-testable; the screen
 *    formats via the pure formatEpochDate helper. created_at==0 (the server default) maps to null.
 *  - InvoiceStatus uses an UNKNOWN fallback for forward compatibility (the backend `status` is a free
 *    string; observed values are `generated` and `emailed`).
 *
 * Mapping is TOTAL: unknown enum strings -> UNKNOWN, absent lists -> empty; no exceptions thrown.
 */

/** Integer cents + ISO-4217 currency. */
data class InvoiceMoney(val cents: Long, val currency: String)

/** Invoice status. Backend default is `generated`; the only badge the web surfaces is `emailed`. */
enum class InvoiceStatus {
    GENERATED,
    EMAILED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): InvoiceStatus = when (value?.lowercase()) {
            "generated" -> GENERATED
            "emailed" -> EMAILED
            else -> UNKNOWN
        }
    }
}

/** A single invoice line item. amount_cents is the line amount (no per-unit field exists). */
data class InvoiceLineItem(
    val description: String,
    val quantity: Int,
    val amount: InvoiceMoney,
)

/**
 * An invoice list row (the paged list projection). Carries enough to render the row without a detail
 * fetch (number, date, type, status badge, total). [invoiceNumber] is the stable row/paging key and the
 * path param for detail/email/pdf.
 */
data class InvoiceSummary(
    val invoiceNumber: String,
    val invoiceId: String,
    val invoiceType: String,
    val status: InvoiceStatus,
    val total: InvoiceMoney,
    val createdAtEpochSeconds: Long?,
)

/** Full invoice detail (line items + totals + parties). */
data class InvoiceDetail(
    val invoiceNumber: String,
    val invoiceId: String,
    val invoiceType: String,
    val status: InvoiceStatus,
    val sellerName: String,
    val buyerName: String,
    val buyerEmail: String,
    val paymentMethodSummary: String,
    val lineItems: List<InvoiceLineItem>,
    val amount: InvoiceMoney,
    val tax: InvoiceMoney,
    val total: InvoiceMoney,
    val createdAtEpochSeconds: Long?,
)

/** One page of invoice summaries + the cursor for the next page (null = end of pagination). */
data class InvoicePage(
    val invoices: List<InvoiceSummary>,
    val nextCursor: String?,
)

/** Result of the email-invoice action (the recipient + the server message). */
data class EmailInvoiceResult(
    val ok: Boolean,
    val emailedTo: String,
    val message: String,
)

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun InvoiceLineItemDto.toDomain(currency: String): InvoiceLineItem = InvoiceLineItem(
    description = description,
    quantity = quantity,
    amount = InvoiceMoney(amountCents, currency),
)

internal fun InvoiceDto.toSummary(): InvoiceSummary = InvoiceSummary(
    invoiceNumber = invoiceNumber,
    invoiceId = invoiceId,
    invoiceType = invoiceType,
    status = InvoiceStatus.fromWire(status),
    total = InvoiceMoney(totalCents, currency),
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
)

internal fun InvoiceDto.toDetail(): InvoiceDetail = InvoiceDetail(
    invoiceNumber = invoiceNumber,
    invoiceId = invoiceId,
    invoiceType = invoiceType,
    status = InvoiceStatus.fromWire(status),
    sellerName = sellerName,
    buyerName = buyerName,
    buyerEmail = buyerEmail,
    paymentMethodSummary = paymentMethodSummary,
    lineItems = lineItems.map { it.toDomain(currency) },
    amount = InvoiceMoney(amountCents, currency),
    tax = InvoiceMoney(taxCents, currency),
    total = InvoiceMoney(totalCents, currency),
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
)

internal fun InvoiceListDto.toPage(): InvoicePage = InvoicePage(
    invoices = invoices.map { it.toSummary() },
    nextCursor = nextCursor?.takeIf { it.isNotBlank() },
)

internal fun InvoiceEmailDto.toDomain(): EmailInvoiceResult = EmailInvoiceResult(
    ok = ok,
    emailedTo = emailedTo,
    message = message,
)
