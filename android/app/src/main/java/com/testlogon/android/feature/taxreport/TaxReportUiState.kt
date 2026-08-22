package com.testlogon.android.feature.taxreport

/**
 * Reporting year filter for the tax-lots surface. A [TaxYear] scopes fills to a calendar year (UTC) or
 * ALL. Pure so the boundary is unit-testable: the caller supplies the fills' timestamps; the ViewModel
 * derives the list of years actually present in the data so the chooser never offers an empty year.
 */
data class TaxYear(val year: Int?) {
    /** null year == "All years". */
    val isAll: Boolean get() = year == null
    val label: String get() = year?.toString() ?: "All"

    companion object {
        val ALL = TaxYear(null)
    }
}

/**
 * UI state for the Tax Lots & Realized-Gains screen. The ViewModel assembles all fills once (paginating
 * the live feed), then re-derives everything purely when the [method] or [year] changes (no re-fetch).
 * Nothing here moves money; it is a read-only reporting view over spot/margin fills.
 *
 * [loading] gates the initial spinner; [unavailable] marks a fully-degraded surface (fills feed 404 /
 * empty AND no data); [error] carries a retryable transient failure; [degraded] is a soft banner (the
 * fills history endpoint returned nothing / is thin) shown alongside whatever data we do have.
 */
data class TaxReportUiState(
    val loading: Boolean = true,
    val unavailable: Boolean = false,
    val degraded: Boolean = false,
    val error: String? = null,
    val method: TaxLotMath.CostBasisMethod = TaxLotMath.CostBasisMethod.FIFO,
    val year: TaxYear = TaxYear.ALL,
    /** The calendar years present in the loaded fills (descending) + ALL, for the year chooser. */
    val availableYears: List<TaxYear> = listOf(TaxYear.ALL),
    val realizedLots: List<TaxLotMath.RealizedLot> = emptyList(),
    val summary: TaxLotMath.RealizedSummary? = null,
    val openLots: List<TaxLotMath.OpenLot> = emptyList(),
    val unrealized: List<TaxLotMath.UnrealizedRow> = emptyList(),
    /** True when there were no marks available to value the open lots (unrealized section unpriced). */
    val marksUnavailable: Boolean = false,
    /** The realized-lots CSV for the current method+year, ready to hand to the share sheet. */
    val csv: String = "",
    val csvName: String = "tax-lots",
) {
    val isEmpty: Boolean
        get() = !loading && !unavailable && error == null &&
            realizedLots.isEmpty() && openLots.isEmpty()
}
