package com.testlogon.android.feature.markets

import com.testlogon.android.data.exchange.Instrument

/**
 * The instrument classes the unified, class-filtered symbol picker groups markets by. Built PURELY
 * from confirmed backend discriminators (see [classesForSymbol]); no invented fields:
 *  - [SPOT]: a non-perpetual (cash) instrument (`isPerpetual == false`).
 *  - [PERP]: a perpetual future (`isPerpetual == true`).
 *  - [PREDICTION]: a symbol with a live binary prediction-market state (detected by probing the
 *    per-symbol PM-state read; there is no list endpoint).
 *  - [FUNDING]: a lens on perpetuals with a positive funding interval — surfaces the funding
 *    interval + latest applied funding rate (bps).
 *
 * A single symbol can belong to several classes at once (a perp is also a FUNDING-book row; a
 * PM-enabled symbol adds PREDICTION), which is why [classesForSymbol] returns a set.
 */
enum class InstrumentClass(val label: String) {
    SPOT("Spot"),
    PERP("Perp"),
    PREDICTION("Prediction"),
    FUNDING("Funding"),
}

/**
 * A filter tab in the picker: either [InstrumentClass.All] (everything) or one concrete class. Kept
 * as a small sealed hierarchy so the "All" tab is a first-class, exhaustive option rather than a
 * nullable class.
 */
sealed interface MarketClassTab {
    val label: String

    data object All : MarketClassTab {
        override val label: String = "All"
    }

    data class Of(val clazz: InstrumentClass) : MarketClassTab {
        override val label: String = clazz.label
    }
}

/** The ordered tab row shown across the top of the picker: All, then Spot, Perp, Prediction, Funding. */
val MARKET_CLASS_TABS: List<MarketClassTab> = buildList {
    add(MarketClassTab.All)
    // Preserve the enum declaration order for the concrete tabs.
    InstrumentClass.entries.forEach { add(MarketClassTab.Of(it)) }
}

/**
 * PURE classifier: the set of [InstrumentClass]es a [symbol] belongs to.
 *
 * @param isPrediction whether a live PM state was observed for this symbol (probed elsewhere; treat
 *   404/error/unknown as false so a non-PM symbol never claims [InstrumentClass.PREDICTION]).
 *
 * Rules (all from confirmed discriminators):
 *  - exactly one of SPOT / PERP by `isPerpetual`.
 *  - a perp with `fundingIntervalS > 0` is ALSO a FUNDING-book row.
 *  - `isPrediction` adds PREDICTION on top of its spot/perp base class.
 */
fun classesForSymbol(symbol: Instrument, isPrediction: Boolean): Set<InstrumentClass> {
    val classes = LinkedHashSet<InstrumentClass>()
    if (symbol.isPerpetual) {
        classes.add(InstrumentClass.PERP)
        if (symbol.fundingIntervalS > 0) classes.add(InstrumentClass.FUNDING)
    } else {
        classes.add(InstrumentClass.SPOT)
    }
    if (isPrediction) classes.add(InstrumentClass.PREDICTION)
    return classes
}

/**
 * Whether a symbol (with its probed [isPrediction] flag) belongs under the given [tab]. "All" always
 * matches; a concrete tab matches when the symbol's class set contains that class.
 */
fun matchesTab(symbol: Instrument, isPrediction: Boolean, tab: MarketClassTab): Boolean = when (tab) {
    is MarketClassTab.All -> true
    is MarketClassTab.Of -> classesForSymbol(symbol, isPrediction).contains(tab.clazz)
}
