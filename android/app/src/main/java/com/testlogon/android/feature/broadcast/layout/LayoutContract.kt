package com.testlogon.android.feature.broadcast.layout

import com.testlogon.android.data.broadcast.LayoutMode
import com.testlogon.android.data.broadcast.LayoutPosition

/**
 * AND-311 — UI state contract for the layout-management surface.
 *
 * MODE TYPE NOTE: AND-310's domain keeps the layout `mode` as a wire String and exposes the verified values
 * through the [LayoutMode] String-constant object (NOT an enum). To give the UI an exhaustive, type-safe set
 * of the four server-supported modes plus an UNKNOWN fallback WITHOUT redefining AND-310's [LayoutMode],
 * AND-311 adds the small presentation enum [LayoutModeUi]. It maps to/from the wire strings via
 * [LayoutModeUi.fromWire] / [LayoutModeUi.wire] so the data layer stays String-based and untouched.
 *
 * The four selectable modes are a STATIC CLIENT CONSTANT ([LayoutModeUi.SELECTABLE]) — they are never
 * fetched. UNKNOWN is only ever the rendered current mode (an unrecognised server value); it is not offered
 * as a card.
 */
enum class LayoutModeUi(val wire: String) {
    SINGLE(LayoutMode.SINGLE),
    SIDE_BY_SIDE(LayoutMode.SIDE_BY_SIDE),
    PIP(LayoutMode.PIP),
    GRID(LayoutMode.GRID),

    /** An unrecognised server mode. Rendered as the current mode but never offered as a selectable card. */
    UNKNOWN("");

    companion object {
        /** The four server-supported modes, in display order. The selectable card list. */
        val SELECTABLE: List<LayoutModeUi> = listOf(SINGLE, SIDE_BY_SIDE, PIP, GRID)

        /** Map a wire `mode` string to a [LayoutModeUi]; any unrecognised value coerces to [UNKNOWN]. */
        fun fromWire(wire: String?): LayoutModeUi =
            SELECTABLE.firstOrNull { it.wire == wire } ?: UNKNOWN
    }
}

/**
 * AND-311 — render state for the layout-management surface.
 */
sealed interface LayoutUiState {

    /** Initial / cold load before any cache or network result. */
    data object Loading : LayoutUiState

    /**
     * The layout is available.
     *
     * [cards] are the four fixed mode cards. [currentMode] is the live (cached) mode. [activeInputCount] is
     * the number of inputs the session has (drives [ModeCard.needsSource]). [isStale] is true when a refresh
     * failed but the cached mode is shown (warm cache). [banner] carries a one-shot human-readable message
     * (e.g. a rolled-back switch failure). [pendingMode] is the optimistic in-flight target (the grid is
     * non-interactive while it is non-null). [positions] is the read-only, in-memory positions list from the
     * last successful refresh (FR-4; NOT persisted in Room).
     */
    data class Content(
        val cards: List<ModeCard>,
        val currentMode: LayoutModeUi,
        val activeInputCount: Int,
        val isStale: Boolean = false,
        val banner: String? = null,
        val pendingMode: LayoutModeUi? = null,
        val positions: List<LayoutPosition> = emptyList(),
    ) : LayoutUiState

    /** Cold-cache failure: nothing to show. [retryable] gates the retry affordance. */
    data class Error(val message: String, val retryable: Boolean) : LayoutUiState
}

/**
 * AND-311 — a single mode card + derived affordance gates.
 *
 * [isLive] — this card's mode == the current (live) layout mode.
 * [isSelectable] — the card can be tapped (it is not already live AND no switch is in flight).
 * [needsSource] — the session has no active inputs, so this layout would not appear on air yet (a
 * non-blocking hint; the card stays selectable).
 */
data class ModeCard(
    val mode: LayoutModeUi,
    val isLive: Boolean,
    val isSelectable: Boolean,
    val needsSource: Boolean,
)
