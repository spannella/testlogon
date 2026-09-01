package com.testlogon.android.data.broadcast

/**
 * Pure, dependency-free validation logic for the broadcast PRO authoring tools (product shelf + multi-input
 * layout). Every function is stateless so it is trivially unit-testable on the JVM (no Android, no
 * coroutines, no network). It centralises the exact wire constraints the host authoring UI + repositories
 * repeatedly re-implement inline, mirroring the FastAPI contract in app/routers/broadcast.py:
 *
 *  - PRODUCT PRICE (BroadcastPriceSetIn / set_broadcast_price_route):
 *      broadcast_price_cents  : gt 0, le 99_999_999, AND strictly < the catalog price (server-enforced).
 *      expires_in_seconds     : optional; when present ge 60, le 86_400 (1 min .. 24 h).
 *  - ADD-PRODUCT (BroadcastShelfAddIn): item_id / category_id non-blank; display_order 0..999.
 *  - REORDER (BroadcastShelfReorderIn): item_order 1..50 entries, each non-blank (dupes rejected here as a
 *    client pre-check — the server treats the list as a total order).
 *  - LAYOUT (BroadcastLayoutSwitchIn / LayoutPosition): mode in {single, side_by_side, pip, grid};
 *    a placed slot's x/y in 0.0..1.0, width/height in (0.0..1.0], the rect must stay in-frame
 *    (x+width le 1, y+height le 1), and z_index 0..10.
 *
 * These are CLIENT pre-checks that fail fast and give a precise message before the network round-trip; the
 * server validates again (this never relaxes a server rule, only mirrors it). Nothing here mutates state.
 */
object BroadcastProMath {

    // ---- product price bounds (mirror BroadcastPriceSetIn) ------------------

    /** Minimum broadcast price in cents (Field gt=0 -> the smallest valid value is 1). */
    const val PRICE_MIN_CENTS: Long = 1L

    /** Maximum broadcast price in cents (Field le=99_999_999). */
    const val PRICE_MAX_CENTS: Long = 99_999_999L

    /** Minimum optional auto-expiry (Field ge=60): one minute. */
    const val EXPIRY_MIN_SECONDS: Long = 60L

    /** Maximum optional auto-expiry (Field le=86_400): twenty-four hours. */
    const val EXPIRY_MAX_SECONDS: Long = 86_400L

    /** display_order bounds for an added product (BroadcastShelfAddIn: ge=0, le=999). */
    const val DISPLAY_ORDER_MIN: Int = 0
    const val DISPLAY_ORDER_MAX: Int = 999

    /** item_order length bounds for a reorder (BroadcastShelfReorderIn: min_length=1, max_length=50). */
    const val REORDER_MIN_ITEMS: Int = 1
    const val REORDER_MAX_ITEMS: Int = 50

    /** LayoutPosition z_index bounds (ge=0, le=10). */
    const val Z_INDEX_MIN: Int = 0
    const val Z_INDEX_MAX: Int = 10

    /** The four wire-valid layout modes (BroadcastLayoutSwitchIn pattern). */
    val LAYOUT_MODES: Set<String> = setOf("single", "side_by_side", "pip", "grid")

    /**
     * Precise, structured outcome of a validation. [Valid] carries no message; [Invalid] carries a stable
     * [reason] the UI can map to a string resource (kept English here for a dependency-free core).
     */
    sealed interface Validation {
        data object Valid : Validation
        data class Invalid(val reason: String) : Validation

        val isValid: Boolean get() = this is Valid
    }

    // ---- product-price validation -------------------------------------------

    /**
     * Validate a broadcast-exclusive price in cents against the item's [catalogPriceCents]. Enforces the full
     * BroadcastPriceSetIn contract PLUS the service rule "strictly below catalog". A non-positive or absent
     * [catalogPriceCents] means we cannot pre-check the "below catalog" rule client-side, so only the absolute
     * bounds are applied (the server still enforces the relationship).
     */
    fun validateBroadcastPriceCents(cents: Long?, catalogPriceCents: Long?): Validation {
        if (cents == null) return Validation.Invalid("PRICE_REQUIRED")
        if (cents < PRICE_MIN_CENTS) return Validation.Invalid("PRICE_TOO_LOW")
        if (cents > PRICE_MAX_CENTS) return Validation.Invalid("PRICE_TOO_HIGH")
        if (catalogPriceCents != null && catalogPriceCents > 0L && cents >= catalogPriceCents) {
            return Validation.Invalid("PRICE_NOT_BELOW_CATALOG")
        }
        return Validation.Valid
    }

    /** Convenience boolean form of [validateBroadcastPriceCents]. */
    fun isBroadcastPriceValid(cents: Long?, catalogPriceCents: Long?): Boolean =
        validateBroadcastPriceCents(cents, catalogPriceCents).isValid

    /**
     * Validate the OPTIONAL auto-expiry. A null / absent expiry is valid (the price simply never auto-reverts).
     * When present it must fall in [EXPIRY_MIN_SECONDS]..[EXPIRY_MAX_SECONDS].
     */
    fun validateExpirySeconds(seconds: Long?): Validation = when {
        seconds == null -> Validation.Valid
        seconds < EXPIRY_MIN_SECONDS -> Validation.Invalid("EXPIRY_TOO_SHORT")
        seconds > EXPIRY_MAX_SECONDS -> Validation.Invalid("EXPIRY_TOO_LONG")
        else -> Validation.Valid
    }

    /**
     * The discount percentage a broadcast price represents versus catalog, floored to a whole percent and
     * clamped to 0..100. Mirrors the server's discount_pct field. Returns 0 when catalog is non-positive or
     * the broadcast price is not actually below catalog.
     */
    fun discountPct(catalogPriceCents: Long, broadcastPriceCents: Long): Int {
        if (catalogPriceCents <= 0L || broadcastPriceCents >= catalogPriceCents || broadcastPriceCents < 0L) return 0
        val pct = ((catalogPriceCents - broadcastPriceCents) * 100L) / catalogPriceCents
        return pct.toInt().coerceIn(0, 100)
    }

    // ---- add-product validation ---------------------------------------------

    /**
     * Validate the fields of an add-product request (BroadcastShelfAddIn). [itemId] / [categoryId] must be
     * non-blank; [displayOrder] must be in [DISPLAY_ORDER_MIN]..[DISPLAY_ORDER_MAX].
     */
    fun validateAddProduct(itemId: String, categoryId: String, displayOrder: Int): Validation = when {
        itemId.isBlank() -> Validation.Invalid("ITEM_ID_REQUIRED")
        categoryId.isBlank() -> Validation.Invalid("CATEGORY_ID_REQUIRED")
        displayOrder < DISPLAY_ORDER_MIN || displayOrder > DISPLAY_ORDER_MAX ->
            Validation.Invalid("DISPLAY_ORDER_OUT_OF_RANGE")
        else -> Validation.Valid
    }

    // ---- reorder validation -------------------------------------------------

    /**
     * Validate an item_order reorder payload (BroadcastShelfReorderIn). Rejects an empty or over-long list, any
     * blank id, and (as a client pre-check) duplicate ids — a total order must reference each item at most once.
     */
    fun validateReorder(itemOrder: List<String>): Validation = when {
        itemOrder.size < REORDER_MIN_ITEMS -> Validation.Invalid("REORDER_EMPTY")
        itemOrder.size > REORDER_MAX_ITEMS -> Validation.Invalid("REORDER_TOO_MANY")
        itemOrder.any { it.isBlank() } -> Validation.Invalid("REORDER_BLANK_ID")
        itemOrder.distinct().size != itemOrder.size -> Validation.Invalid("REORDER_DUPLICATE_ID")
        else -> Validation.Valid
    }

    // ---- layout validation --------------------------------------------------

    /** True when [mode] is one of the four wire-valid layout modes. */
    fun isValidLayoutMode(mode: String): Boolean = mode in LAYOUT_MODES

    /**
     * Validate a single placed layout slot (a normalized-coordinate rectangle for one input). Mirrors
     * LayoutPosition plus the geometric invariant that the rect stays fully in-frame:
     *   x in 0..1, y in 0..1, width in (0..1], height in (0..1], x+width <= 1, y+height <= 1, z 0..10.
     * [inputId] must be non-blank. A tiny epsilon absorbs float rounding at the frame edge.
     */
    fun validateLayoutSlot(
        inputId: String,
        x: Double,
        y: Double,
        width: Double,
        height: Double,
        zIndex: Int,
    ): Validation {
        val eps = 1e-6
        return when {
            inputId.isBlank() -> Validation.Invalid("SLOT_INPUT_REQUIRED")
            x < 0.0 || x > 1.0 + eps -> Validation.Invalid("SLOT_X_OUT_OF_RANGE")
            y < 0.0 || y > 1.0 + eps -> Validation.Invalid("SLOT_Y_OUT_OF_RANGE")
            width <= 0.0 || width > 1.0 + eps -> Validation.Invalid("SLOT_WIDTH_OUT_OF_RANGE")
            height <= 0.0 || height > 1.0 + eps -> Validation.Invalid("SLOT_HEIGHT_OUT_OF_RANGE")
            x + width > 1.0 + eps -> Validation.Invalid("SLOT_OVERFLOWS_X")
            y + height > 1.0 + eps -> Validation.Invalid("SLOT_OVERFLOWS_Y")
            zIndex < Z_INDEX_MIN || zIndex > Z_INDEX_MAX -> Validation.Invalid("SLOT_Z_OUT_OF_RANGE")
            else -> Validation.Valid
        }
    }

    /**
     * Validate a whole layout-switch request (BroadcastLayoutSwitchIn). [mode] must be wire-valid; when
     * [primaryInputId] is supplied it must be non-blank AND, if [inputIds] is supplied, be a member of it;
     * a supplied [inputIds] must be non-empty with no blank / duplicate ids.
     */
    fun validateLayoutSwitch(
        mode: String,
        primaryInputId: String?,
        inputIds: List<String>?,
    ): Validation {
        if (!isValidLayoutMode(mode)) return Validation.Invalid("LAYOUT_MODE_INVALID")
        if (inputIds != null) {
            if (inputIds.isEmpty()) return Validation.Invalid("LAYOUT_INPUTS_EMPTY")
            if (inputIds.any { it.isBlank() }) return Validation.Invalid("LAYOUT_INPUT_BLANK")
            if (inputIds.distinct().size != inputIds.size) return Validation.Invalid("LAYOUT_INPUT_DUPLICATE")
        }
        if (primaryInputId != null) {
            if (primaryInputId.isBlank()) return Validation.Invalid("LAYOUT_PRIMARY_BLANK")
            if (inputIds != null && primaryInputId !in inputIds) return Validation.Invalid("LAYOUT_PRIMARY_NOT_IN_INPUTS")
        }
        return Validation.Valid
    }

    // ---- degrade-on-404 -----------------------------------------------------

    /**
     * True when a failed *optional* PRO read (product shelf list / current layout) should degrade to an
     * honest-empty result instead of an error surface. 404 (session/shelf/layout absent) and 410 (gone) are
     * benign for these additive reads; everything else (401/403/429/5xx) is a real failure. Mutations
     * (add/remove/reorder/set-price/switch-layout) must NEVER be degraded — surface their errors.
     */
    fun isBenignProReadFailure(httpStatus: Int): Boolean = httpStatus == 404 || httpStatus == 410
}
