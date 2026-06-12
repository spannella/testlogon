package com.testlogon.android.data.broadcast

/**
 * AND-310 — canonical (DTO-free) broadcast LAYOUT domain + mappers for the inputs-management surface.
 *
 * Kept minimal/clean; AND-311 (layout-management) will build richer behaviour on top of this. The PROGRAM
 * input is the one whose id == [BroadcastLayout.primaryInputId] — clients derive a per-input `isProgram`
 * by joining the input list against this.
 */
data class BroadcastLayout(
    val mode: String,
    val primaryInputId: String?,
    val inputIds: List<String>,
    val positions: List<LayoutPosition>,
)

/** AND-310 — a single placed input rectangle within a [BroadcastLayout]. */
data class LayoutPosition(
    val inputId: String,
    val x: Double,
    val y: Double,
    val width: Double,
    val height: Double,
    val zIndex: Int,
)

/** AND-310 — known layout modes. `mode` stays a String on the domain; these are the verified wire values. */
object LayoutMode {
    const val SINGLE = "single"
    const val SIDE_BY_SIDE = "side_by_side"
    const val PIP = "pip"
    const val GRID = "grid"
}

// ─── DTO -> domain mappers (pure; android-free) ──────────────────────────────────────────────────────

/**
 * AND-310 — maps a [BroadcastInputOutDto] to the extended [BroadcastInput] domain. Epoch-second
 * connected_at / disconnected_at stay Long?; ISO created_at / updated_at parse to Instant? (unparseable ->
 * null, never throws). [BroadcastInput.isProgram] is left at its default false here — it is derived later
 * by the caller by joining against the layout's primary_input_id.
 */
fun BroadcastInputOutDto.toDomain(): BroadcastInput = BroadcastInput(
    inputId = inputId,
    sessionId = sessionId,
    inputType = inputType,
    label = label,
    ingestUrl = ingestUrl,
    streamKey = streamKeyRef,
    position = position,
    isLive = isLive,
    connectedAt = connectedAt,
    disconnectedAt = disconnectedAt,
    createdBy = createdBy,
    createdAt = parseInstantOrNull(createdAt),
    updatedAt = parseInstantOrNull(updatedAt),
)

/** AND-310 — maps the inputs LIST envelope to the domain input list. */
fun BroadcastInputListDto.toDomain(): List<BroadcastInput> = inputs.map { it.toDomain() }

/** AND-310 — maps a [BroadcastLayoutDto] to the [BroadcastLayout] domain. */
fun BroadcastLayoutDto.toDomain(): BroadcastLayout = BroadcastLayout(
    mode = mode,
    primaryInputId = primaryInputId,
    inputIds = inputIds,
    positions = positions.map { it.toDomain() },
)

/** AND-310 — maps a [LayoutPositionDto] to the [LayoutPosition] domain. */
fun LayoutPositionDto.toDomain(): LayoutPosition = LayoutPosition(
    inputId = inputId,
    x = x,
    y = y,
    width = width,
    height = height,
    zIndex = zIndex,
)
