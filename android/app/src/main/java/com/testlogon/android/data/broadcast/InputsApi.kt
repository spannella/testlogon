package com.testlogon.android.data.broadcast

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-310 — Retrofit interface for the broadcast INPUTS-MANAGEMENT surface (list inputs, activate /
 * deactivate, and the layout get/switch that promotes one input to the live program).
 *
 * Kept SEPARATE from [BroadcastApi] / [HostControlApi] so the shared BroadcastRepository fakes (Viewer /
 * Browse / CreateBroadcast / Ingest tests) are NOT touched. Provided on the SHARED Retrofit by
 * [BroadcastApiModule] (no new OkHttp/Retrofit). Paths are relative (no leading slash) so they resolve
 * against the shared base URL; cookies / Authorization: Bearer / X-CSRF-Token are attached project-wide by
 * the core-network interceptor chain — this interface stays header-agnostic.
 *
 * Base path: `broadcast/sessions/{sessionId}/...`.
 *
 * KEY WIRE FACTS (do not drift):
 *  - GET inputs -> a LIST envelope { session_id, count, max_inputs (default 4), inputs:[...] }.
 *  - activate / deactivate take an EMPTY body and return only { "ok": true } — they do NOT return the row,
 *    so the repository MUST re-GET the list after a successful toggle to learn the authoritative is_live.
 *  - GET / POST layout returns BroadcastLayoutOut { mode, primary_input_id?, input_ids:[], positions:[] }.
 *    "Make live" = POST layout with the required `mode` plus `primary_input_id` = the target input. THE
 *    PROGRAM input is the one whose input_id == layout.primary_input_id (client-derived).
 *
 * NOTE: AND-308 already declared activate/deactivate on [BroadcastApi] returning Unit (used by the ingest
 * teardown). AND-310 deliberately RE-DECLARES them here returning [OkDto] because the inputs-management
 * repository needs the { ok } acknowledgement to decide whether to refetch, and keeping them on this
 * self-contained interface avoids touching the shared BroadcastApi/BroadcastRepository fakes.
 */
interface InputsApi {

    /** List all ingest inputs for [sessionId] (LIST envelope with count / max_inputs). */
    @GET("broadcast/sessions/{sessionId}/inputs")
    suspend fun listInputs(@Path("sessionId") sessionId: String): BroadcastInputListDto

    /** Activate [inputId] (mark it a live/publishing feed). EMPTY body; returns { ok }. */
    @POST("broadcast/sessions/{sessionId}/inputs/{inputId}/activate")
    suspend fun activateInput(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    ): OkDto

    /** Deactivate [inputId]. EMPTY body; returns { ok }. */
    @POST("broadcast/sessions/{sessionId}/inputs/{inputId}/deactivate")
    suspend fun deactivateInput(
        @Path("sessionId") sessionId: String,
        @Path("inputId") inputId: String,
    ): OkDto

    /** Read [sessionId]'s current layout (mode + primary_input_id + input_ids + positions). */
    @GET("broadcast/sessions/{sessionId}/layout")
    suspend fun getLayout(@Path("sessionId") sessionId: String): BroadcastLayoutDto

    /**
     * Switch [sessionId]'s layout. `mode` is REQUIRED; setting `primary_input_id` promotes that input to
     * the live program ("Make live"). Returns the updated BroadcastLayoutOut.
     */
    @POST("broadcast/sessions/{sessionId}/layout")
    suspend fun switchLayout(
        @Path("sessionId") sessionId: String,
        @Body body: LayoutSwitchRequestDto,
    ): BroadcastLayoutDto
}

// ─── wire DTOs (exact snake_case via @Json; absent optionals fall back to Kotlin defaults) ──────────────

/** AND-310 — generic { "ok": true } acknowledgement returned by activate / deactivate. */
@JsonClass(generateAdapter = true)
data class OkDto(
    @Json(name = "ok") val ok: Boolean = false,
)

/** AND-310 — BroadcastInputListOut: the inputs LIST envelope. */
@JsonClass(generateAdapter = true)
data class BroadcastInputListDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "count") val count: Int = 0,
    @Json(name = "max_inputs") val maxInputs: Int = 4,
    @Json(name = "inputs") val inputs: List<BroadcastInputOutDto> = emptyList(),
)

/**
 * AND-310 — BroadcastInputOut: a single input row. `input_type` is "primary"|"guest"|"screen" (unknown ->
 * [InputType.UNKNOWN], never throws). `connected_at` / `disconnected_at` are nullable epoch SECONDS
 * integers; `created_at` / `updated_at` are ISO strings. There is NO kind/status/active/is_program field —
 * `is_live` is the only liveness signal on the wire; program is derived from the layout.
 */
@JsonClass(generateAdapter = true)
data class BroadcastInputOutDto(
    @Json(name = "input_id") val inputId: String,
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "input_type") val inputType: String = BroadcastInputType.GUEST,
    @Json(name = "label") val label: String? = null,
    @Json(name = "is_live") val isLive: Boolean = false,
    @Json(name = "ingest_url") val ingestUrl: String? = null,
    @Json(name = "stream_key_ref") val streamKeyRef: String? = null,
    @Json(name = "aws_input_arn") val awsInputArn: String? = null,
    @Json(name = "relay_mode") val relayMode: String? = null,
    @Json(name = "position") val position: Int = 0,
    @Json(name = "connected_at") val connectedAt: Long? = null,
    @Json(name = "disconnected_at") val disconnectedAt: Long? = null,
    @Json(name = "created_by") val createdBy: String = "",
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

/** AND-310 — BroadcastLayoutOut: the session's current composition layout. */
@JsonClass(generateAdapter = true)
data class BroadcastLayoutDto(
    @Json(name = "mode") val mode: String = "",
    @Json(name = "primary_input_id") val primaryInputId: String? = null,
    @Json(name = "input_ids") val inputIds: List<String> = emptyList(),
    @Json(name = "positions") val positions: List<LayoutPositionDto> = emptyList(),
)

/** AND-310 — a single placed input rectangle in a layout. */
@JsonClass(generateAdapter = true)
data class LayoutPositionDto(
    @Json(name = "input_id") val inputId: String,
    @Json(name = "x") val x: Double = 0.0,
    @Json(name = "y") val y: Double = 0.0,
    @Json(name = "width") val width: Double = 0.0,
    @Json(name = "height") val height: Double = 0.0,
    @Json(name = "z_index") val zIndex: Int = 0,
)

/**
 * AND-310 — BroadcastLayoutSwitchIn: layout switch request. `mode` is REQUIRED (one of
 * single|side_by_side|pip|grid). `primary_input_id` promotes that input to the live program;
 * `input_ids` (nullable) optionally re-orders the composition. Nulls are omitted by Moshi.
 */
@JsonClass(generateAdapter = true)
data class LayoutSwitchRequestDto(
    @Json(name = "mode") val mode: String,
    @Json(name = "primary_input_id") val primaryInputId: String? = null,
    @Json(name = "input_ids") val inputIds: List<String>? = null,
)
