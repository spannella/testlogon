package com.testlogon.android.core.network.signing

import com.squareup.moshi.FromJson
import com.squareup.moshi.Json
import com.squareup.moshi.ToJson

/**
 * AND-339 - signing transport enums (signature packets + templates).
 *
 * RECONCILIATION (enum UNKNOWN fallback): the ticket text asks for
 * EnumJsonAdapter.create(E).withUnknownFallback(E.UNKNOWN). That class lives in the
 * com.squareup.moshi:moshi-adapters artifact, which is NOT a declared dependency of this project
 * (the version catalog only carries moshi / moshi-kotlin / moshi-kotlin-codegen) and this ticket
 * forbids adding any new dependency. So we reproduce the SAME lenient semantics the established way in
 * this codebase (mirroring KycCaseStatusAdapter / KycFileTypeAdapter): each enum carries the wire
 * token, an UNKNOWN member, and a custom Moshi adapter object whose fromJson maps an unrecognized
 * token to UNKNOWN (never throws) and whose toJson writes the token back. The adapter objects are
 * registered on the shared Moshi in NetworkModule.provideMoshi and rebuilt identically in the contract
 * test. The @Json annotations on the members document the wire tokens and keep parity with the rest of
 * core-network; the adapter objects are the load-bearing part for the UNKNOWN fallback.
 */

/** Lifecycle status of a signature packet (wire token decoded via [PacketStatusAdapter]). */
enum class PacketStatus(val token: String) {
    @Json(name = "draft") DRAFT("draft"),
    @Json(name = "sent") SENT("sent"),
    @Json(name = "partially_signed") PARTIALLY_SIGNED("partially_signed"),
    @Json(name = "completed") COMPLETED("completed"),
    @Json(name = "cancelled") CANCELLED("cancelled"),
    @Json(name = "expired") EXPIRED("expired"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): PacketStatus = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Type of a signature field placed on a packet / template (wire token via [SignatureFieldTypeAdapter]). */
enum class SignatureFieldType(val token: String) {
    @Json(name = "signature") SIGNATURE("signature"),
    @Json(name = "initials") INITIALS("initials"),
    @Json(name = "date") DATE("date"),
    @Json(name = "text") TEXT("text"),
    @Json(name = "notary_stamp") NOTARY_STAMP("notary_stamp"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): SignatureFieldType =
            entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** Role of the viewing user relative to a packet (wire token via [PacketRoleAdapter]). */
enum class PacketRole(val token: String) {
    @Json(name = "sender") SENDER("sender"),
    @Json(name = "signer") SIGNER("signer"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): PacketRole = entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/** How a field value was captured (wire token via [SignatureInputModeAdapter]). */
enum class SignatureInputMode(val token: String) {
    @Json(name = "typed") TYPED("typed"),
    @Json(name = "drawn") DRAWN("drawn"),
    UNKNOWN("unknown"),
    ;

    companion object {
        /** Lenient: an unrecognized token maps to [UNKNOWN] rather than throwing. */
        fun fromToken(t: String?): SignatureInputMode =
            entries.firstOrNull { it.token == t } ?: UNKNOWN
    }
}

/**
 * AND-339 - Moshi adapter for [PacketStatus]. Wire value is the snake_case token; an unrecognized
 * token decodes to [PacketStatus.UNKNOWN] (never throws) and serializes back to its token. This is the
 * dependency-free stand-in for EnumJsonAdapter.withUnknownFallback. Registered on the production Moshi
 * in NetworkModule.provideMoshi.
 */
object PacketStatusAdapter {
    @FromJson fun fromJson(token: String?): PacketStatus = PacketStatus.fromToken(token)
    @ToJson fun toJson(value: PacketStatus): String = value.token
}

/** AND-339 - Moshi adapter for [SignatureFieldType] (token in/out, unknown token -> UNKNOWN). */
object SignatureFieldTypeAdapter {
    @FromJson fun fromJson(token: String?): SignatureFieldType = SignatureFieldType.fromToken(token)
    @ToJson fun toJson(value: SignatureFieldType): String = value.token
}

/** AND-339 - Moshi adapter for [PacketRole] (token in/out, unknown token -> UNKNOWN). */
object PacketRoleAdapter {
    @FromJson fun fromJson(token: String?): PacketRole = PacketRole.fromToken(token)
    @ToJson fun toJson(value: PacketRole): String = value.token
}

/** AND-339 - Moshi adapter for [SignatureInputMode] (token in/out, unknown token -> UNKNOWN). */
object SignatureInputModeAdapter {
    @FromJson fun fromJson(token: String?): SignatureInputMode = SignatureInputMode.fromToken(token)
    @ToJson fun toJson(value: SignatureInputMode): String = value.token
}
