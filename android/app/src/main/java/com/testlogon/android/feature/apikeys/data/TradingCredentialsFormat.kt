package com.testlogon.android.feature.apikeys.data

/**
 * Multi-protocol trading/custody credentials — PURE, framework-free helpers for the API-key management surface,
 * mirrored VERBATIM from the web `lib/tradingCredentials.ts`. Provisions REST / WS / FIX / Binary access against
 * the unified exchange gateway. No Android/Compose/Retrofit deps → covered by a fast JVM unit test.
 *
 * The exchange is ONE gateway fronting trading + custody across:
 *  - REST   — generic scoped HTTP (any scope).
 *  - WS      — user channels ({"sub":"events"} / {"sub":"custody"}), authed with a WS token.
 *  - FIX     — me-fix-gateway order-entry + CU-series custody MsgTypes.
 *  - Binary  — me_wire listener, CU_OP_* / order-entry ops, HMAC.
 * A credential may be issued for any SUBSET of these protocols.
 */

/** The wire protocol identifiers accepted by the create body `protocols:[...]` (verbatim, lowercase). */
enum class Protocol(val wire: String) {
    REST("rest"),
    WS("ws"),
    FIX("fix"),
    BINARY("binary"),
    ;

    companion object {
        /** Parse a wire id (case-insensitive) → [Protocol], or null when unknown (degrade quietly). */
        fun fromWire(value: String?): Protocol? =
            entries.firstOrNull { it.wire.equals(value?.trim(), ignoreCase = true) }
    }
}

object TradingCredentialsFormat {

    /** All protocols, in catalog display order. */
    val ALL_PROTOCOLS: List<Protocol> = listOf(Protocol.REST, Protocol.WS, Protocol.FIX, Protocol.BINARY)

    // ── Scope groups (mirror ApiKeyCapabilities Trading/Custody/Market Data groups). Kept here so the
    //    validator stays pure and independently testable. ──────────────────────────────────────────────
    val TRADING_SCOPES: List<String> = listOf(
        "trading:read",
        "trading:orders",
        "trading:cancel",
        "trading:positions",
        "trading:funding",
    )

    val CUSTODY_SCOPES: List<String> = listOf(
        "custody:read",
        "custody:deposit",
        "custody:withdraw",
        "custody:transfer",
    )

    val MARKETDATA_SCOPES: List<String> = listOf("marketdata:read", "marketdata:stream")

    /** Human-readable label for a protocol (e.g. "WebSocket"). */
    fun protocolLabel(protocol: Protocol): String = when (protocol) {
        Protocol.REST -> "REST"
        Protocol.WS -> "WebSocket"
        Protocol.FIX -> "FIX"
        Protocol.BINARY -> "Binary"
    }

    /**
     * The scopes a given protocol is expected to carry AT MINIMUM (any ONE of the returned scopes satisfies it):
     *  - REST    → generic, no requirement (empty list).
     *  - WS      → at least one Trading / Custody / Market Data scope.
     *  - FIX     → order-entry / custody transport → at least one Trading or Custody scope.
     *  - BINARY  → CU_OP_* / order-entry transport → at least one Trading or Custody scope.
     */
    fun protocolRequiresScopes(protocol: Protocol): List<String> = when (protocol) {
        Protocol.FIX, Protocol.BINARY -> TRADING_SCOPES + CUSTODY_SCOPES
        Protocol.WS -> TRADING_SCOPES + CUSTODY_SCOPES + MARKETDATA_SCOPES
        Protocol.REST -> emptyList()
    }

    private fun isTradingOrCustodyScope(scope: String): Boolean =
        scope in TRADING_SCOPES || scope in CUSTODY_SCOPES

    /** One protocol/scope mismatch surfaced by [validateProtocolScopes]. */
    data class ProtocolValidationError(val protocol: Protocol, val message: String)

    /**
     * Validate the selected [protocols] against the selected [scopes]. FIX and Binary require at least one
     * Trading-or-Custody scope; WS requires at least one Trading/Custody/Market Data scope; REST imposes none.
     * Returns the list of errors (EMPTY ⇒ valid).
     */
    fun validateProtocolScopes(
        protocols: Collection<Protocol>,
        scopes: Collection<String>,
    ): List<ProtocolValidationError> {
        val scopeSet = scopes.toSet()
        val errors = mutableListOf<ProtocolValidationError>()
        for (protocol in protocols) {
            when (protocol) {
                Protocol.FIX, Protocol.BINARY -> {
                    if (scopes.none { isTradingOrCustodyScope(it) }) {
                        errors += ProtocolValidationError(
                            protocol,
                            "${protocolLabel(protocol)} requires at least one Trading or Custody scope.",
                        )
                    }
                }
                Protocol.WS -> {
                    val allowed = protocolRequiresScopes(Protocol.WS)
                    if (allowed.none { it in scopeSet }) {
                        errors += ProtocolValidationError(
                            protocol,
                            "${protocolLabel(protocol)} requires at least one Trading, Custody, or Market Data scope.",
                        )
                    }
                }
                Protocol.REST -> Unit
            }
        }
        return errors
    }

    /** Session parameters for [buildFixSessionConfig]. */
    data class FixSessionParams(
        val senderCompId: String,
        val targetCompId: String,
        val host: String,
        val port: String,
        val username: String? = null,
        val password: String? = null,
        val msgTypes: List<String> = emptyList(),
        val beginString: String = "FIX.4.4",
        val heartBtInt: Int = 30,
    )

    /**
     * Build a downloadable/shareable QuickFIX-style INITIATOR session config (.cfg text) from [params].
     * Pure string builder — no I/O. Password is included only when present (one-time credential material).
     */
    fun buildFixSessionConfig(params: FixSessionParams): String {
        val lines = mutableListOf<String>()
        lines += "# QuickFIX session configuration"
        lines += "# Generated by the credential manager. Store securely."
        lines += ""
        lines += "[DEFAULT]"
        lines += "ConnectionType=initiator"
        lines += "ReconnectInterval=5"
        lines += "HeartBtInt=${params.heartBtInt}"
        lines += "FileStorePath=store"
        lines += "FileLogPath=log"
        lines += "StartTime=00:00:00"
        lines += "EndTime=00:00:00"
        lines += "UseDataDictionary=Y"
        lines += "ResetOnLogon=Y"
        lines += ""
        lines += "[SESSION]"
        lines += "BeginString=${params.beginString}"
        lines += "SenderCompID=${params.senderCompId}"
        lines += "TargetCompID=${params.targetCompId}"
        lines += "SocketConnectHost=${params.host}"
        lines += "SocketConnectPort=${params.port}"
        if (!params.username.isNullOrEmpty()) lines += "Username=${params.username}"
        if (!params.password.isNullOrEmpty()) lines += "Password=${params.password}"
        if (params.msgTypes.isNotEmpty()) lines += "# Permitted MsgTypes: ${params.msgTypes.joinToString(", ")}"
        lines += ""
        return lines.joinToString("\n")
    }

    /** Filename for a downloaded/shared FIX session config (safe-charactered from the SenderCompID). */
    fun fixConfigFilename(senderCompId: String): String {
        val safe = senderCompId.ifBlank { "session" }.replace(Regex("[^A-Za-z0-9_.-]+"), "_")
        return "fix-$safe.cfg"
    }

    /** Format a WS subscribe payload as a compact JSON string for display/copy (e.g. {"sub":"events"}). */
    fun wsSubscribePayload(sub: String): String = "{\"sub\":\"$sub\"}"

    /** The subscribe channels a WS credential exposes; falls back to the default user channels. */
    fun wsSubscribeChannels(subs: List<String>?): List<String> =
        subs?.takeIf { it.isNotEmpty() } ?: listOf("events", "custody")
}
