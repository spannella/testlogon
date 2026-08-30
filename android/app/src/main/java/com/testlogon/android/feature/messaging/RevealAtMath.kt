package com.testlogon.android.feature.messaging

/**
 * FE-120 (EPIC C, <- BE-120/BE-121) - pure, dependency-free logic for a scheduled "reveal at" drop.
 *
 * A creator can attach an optional future reveal time to any outgoing message. BEFORE that time the
 * RECIPIENTS see a locked/blurred bubble with a live countdown; at the reveal instant (a 1s tick
 * reaching it, or a `message:revealed` stream event) it auto-reveals the inner content. The SENDER
 * always sees the content. Everything here is pure integer-epoch math ([nowSec] is passed in) plus a
 * self-contained sentinel codec, so it is fully JVM-unit-testable (RevealAtMathTest).
 *
 * TRANSPORT (works-now, degrade-on-unknown, mirrors [EcomCardModel] / [CryptoTransferModel] /
 * [TradingCardModel]): the message DTO carries no `reveal_at` field, so the reveal time + the inner
 * body are encoded into a NORMAL text message behind a rare sentinel tag ([SENTINEL]) distinct from
 * every other card sentinel. [MessageDto.toMedia] parses it back to a domain type; an un-upgraded
 * client that does not recognise the sentinel simply shows the raw text (degrades naturally). The
 * inner body may itself be plain text OR another card sentinel (TLCARD1/TLXFER1/TLSHOP1), so the
 * countdown is self-contained and cross-client.
 *
 * Encoding: [SENTINEL] + reveal_at_seconds + ";" + inner-body (verbatim, NOT escaped - it is the
 * remainder of the string after the first ';', so any inner sentinel/`;`/`=` round-trips untouched).
 */
object RevealAtMath {

    /** Sentinel prefix marking a reveal-wrapped message body. Distinct from every other card sentinel. */
    const val SENTINEL: String = "TLRVL1:"

    /**
     * Minimum lead time (seconds) a reveal must be scheduled into the future. A reveal at/behind this
     * lead is pointless (it would render already-revealed), so the composer rejects it. Kept small so
     * demos/tests can arm a near-future reveal.
     */
    const val MIN_REVEAL_LEAD_SEC: Long = 10L

    // ---- reveal-time math (pure integer epoch; nowSec is supplied by the caller/ticker) ----

    /**
     * True when the message must render as a LOCKED (pre-reveal) bubble for this viewer. The sender is
     * NEVER locked (they always see their own content); an absent/<=0 reveal time is never locked; and
     * once [nowSec] reaches [revealAtSec] it auto-unlocks (no manual refresh).
     */
    fun isRevealLocked(revealAtSec: Long?, isSender: Boolean, nowSec: Long): Boolean {
        if (isSender) return false
        val target = revealAtSec ?: return false
        if (target <= 0L) return false
        return nowSec < target
    }

    /** Whole seconds remaining until the reveal, clamped to >= 0 (0 once reached/absent). */
    fun secondsUntilReveal(revealAtSec: Long?, nowSec: Long): Long {
        val target = revealAtSec ?: return 0L
        if (target <= 0L) return 0L
        return (target - nowSec).coerceAtLeast(0L)
    }

    /**
     * True when a reveal time is a well-formed, still-in-the-future target worth arming/rendering as a
     * countdown for a recipient (present, positive, and strictly after [nowSec]).
     */
    fun isRevealable(revealAtSec: Long?, nowSec: Long): Boolean {
        val target = revealAtSec ?: return false
        if (target <= 0L) return false
        return target > nowSec
    }

    /**
     * True when a picked reveal time satisfies the composer's minimum lead (>= [MIN_REVEAL_LEAD_SEC]
     * into the future from [nowSec]). Used to enable/disable the "arm reveal" affordance.
     */
    fun meetsMinLead(revealAtSec: Long?, nowSec: Long): Boolean {
        val target = revealAtSec ?: return false
        return target - nowSec >= MIN_REVEAL_LEAD_SEC
    }

    /**
     * Live countdown label to the reveal, formatted "2d 04:12:09" (days only when >= 1 day) /
     * "04:12:09" / "00:00:00". Mirrors [com.testlogon.android.data.messaging.CountdownLogic.format]
     * so the reveal countdown matches the other messaging countdowns; kept here so the label is pure
     * and self-contained for the JVM test.
     */
    fun revealCountdownLabel(revealAtSec: Long?, nowSec: Long): String {
        val total = secondsUntilReveal(revealAtSec, nowSec)
        val days = total / SECONDS_PER_DAY
        val hours = (total % SECONDS_PER_DAY) / SECONDS_PER_HOUR
        val minutes = (total % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE
        val seconds = total % SECONDS_PER_MINUTE
        val hms = padded(hours) + ":" + padded(minutes) + ":" + padded(seconds)
        return if (days > 0L) days.toString() + "d " + hms else hms
    }

    // ---- TLRVL1 sentinel codec (self-contained; round-trip tested) ----

    /** A parsed reveal wrapper: the reveal instant + the inner (possibly-card) body it guards. */
    data class RevealWrapper(
        val revealAtSec: Long,
        val innerBody: String,
    )

    /** True when [body] begins with the reveal sentinel (fast pre-check before a full parse). */
    fun isWrapped(body: String?): Boolean = body != null && body.startsWith(SENTINEL)

    /**
     * Encode a reveal-wrapped message body: [SENTINEL] + revealAtSec + ';' + [innerBody] verbatim.
     * The inner body is NOT escaped - it is captured as the whole remainder after the first ';', so
     * any nested sentinel or reserved char round-trips through [parse]. A non-positive reveal time or
     * a blank inner body returns the inner body unwrapped (nothing to schedule -> plain send).
     */
    fun encode(revealAtSec: Long, innerBody: String): String {
        if (revealAtSec <= 0L || innerBody.isBlank()) return innerBody
        return SENTINEL + revealAtSec.toString() + ";" + innerBody
    }

    /**
     * Parse a reveal-wrapped body into a [RevealWrapper], or null when [body] is not a well-formed
     * reveal wrapper (missing sentinel, unparseable time, non-positive time, or empty inner body) -
     * in which case the caller keeps the raw body (degrade naturally).
     */
    fun parse(body: String?): RevealWrapper? {
        if (body == null || !body.startsWith(SENTINEL)) return null
        val payload = body.substring(SENTINEL.length)
        val sep = payload.indexOf(';')
        if (sep <= 0) return null
        val revealAt = payload.substring(0, sep).toLongOrNull() ?: return null
        if (revealAt <= 0L) return null
        val inner = payload.substring(sep + 1)
        if (inner.isBlank()) return null
        return RevealWrapper(revealAtSec = revealAt, innerBody = inner)
    }

    /**
     * Conversation-list / reply preview for a body that MAY be a reveal wrapper; null when it is not
     * one (so the caller keeps the server text preview). VIEWER-AGNOSTIC on purpose (the inbox row
     * cannot know sender-vs-recipient), so it always masks the inner body behind the locked label -
     * the inner content never leaks into a list preview. Renders "🔒 Scheduled reveal".
     */
    fun previewForBody(body: String?): String? =
        if (isWrapped(body) && parse(body) != null) LOCKED_PREVIEW else null

    /** The masked preview / locked-bubble label shown before a reveal (lock glyph + text). */
    const val LOCKED_PREVIEW: String = "🔒 Scheduled reveal"

    private const val SECONDS_PER_MINUTE = 60L
    private const val SECONDS_PER_HOUR = 60L * 60L
    private const val SECONDS_PER_DAY = 24L * 60L * 60L

    private fun padded(n: Long): String {
        val v = n.coerceAtLeast(0L)
        return if (v < 10L) "0$v" else v.toString()
    }
}
