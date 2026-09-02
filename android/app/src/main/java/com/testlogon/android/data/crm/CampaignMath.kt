package com.testlogon.android.data.crm

/**
 * CMP — PURE, framework-free logic for the CRM Marketing Campaigns surface (send eligibility,
 * A/B variant split, HTML email-template merge-var validation). No Android / java.time types
 * leak in, so every function is JVM-unit-testable (mirrors the CrmPecMath / CrmSalesMath idiom).
 *
 * Mirrors the LIVE web contract (crmCampaigns.ts / crmEmail.ts → app/routers/crm_campaigns.py):
 *  - a campaign is send-eligible only when it targets at least one audience (contact list or
 *    segment) and is not already in a terminal/sent status.
 *  - the A/B split apportions a resolved audience across N variants as evenly as possible, giving
 *    the remainder to the earliest variants (deterministic, sums back to the total).
 *  - merge-var validation extracts {{ var }} placeholders (same regex as the server's _VAR_RE) and
 *    reports which are unfilled by a given sample map.
 *
 * Degrade, never throw: null / malformed inputs return neutral results rather than raising, so a
 * 404 (module disabled) or dev-host drift renders cleanly.
 */
object CampaignMath {

    // ── Campaign send eligibility ─────────────────────────────────────────────

    /** Statuses in which a campaign can no longer be (re-)sent. Mirrors the server lifecycle. */
    val TERMINAL_STATUSES: Set<String> = setOf("sent", "sending", "completed", "archived", "cancelled")

    /** A campaign targets an audience when it has at least one contact list or segment. */
    fun hasAudience(contactListIds: List<String>?, segmentIds: List<String>?): Boolean {
        val lists = contactListIds?.count { it.isNotBlank() } ?: 0
        val segs = segmentIds?.count { it.isNotBlank() } ?: 0
        return lists + segs > 0
    }

    /** Total distinct-ish audience source count (lists + segments), ignoring blanks. */
    fun audienceSourceCount(contactListIds: List<String>?, segmentIds: List<String>?): Int {
        val lists = contactListIds?.count { it.isNotBlank() } ?: 0
        val segs = segmentIds?.count { it.isNotBlank() } ?: 0
        return lists + segs
    }

    /**
     * Whether a "Send" (or "Send test") action is meaningful. Requires an audience and a
     * non-terminal status. A blank/unknown status is treated as draft (eligible).
     */
    fun canSend(status: String?, contactListIds: List<String>?, segmentIds: List<String>?): Boolean {
        if (!hasAudience(contactListIds, segmentIds)) return false
        val s = status?.trim()?.lowercase()
        if (s.isNullOrBlank()) return true
        return s !in TERMINAL_STATUSES
    }

    /** Coarse reason a send is blocked, for surfacing a helper line under the Send button. */
    fun sendBlockedReason(status: String?, contactListIds: List<String>?, segmentIds: List<String>?): String? {
        if (!hasAudience(contactListIds, segmentIds)) {
            return "Add a contact list or segment before sending."
        }
        val s = status?.trim()?.lowercase()
        if (!s.isNullOrBlank() && s in TERMINAL_STATUSES) {
            return "This campaign has already been sent."
        }
        return null
    }

    // ── A/B split ─────────────────────────────────────────────────────────────

    /**
     * Apportion [audienceSize] recipients across [variantCount] variants as evenly as possible.
     * The remainder (audienceSize mod variantCount) is handed to the earliest variants, one each,
     * so the returned list always sums back to [audienceSize] and is non-increasing.
     *
     * Degrades: a non-positive variant count returns an empty split; a non-positive audience
     * returns all-zeros of length variantCount.
     */
    fun abSplit(audienceSize: Int, variantCount: Int): List<Int> {
        if (variantCount <= 0) return emptyList()
        if (audienceSize <= 0) return List(variantCount) { 0 }
        val base = audienceSize / variantCount
        val remainder = audienceSize % variantCount
        return List(variantCount) { i -> base + if (i < remainder) 1 else 0 }
    }

    /**
     * The percentage share (0..100, one decimal precision as a Double) each variant receives of a
     * given [variantCount]-way even split. Used for the editor's "50% / 50%" hint. Empty when
     * variantCount <= 0.
     */
    fun abSplitPercents(variantCount: Int): List<Double> {
        if (variantCount <= 0) return emptyList()
        val each = 100.0 / variantCount
        val rounded = kotlin.math.round(each * 10.0) / 10.0
        return List(variantCount) { rounded }
    }

    /**
     * Whether a set of variants constitutes a valid A/B test: at least two variants, each with a
     * non-blank label/id key. A single variant (or none) is a plain broadcast, not an A/B test.
     */
    fun isAbTest(variantLabels: List<String>?): Boolean =
        (variantLabels?.count { it.isNotBlank() } ?: 0) >= 2

    /**
     * Determine the winning variant id by the higher of open-rate then click-rate (click-rate is
     * the tie-breaker). Returns null when there are no variants or all rates are zero (no signal).
     * [variants] is a list of (variantId, openRate, clickRate).
     */
    fun pickWinner(variants: List<Triple<String, Double, Double>>): String? {
        if (variants.isEmpty()) return null
        val best = variants.maxWithOrNull(
            compareBy<Triple<String, Double, Double>> { it.second }.thenBy { it.third },
        ) ?: return null
        if (best.second <= 0.0 && best.third <= 0.0) return null
        return best.first
    }

    // ── Email-template merge-var validation ───────────────────────────────────

    // Mirror the server regex app/services/marketing_email_templates.py::_VAR_RE = {{ var }}.
    private val VAR_RE = Regex("""\{\{\s*([a-zA-Z0-9_]+)\s*\}\}""")

    /**
     * Extract the distinct merge-var names referenced by a subject + body (sorted, de-duplicated),
     * matching the server's _extract_variables. Null / blank inputs contribute nothing.
     */
    fun extractTemplateVars(subject: String?, body: String?): List<String> {
        val text = (subject ?: "") + (body ?: "")
        return VAR_RE.findAll(text).map { it.groupValues[1] }.toSortedSet().toList()
    }

    /**
     * The subset of [extractTemplateVars] that a [sampleVars] map does NOT satisfy (missing key or
     * blank value). Sorted, distinct. Mirrors the server's merge_vars_missing computation.
     */
    fun missingTemplateVars(subject: String?, body: String?, sampleVars: Map<String, String>?): List<String> {
        val vars = extractTemplateVars(subject, body)
        val provided = sampleVars ?: emptyMap()
        return vars.filter { provided[it].isNullOrBlank() }
    }

    /** A template is preview-ready when every referenced merge var has a non-blank sample value. */
    fun isTemplateComplete(subject: String?, body: String?, sampleVars: Map<String, String>?): Boolean =
        missingTemplateVars(subject, body, sampleVars).isEmpty()

    /**
     * Client-side create/edit validation for an email template. Returns null when valid, or a
     * human message for the first failing rule (mirrors the server field constraints: name 1..120,
     * subject 1..500, body 1..50000).
     */
    fun validateTemplateInput(name: String?, subject: String?, bodyHtml: String?): String? {
        val n = name?.trim().orEmpty()
        if (n.isEmpty()) return "A template name is required."
        if (n.length > 120) return "The template name is too long (max 120)."
        val s = subject?.trim().orEmpty()
        if (s.isEmpty()) return "A subject line is required."
        if (s.length > 500) return "The subject line is too long (max 500)."
        val b = bodyHtml.orEmpty()
        if (b.isBlank()) return "The email body cannot be empty."
        if (b.length > 50_000) return "The email body is too long (max 50,000)."
        return null
    }

    /**
     * Client-side create/edit validation for a campaign. Returns null when valid, else a message.
     * Mirrors CrmCampaignCreateIn: name 1..200, objective <=500, budget_cents >= 0.
     */
    fun validateCampaignInput(name: String?, objective: String?, budgetCents: Long?): String? {
        val n = name?.trim().orEmpty()
        if (n.isEmpty()) return "A campaign name is required."
        if (n.length > 200) return "The campaign name is too long (max 200)."
        if ((objective?.length ?: 0) > 500) return "The objective is too long (max 500)."
        if ((budgetCents ?: 0L) < 0L) return "The budget cannot be negative."
        return null
    }

    /** Curated campaign-type keys for the editor chip row (mirror the server pattern). */
    val CAMPAIGN_TYPES: List<String> = listOf("email", "phone", "mail", "fax", "sms")

    /**
     * Parse a user-entered budget in dollars ("1,234.50", "$12", "") into integer cents. Returns
     * null when the input is present but not parseable; blank → 0. Tolerant of $ and thousands
     * separators.
     */
    fun parseBudgetToCents(raw: String?): Long? {
        val cleaned = raw?.trim()?.removePrefix("$")?.replace(",", "")?.trim().orEmpty()
        if (cleaned.isEmpty()) return 0L
        val d = cleaned.toDoubleOrNull() ?: return null
        if (d < 0) return null
        return kotlin.math.round(d * 100.0).toLong()
    }
}
