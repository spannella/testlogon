package com.testlogon.android.data.admin.email

import java.util.Locale

/**
 * Framework-free pure logic for the ADMIN-EMAIL surface:
 *  - display formatters for the delivery stats header (percentages 0-100, compact counts),
 *  - merge-field name validation (a 1:1 mirror of the backend `CampaignEmailTemplateCreate`
 *    `_validate_merge_fields` regex `[a-zA-Z0-9_]{1,64}`),
 *  - campaign-template create-form validation mirroring the server field bounds.
 *
 * Nothing here touches Android, Retrofit or coroutines, so it is fully unit-testable on the JVM.
 */
object AdminEmailMath {

    // Server field bounds (CampaignEmailTemplateCreate in app/models.py).
    const val NAME_MAX = 100
    const val SUBJECT_MAX = 200
    const val BODY_MAX = 50_000
    const val MERGE_FIELD_MAX = 64

    private val MERGE_FIELD_RE = Regex("[a-zA-Z0-9_]{1,$MERGE_FIELD_MAX}")

    /**
     * Format a rate that the backend already expresses as a PERCENTAGE 0-100, e.g. 98.7 -> "98.7%",
     * 100.0 -> "100%", 0.0 -> "0%". Clamps to [0, 100] and drops a trailing ".0".
     */
    fun formatRate(percent: Double): String {
        if (percent.isNaN() || percent.isInfinite()) return "0%"
        val clamped = percent.coerceIn(0.0, 100.0)
        val rounded = Math.round(clamped * 10.0) / 10.0
        val body = if (rounded % 1.0 == 0.0) rounded.toLong().toString()
        else String.format(Locale.US, "%.1f", rounded)
        return "$body%"
    }

    /** Compact count formatting (1_500 -> "1.5K", 2_000_000 -> "2M", 42 -> "42"). Negatives -> "0". */
    fun formatCount(count: Int): String {
        if (count <= 0) return "0"
        return when {
            count < 1_000 -> count.toString()
            count < 1_000_000 -> trimTenth(count / 1_000.0) + "K"
            else -> trimTenth(count / 1_000_000.0) + "M"
        }
    }

    /**
     * One-line summary of the delivery window, e.g. "1,240 sent · 98.7% delivered" for the header.
     * Uses grouped thousands for the send volume and the delivery rate percentage.
     */
    fun summaryLine(sent: Int, deliveryRatePercent: Double): String {
        val volume = groupThousands(sent.coerceAtLeast(0).toLong())
        return "$volume sent · ${formatRate(deliveryRatePercent)} delivered"
    }

    /** True when [field] is a valid merge-field name (mirrors the backend regex). */
    fun isValidMergeField(field: String): Boolean = MERGE_FIELD_RE.matches(field)

    /**
     * Parse a comma / whitespace separated merge-field string into a clean, de-duplicated, ordered list,
     * returning null when ANY token is invalid (so the form can block submit with an error), or an empty
     * list when the input is blank. Preserves first-seen order.
     */
    fun parseMergeFields(input: String): List<String>? {
        val tokens = input.split(',', ' ', '\n', '\t')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        if (tokens.isEmpty()) return emptyList()
        val seen = LinkedHashSet<String>()
        for (t in tokens) {
            if (!isValidMergeField(t)) return null
            seen.add(t)
        }
        return seen.toList()
    }

    /** Reasons a create-template form is not submittable (empty when valid). Mirrors server bounds. */
    fun templateFormErrors(name: String, subject: String, body: String, mergeRaw: String): List<String> {
        val errors = mutableListOf<String>()
        val n = name.trim()
        val s = subject.trim()
        when {
            n.isEmpty() -> errors.add("Name is required")
            n.length > NAME_MAX -> errors.add("Name too long (max $NAME_MAX)")
        }
        when {
            s.isEmpty() -> errors.add("Subject is required")
            s.length > SUBJECT_MAX -> errors.add("Subject too long (max $SUBJECT_MAX)")
        }
        when {
            body.isEmpty() -> errors.add("Body is required")
            body.length > BODY_MAX -> errors.add("Body too long (max $BODY_MAX)")
        }
        if (parseMergeFields(mergeRaw) == null) errors.add("Invalid merge field name")
        return errors
    }

    /** True when the create-template form passes all validation. */
    fun canSubmitTemplate(name: String, subject: String, body: String, mergeRaw: String): Boolean =
        templateFormErrors(name, subject, body, mergeRaw).isEmpty()

    // ---- internal helpers ----

    private fun trimTenth(v: Double): String {
        val rounded = Math.round(v * 10.0) / 10.0
        return if (rounded % 1.0 == 0.0) rounded.toLong().toString()
        else String.format(Locale.US, "%.1f", rounded)
    }

    private fun groupThousands(n: Long): String {
        val s = n.toString()
        if (s.length <= 3) return s
        val sb = StringBuilder()
        val first = s.length % 3
        if (first > 0) {
            sb.append(s, 0, first)
            if (s.length > first) sb.append(',')
        }
        var i = first
        while (i < s.length) {
            sb.append(s, i, i + 3)
            if (i + 3 < s.length) sb.append(',')
            i += 3
        }
        return sb.toString()
    }
}
