package com.testlogon.android.core.data.telemetry

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * AND-052 — the single, central sanitizer through which every telemetry value must pass.
 *
 * Two defenses:
 *  1. **Key denylist** — any attribute whose key matches a forbidden token is dropped entirely.
 *  2. **Value scrubbing** — values that look like secrets (OTP codes, JWTs, long hex/base64) are
 *     masked to `***`.
 *
 * `challenge_id` correlation uses a salted HMAC short hash ([shortHash]) so events from one flow
 * can be correlated without the raw, reversible id ever being logged.
 */
class Redactor(private val salt: ByteArray) {

    /** 4-hex correlation token for a challenge id; not reversible, stable within a process. */
    fun shortHash(value: String): String {
        if (value.isEmpty()) return "none"
        return runCatching {
            val mac = Mac.getInstance(HMAC_ALGO)
            mac.init(SecretKeySpec(salt, HMAC_ALGO))
            mac.doFinal(value.toByteArray(Charsets.UTF_8))
                .joinToString("") { b -> "%02x".format(b) }
                .take(SHORT_HASH_LEN)
        }.getOrDefault("redacted")
    }

    /** True when an attribute key is forbidden and the whole pair must be dropped. */
    fun isDeniedKey(key: String): Boolean {
        val k = key.lowercase()
        return DENYLIST.any { k.contains(it) }
    }

    /** Mask secret-shaped substrings in free text. */
    fun scrub(text: String): String =
        SECRET_PATTERNS.fold(text) { acc, regex -> regex.replace(acc, MASK) }

    /**
     * Build a redacted "k=v" line from already-coarse attributes: denied keys are dropped, and the
     * remaining values are scrubbed for secret-shaped content.
     */
    fun line(attrs: List<Pair<String, String?>>): String =
        attrs
            .asSequence()
            .filter { (k, v) -> v != null && !isDeniedKey(k) }
            .joinToString(" ") { (k, v) -> "$k=${scrub(v!!)}" }

    companion object {
        const val MASK = "***"
        private const val HMAC_ALGO = "HmacSHA256"
        private const val SHORT_HASH_LEN = 4

        /** Never logged in any form (substring, case-insensitive match on the key). */
        val DENYLIST = listOf(
            "password", "pwd", "code", "totp_code", "otp", "token",
            "csrf", "cookie", "set-cookie", "authorization", "secret",
        )

        private val SECRET_PATTERNS = listOf(
            Regex("""\b\d{6,8}\b"""), // OTP / SMS / email codes
            Regex("""eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"""), // JWT-ish (eyJ header + 3 segments)
            Regex("""\b[A-Fa-f0-9]{32,}\b"""), // long hex blobs
            Regex("""\b[A-Za-z0-9+/]{40,}={0,2}\b"""), // long base64 blobs
        )
    }
}
