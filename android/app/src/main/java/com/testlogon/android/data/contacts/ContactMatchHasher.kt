package com.testlogon.android.data.contacts

import java.security.MessageDigest
import java.util.Locale

/**
 * Contacts Feature 2 — on-device normalize + hash for privacy-safe contact matching.
 *
 * This is the byte-for-byte mirror of the server scheme
 * (app/services/contact_match.py + app/core/normalize.py):
 *
 *     id_hash = sha256( CONTACT_MATCH_SALT + ":" + normalized_identifier )   (lowercase hex)
 *
 *   - email: lowercased + trimmed.
 *   - phone: E.164 (default region +1), matching the server's normalize_phone:
 *       * strip spaces / - / ( ) / .
 *       * a leading '+' is kept, remaining non-digits stripped -> "+<digits>"
 *       * exactly 10 digits           -> "+1<digits>"
 *       * 11 digits starting with '1' -> "+<digits>"
 *       * anything else               -> INVALID (dropped)
 *
 * PURE Kotlin (no Android imports) so it is directly JVM-unit-testable and provably
 * produces the same hash the server computes for the same raw input.
 *
 * The salt is injected (from BuildConfig.CONTACT_MATCH_SALT) so tests can pin a fixed
 * vector without depending on the Android build config.
 */
class ContactMatchHasher(private val salt: String) {

    /** sha256(salt + ":" + normalized) -> lowercase hex. */
    fun hash(normalized: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest("$salt:$normalized".toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** Normalize + hash an email; null if the value is not a plausible email. */
    fun hashEmail(raw: String?): String? {
        val n = normalizeEmail(raw) ?: return null
        return hash(n)
    }

    /** Normalize (E.164) + hash a phone; null if it cannot be normalized. */
    fun hashPhone(raw: String?): String? {
        val n = normalizePhone(raw) ?: return null
        return hash(n)
    }

    companion object {
        /** Lowercase + trim; must contain '@' and be <= 254 chars (mirrors normalize_email). */
        fun normalizeEmail(raw: String?): String? {
            val s = raw?.trim()?.lowercase(Locale.ROOT) ?: return null
            if (s.isEmpty() || !s.contains('@') || s.length > 254) return null
            return s
        }

        private val SEPARATORS = Regex("""[\s\-().]""")

        /** Best-effort E.164 with default region +1 — mirrors server normalize_phone. */
        fun normalizePhone(raw: String?): String? {
            val trimmed = raw?.trim().orEmpty()
            if (trimmed.isEmpty()) return null
            val s2 = trimmed.replace(SEPARATORS, "")
            if (s2.startsWith("+")) {
                val digits = s2.substring(1).filter { it.isDigit() }
                if (digits.isEmpty()) return null
                return "+$digits"
            }
            val digits = s2.filter { it.isDigit() }
            return when {
                digits.length == 10 -> "+1$digits"
                digits.length == 11 && digits.startsWith("1") -> "+$digits"
                else -> null
            }
        }
    }
}
