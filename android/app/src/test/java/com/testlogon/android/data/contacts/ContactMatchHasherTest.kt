package com.testlogon.android.data.contacts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Contacts Feature 2 — proves the on-device normalize + hash produces BYTE-IDENTICAL
 * hashes to the server scheme (app/services/contact_match.py + app/core/normalize.py).
 *
 * The expected hashes below were computed on the SERVER with the same fixed salt
 * ("tl_contact_match_v1") over the same raw inputs (a shared test vector). If the
 * client scheme drifts from the server, these assertions fail — which is exactly the
 * regression we want to catch, since mismatched hashes = silent match failures.
 */
class ContactMatchHasherTest {

    private val salt = "tl_contact_match_v1"
    private val hasher = ContactMatchHasher(salt)

    // ── Shared client==server hash vectors ──────────────────────────────────

    @Test
    fun email_matches_server_hash() {
        // server: normalize_email("  Alice.Smith@Example.COM ") -> "alice.smith@example.com"
        assertEquals(
            "0a83af565c0afaa2eddfb243381f4877e872c94a4d377957f6ed8f29a087c73e",
            hasher.hashEmail("  Alice.Smith@Example.COM "),
        )
    }

    @Test
    fun phone_us_10digit_matches_server_hash() {
        val expected = "f25d3883c7b730fae325a77e88891a2870f8f26b1a20d5384a4d639a7241bcf0"
        // All of these normalize to +14155550142 on both client and server.
        assertEquals(expected, hasher.hashPhone("(415) 555-0142"))
        assertEquals(expected, hasher.hashPhone("+1 415-555-0142"))
        assertEquals(expected, hasher.hashPhone("4155550142"))
    }

    @Test
    fun phone_international_e164_matches_server_hash() {
        // A +44 number keeps its country code (no default-region rewrite).
        assertEquals(
            "69dc7ecba32f7775b1a0407a260a9f27d68c991381bfc051e1b7478c570e50db",
            hasher.hashPhone("+442071838750"),
        )
    }

    // ── Normalization edge cases (must mirror the server exactly) ────────────

    @Test
    fun email_without_at_is_rejected() {
        assertNull(hasher.hashEmail("not-an-email"))
        assertNull(hasher.hashEmail("   "))
        assertNull(hasher.hashEmail(null))
    }

    @Test
    fun phone_too_short_or_junk_is_rejected() {
        assertNull(hasher.hashPhone("12345"))       // 5 digits, no + -> invalid
        assertNull(hasher.hashPhone("abc"))
        assertNull(hasher.hashPhone(""))
        assertNull(hasher.hashPhone(null))
    }

    @Test
    fun phone_11digit_leading_one_normalizes() {
        // "1 415 555 0142" -> +14155550142 (same as the 10-digit case).
        assertEquals(hasher.hashPhone("4155550142"), hasher.hashPhone("1-415-555-0142"))
    }

    @Test
    fun normalize_helpers_are_pure_and_deterministic() {
        assertEquals("alice.smith@example.com", ContactMatchHasher.normalizeEmail("  Alice.Smith@Example.COM "))
        assertEquals("+14155550142", ContactMatchHasher.normalizePhone("(415) 555-0142"))
        assertEquals("+442071838750", ContactMatchHasher.normalizePhone("+44 20 7183 8750"))
        assertNull(ContactMatchHasher.normalizePhone("12345"))
    }
}
