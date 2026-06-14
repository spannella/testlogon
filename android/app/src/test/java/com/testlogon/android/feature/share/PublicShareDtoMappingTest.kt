package com.testlogon.android.feature.share

import com.testlogon.android.core.model.files.PublicShareDto
import com.testlogon.android.feature.share.model.PublicShareState
import com.testlogon.android.feature.share.model.toDomain
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-392 - mapping tests for the CORRECTED public-info contract (`ShareLinkPublicInfoOut`).
 *
 * The verified payload uses `file_size_bytes`, `requires_password`, and the boolean flags
 * `is_revoked` / `is_expired` / `is_used` (the consumed / download-limit case) - NOT the AND-335 draft's
 * `size` / `password_required` / `revoked` / `expired` / `exhausted`. These tests assert that
 * [PublicShareDto.toDomain] PREFERS the corrected fields and still falls back to the legacy fields so an
 * older backend (and the existing AND-335 fakes) keep resolving. `is_used` maps to EXHAUSTED (the same
 * terminal the web `unavailableMessage()` renders for the consumed / limit-reached case). Precedence is
 * revoked -> expired -> used, matching the web `unavailableMessage()` ordering. org.junit.Test; no
 * shadowed names.
 */
class PublicShareDtoMappingTest {

    @Test
    fun correctedFields_available_mapsSizeAndPasswordFlag() {
        val share = PublicShareDto(
            file_name = "quarterly-report.pdf",
            file_size_bytes = 4823311L,
            content_type = "application/pdf",
            requires_password = true,
            remaining_downloads = 17,
        ).toDomain()

        assertEquals("quarterly-report.pdf", share.fileName)
        assertEquals(4823311L, share.sizeBytes)
        assertEquals("application/pdf", share.contentType)
        assertEquals(true, share.passwordRequired)
        assertEquals(PublicShareState.AVAILABLE, share.state)
    }

    @Test
    fun isRevoked_mapsToRevoked() {
        assertEquals(
            PublicShareState.REVOKED,
            PublicShareDto(file_name = "a", file_size_bytes = 1L, is_revoked = true).toDomain().state,
        )
    }

    @Test
    fun isExpired_mapsToExpired() {
        assertEquals(
            PublicShareState.EXPIRED,
            PublicShareDto(file_name = "a", file_size_bytes = 1L, is_expired = true).toDomain().state,
        )
    }

    @Test
    fun isUsed_mapsToExhausted() {
        assertEquals(
            PublicShareState.EXHAUSTED,
            PublicShareDto(file_name = "a", file_size_bytes = 1L, is_used = true).toDomain().state,
        )
    }

    @Test
    fun revokedPrecedesExpiredAndUsed() {
        assertEquals(
            PublicShareState.REVOKED,
            PublicShareDto(
                file_name = "a",
                file_size_bytes = 1L,
                is_revoked = true,
                is_expired = true,
                is_used = true,
            ).toDomain().state,
        )
    }

    @Test
    fun legacyFields_stillResolve_whenCorrectedAbsent() {
        val share = PublicShareDto(
            link_id = "lnk",
            file_name = "old.bin",
            size = 99L,
            password_required = true,
            expired = true,
        ).toDomain()

        assertEquals(99L, share.sizeBytes)
        assertEquals(true, share.passwordRequired)
        assertEquals(PublicShareState.EXPIRED, share.state)
    }

    @Test
    fun correctedSize_preferredOverLegacySize() {
        val share = PublicShareDto(
            file_name = "x",
            file_size_bytes = 4823311L,
            size = 1L,
        ).toDomain()

        assertEquals(4823311L, share.sizeBytes)
    }
}
