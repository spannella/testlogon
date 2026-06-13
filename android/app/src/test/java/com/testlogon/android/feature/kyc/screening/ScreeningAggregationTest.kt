package com.testlogon.android.feature.kyc.screening

import com.testlogon.android.core.model.kyc.KycScreeningResultOut
import com.testlogon.android.feature.kyc.screening.model.KycScreenResult
import com.testlogon.android.feature.kyc.screening.model.KycScreenType
import com.testlogon.android.feature.kyc.screening.model.ScreeningStatus
import com.testlogon.android.feature.kyc.screening.model.aggregate
import com.testlogon.android.feature.kyc.screening.model.toDomain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.time.Instant

/**
 * AND-328 - unit tests for the pure screening aggregation reducer + the DTO -> domain mapper.
 *
 * No coroutines / I/O: [aggregate] is a pure function and [toDomain] is a straight mapping (unknown token ->
 * UNKNOWN, epoch -> Instant).
 */
class ScreeningAggregationTest {

    @Test
    fun confirmedMatch_dominates_everything_to_HIT() {
        val results = listOf(
            domain(KycScreenResult.CLEAR),
            domain(KycScreenResult.POTENTIAL_MATCH),
            domain(KycScreenResult.CONFIRMED_MATCH),
        )
        assertEquals(ScreeningStatus.HIT, aggregate(results))
    }

    @Test
    fun potentialMatch_withoutConfirmed_to_REVIEW() {
        val results = listOf(
            domain(KycScreenResult.CLEAR),
            domain(KycScreenResult.POTENTIAL_MATCH),
        )
        assertEquals(ScreeningStatus.REVIEW, aggregate(results))
    }

    @Test
    fun allClear_nonEmpty_to_CLEAR() {
        val results = listOf(domain(KycScreenResult.CLEAR), domain(KycScreenResult.CLEAR))
        assertEquals(ScreeningStatus.CLEAR, aggregate(results))
    }

    @Test
    fun empty_to_NOT_STARTED() {
        assertEquals(ScreeningStatus.NOT_STARTED, aggregate(emptyList()))
    }

    @Test
    fun allUnknownTokens_to_UNKNOWN() {
        val results = listOf(domain(KycScreenResult.UNKNOWN))
        assertEquals(ScreeningStatus.UNKNOWN, aggregate(results))
    }

    @Test
    fun unknownWireToken_mapsTo_UNKNOWN_result() {
        val dto = KycScreeningResultOut(result = "not_a_real_token", screen_type = "mystery_screen")
        val mapped = dto.toDomain()
        assertEquals(KycScreenResult.UNKNOWN, mapped.result)
        assertEquals(KycScreenType.UNKNOWN, mapped.screenType)
        assertNull(mapped.screenedAt)
    }

    @Test
    fun knownTokens_and_epoch_mapToDomain() {
        val dto = KycScreeningResultOut(
            result = "confirmed_match",
            screen_type = "sanctions_ofac",
            screened_at = 1_780_000_000L,
            match_count = 3,
        )
        val mapped = dto.toDomain()
        assertEquals(KycScreenResult.CONFIRMED_MATCH, mapped.result)
        assertEquals(KycScreenType.SANCTIONS_OFAC, mapped.screenType)
        assertEquals(Instant.ofEpochSecond(1_780_000_000L), mapped.screenedAt)
        assertEquals(3, mapped.matchCount)
    }

    private fun domain(result: KycScreenResult) =
        KycScreeningResultOut(result = wire(result)).toDomain()

    private fun wire(result: KycScreenResult): String = when (result) {
        KycScreenResult.CLEAR -> "clear"
        KycScreenResult.POTENTIAL_MATCH -> "potential_match"
        KycScreenResult.CONFIRMED_MATCH -> "confirmed_match"
        KycScreenResult.UNKNOWN -> "garbage_token"
    }
}
