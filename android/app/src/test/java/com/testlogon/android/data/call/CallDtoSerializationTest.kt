package com.testlogon.android.data.call

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-295 — DTO round-trip + default/nullable serialization (plain Moshi, no codegen reliance assumed for
 * the assertions — the project Moshi.Builder().build() is used like the other contract tests).
 */
class CallDtoSerializationTest {

    private val moshi: Moshi = Moshi.Builder().build()

    @Test
    fun inviteIn_defaults_emitAudioAndPaidFalse() {
        val adapter = moshi.adapter(CallInviteInDto::class.java)
        val json = adapter.toJson(CallInviteInDto(callId = "c", conversationId = "conv", calleeUserId = "u"))
        assertEquals("audio", moshi.parse(json)["initial_mode"])
        assertEquals(false, moshi.parse(json)["paid"])
    }

    @Test
    fun declineIn_default_emitsDeclined() {
        val json = moshi.adapter(CallDeclineInDto::class.java).toJson(CallDeclineInDto())
        assertEquals("declined", moshi.parse(json)["reason"])
    }

    @Test
    fun endIn_default_emitsEnded() {
        val json = moshi.adapter(CallEndInDto::class.java).toJson(CallEndInDto())
        assertEquals("ended", moshi.parse(json)["reason"])
    }

    @Test
    fun timeoutIn_default_emitsNoAnswer() {
        val json = moshi.adapter(CallTimeoutInDto::class.java).toJson(CallTimeoutInDto())
        assertEquals("no_answer", moshi.parse(json)["reason"])
    }

    @Test
    fun inviteOut_roundTrips_andMapsDomain() {
        val adapter = moshi.adapter(CallInviteOutDto::class.java)
        val dto = adapter.fromJson(
            """{"call_id":"c","conversation_id":"conv","caller_user_id":"a","callee_user_id":"b",
                "state":"ringing","initial_mode":"video","start_ts":42,"paid":false,
                "rate_cents_per_minute":null}""",
        )!!
        val domain = dto.toDomain()
        assertEquals(CallMode.VIDEO, domain.mode)
        assertEquals(42L, domain.startTsEpochSeconds)
        assertNull(domain.rateCentsPerMinute)
    }

    @Test
    fun actionOut_absentNullableFields_decodeNull() {
        val dto = moshi.adapter(CallActionOutDto::class.java).fromJson(
            """{"call_id":"c","conversation_id":"conv","state":"ended","event_ts":7}""",
        )!!
        assertNull(dto.fromState)
        assertNull(dto.reason)
        assertEquals(false, dto.voicemailEligible)
    }

    @Test
    fun heartbeatOut_minutesRemaining_isDouble() {
        val dto = moshi.adapter(HeartbeatOutDto::class.java).fromJson(
            """{"call_id":"c","minutes_remaining":3.5}""",
        )!!
        assertEquals(3.5, dto.minutesRemaining, 0.0001)
        assertEquals("ok", dto.action)
    }

    private fun Moshi.parse(json: String): Map<String, Any?> {
        val type = com.squareup.moshi.Types.newParameterizedType(
            Map::class.java, String::class.java, Any::class.java,
        )
        return adapter<Map<String, Any?>>(type).fromJson(json) ?: emptyMap()
    }
}
