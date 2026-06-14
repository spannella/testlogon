package com.testlogon.android.data.call

import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.testlogon.android.data.webrtc.CallSignalingInDto
import com.testlogon.android.data.webrtc.CallSignalingOutDto
import com.testlogon.android.data.webrtc.TurnCredentialsDto
import com.testlogon.android.data.webrtc.TurnIceServerDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-306 — SIGNALING + call CONTROL-PLANE codec coverage.
 *
 * Fills the genuinely-missing gap left by the AND-294/295 suites: a plain Moshi (no codegen reliance in
 * the assertions, exactly Moshi.Builder().build() like the contract tests) ROUND-TRIP for the RAW wire
 * DTOs the call/signaling transport serializes -> toJson then fromJson EQUALS the original, and fromJson
 * of the §5-shaped wire JSON yields the expected fields. We also assert the snake_case keys actually
 * appear in the encoded output (guards against a future @Json rename silently breaking the wire contract).
 *
 * Scope note: SignalingRepositoryContractTest exercises the request envelope over MockWebServer and
 * SignalingMappingTest covers the SignalingMessage -> payload helpers; neither asserts the DTO's own
 * encode/decode identity. CallDtoSerializationTest covers a few CallDtos defaults but not the full
 * round-trip-equals-original for the invite/action DTOs. This test owns that identity contract.
 *
 * None of these DTOs use BigDecimal (money is Int/Long cents; sent_at/ttl are Long seconds), so no
 * BigDecimalAdapter is registered — plain Moshi is correct.
 */
class SignalingCodecTest {

    private val moshi: Moshi = Moshi.Builder().build()

    private fun parse(json: String): Map<String, Any?> {
        val type = Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java)
        return moshi.adapter<Map<String, Any?>>(type).fromJson(json) ?: emptyMap()
    }

    // ─── CallSignalingInDto (the flat send envelope; SDP nests under payload) ──────────────────────

    @Test
    fun callSignalingIn_roundTrips_andEmitsSnakeCaseKeys() {
        val adapter = moshi.adapter(CallSignalingInDto::class.java)
        val original = CallSignalingInDto(
            type = "webrtc.offer",
            eventId = "evt_1",
            conversationId = "conv_1",
            recipientUserId = "user_B",
            nonce = "nonce1234",
            sentAt = 1_717_603_200L,
            payload = mapOf("sdp" to "v=0 offer"),
        )
        val json = adapter.toJson(original)

        // Wire keys are snake_case (the dotted discriminator stays under "type").
        val map = parse(json)
        assertEquals("webrtc.offer", map["type"])
        assertEquals("evt_1", map["event_id"])
        assertEquals("conv_1", map["conversation_id"])
        assertEquals("user_B", map["recipient_user_id"])
        assertEquals("nonce1234", map["nonce"])
        // sent_at is a Long but decodes back through the loose Any? map as a Double.
        assertEquals(1_717_603_200.0, map["sent_at"])
        @Suppress("UNCHECKED_CAST")
        val payload = map["payload"] as Map<String, Any?>
        assertEquals("v=0 offer", payload["sdp"])
        assertTrue(json.contains("\"event_id\""))
        assertTrue(json.contains("\"recipient_user_id\""))
        assertTrue(json.contains("\"sent_at\""))

        // Round-trip identity: decoding the encoded form reproduces the original.
        assertEquals(original, adapter.fromJson(json))
    }

    @Test
    fun callSignalingIn_decodesWireJson_intoExpectedFields() {
        val dto = moshi.adapter(CallSignalingInDto::class.java).fromJson(
            """
            {"type":"webrtc.offer","event_id":"evt_9","conversation_id":"conv_9",
             "recipient_user_id":"user_Z","nonce":"n_9","sent_at":1700000000,
             "payload":{"sdp":"v=0 wire"}}
            """.trimIndent(),
        )!!
        assertEquals("webrtc.offer", dto.type)
        assertEquals("evt_9", dto.eventId)
        assertEquals("conv_9", dto.conversationId)
        assertEquals("user_Z", dto.recipientUserId)
        assertEquals("n_9", dto.nonce)
        assertEquals(1_700_000_000L, dto.sentAt)
        assertEquals("v=0 wire", dto.payload["sdp"])
    }

    // ─── CallSignalingOutDto (the send acknowledgement) ───────────────────────────────────────────

    @Test
    fun callSignalingOut_roundTrips_andEmitsSnakeCaseKeys() {
        val adapter = moshi.adapter(CallSignalingOutDto::class.java)
        val original = CallSignalingOutDto(
            eventId = "evt_1",
            callId = "call_1",
            conversationId = "conv_1",
            eventType = "webrtc.offer",
            deliveredTo = "user_B",
            status = "delivered",
        )
        val json = adapter.toJson(original)

        val map = parse(json)
        assertEquals("evt_1", map["event_id"])
        assertEquals("call_1", map["call_id"])
        assertEquals("conv_1", map["conversation_id"])
        assertEquals("webrtc.offer", map["event_type"])
        assertEquals("user_B", map["delivered_to"])
        assertEquals("delivered", map["status"])
        assertTrue(json.contains("\"event_type\""))
        assertTrue(json.contains("\"delivered_to\""))

        assertEquals(original, adapter.fromJson(json))
    }

    // ─── CallInviteInDto / CallInviteOutDto / CallActionOutDto (control-plane DTOs) ────────────────

    @Test
    fun callInviteIn_roundTrips_withPaidRate_andSnakeCaseKeys() {
        val adapter = moshi.adapter(CallInviteInDto::class.java)
        val original = CallInviteInDto(
            callId = "c_1",
            conversationId = "conv_1",
            calleeUserId = "u_peer",
            initialMode = "video",
            idempotencyKey = "idk_1",
            paid = true,
            // REQUEST spelling is rate_cents_per_min (asymmetric with the response) — pin it.
            rateCentsPerMin = 50,
        )
        val json = adapter.toJson(original)

        val map = parse(json)
        assertEquals("c_1", map["call_id"])
        assertEquals("u_peer", map["callee_user_id"])
        assertEquals("video", map["initial_mode"])
        assertEquals("idk_1", map["idempotency_key"])
        assertEquals(true, map["paid"])
        assertEquals(50.0, map["rate_cents_per_min"])
        // Guard against regressing the REQUEST field to the RESPONSE spelling.
        assertTrue(json.contains("\"rate_cents_per_min\""))
        assertTrue(!json.contains("\"rate_cents_per_minute\""))

        assertEquals(original, adapter.fromJson(json))
    }

    @Test
    fun callInviteOut_roundTrips_withResponseRateSpelling() {
        val adapter = moshi.adapter(CallInviteOutDto::class.java)
        val original = CallInviteOutDto(
            callId = "c_1",
            conversationId = "conv_1",
            callerUserId = "u_self",
            calleeUserId = "u_peer",
            state = "ringing",
            initialMode = "audio",
            startTsEpochSeconds = 1_733_400_000L,
            paid = true,
            // RESPONSE spelling is rate_cents_per_minute.
            rateCentsPerMinute = 75,
        )
        val json = adapter.toJson(original)

        val map = parse(json)
        assertEquals("u_self", map["caller_user_id"])
        assertEquals("ringing", map["state"])
        assertEquals(1_733_400_000.0, map["start_ts"])
        assertEquals(75.0, map["rate_cents_per_minute"])
        assertTrue(json.contains("\"caller_user_id\""))
        assertTrue(json.contains("\"start_ts\""))
        assertTrue(json.contains("\"rate_cents_per_minute\""))

        assertEquals(original, adapter.fromJson(json))
    }

    @Test
    fun callActionOut_roundTrips_withAllOptionalsPresent() {
        val adapter = moshi.adapter(CallActionOutDto::class.java)
        val original = CallActionOutDto(
            callId = "c_9",
            conversationId = "conv_9",
            state = "declined",
            eventTsEpochSeconds = 1_733_400_100L,
            fromState = "ringing",
            reason = "busy",
            voicemailEligible = true,
        )
        val json = adapter.toJson(original)

        val map = parse(json)
        assertEquals("c_9", map["call_id"])
        assertEquals("declined", map["state"])
        assertEquals(1_733_400_100.0, map["event_ts"])
        assertEquals("ringing", map["from_state"])
        assertEquals("busy", map["reason"])
        assertEquals(true, map["voicemail_eligible"])
        assertTrue(json.contains("\"event_ts\""))
        assertTrue(json.contains("\"from_state\""))
        assertTrue(json.contains("\"voicemail_eligible\""))

        assertEquals(original, adapter.fromJson(json))
    }

    // ─── TurnCredentialsDto / TurnIceServerDto (the ICE-server fetch) ──────────────────────────────

    @Test
    fun turnCredentials_roundTrips_andEmitsSnakeCaseKeys() {
        val adapter = moshi.adapter(TurnCredentialsDto::class.java)
        val original = TurnCredentialsDto(
            iceServers = listOf(
                TurnIceServerDto(
                    urls = listOf("turn:turn.example.com:3478", "stun:stun.example.com:3478"),
                    username = "u-123",
                    credential = "cred-abc",
                ),
            ),
            ttlSeconds = 600,
            expiresAtEpochSeconds = 1_733_400_600L,
        )
        val json = adapter.toJson(original)

        val map = parse(json)
        assertEquals(600.0, map["ttl_seconds"])
        assertEquals(1_733_400_600.0, map["expires_at"])
        @Suppress("UNCHECKED_CAST")
        val servers = map["ice_servers"] as List<Map<String, Any?>>
        assertEquals(1, servers.size)
        assertEquals("u-123", servers[0]["username"])
        assertEquals("cred-abc", servers[0]["credential"])
        @Suppress("UNCHECKED_CAST")
        val urls = servers[0]["urls"] as List<String>
        assertEquals("turn:turn.example.com:3478", urls[0])
        assertTrue(json.contains("\"ice_servers\""))
        assertTrue(json.contains("\"ttl_seconds\""))
        assertTrue(json.contains("\"expires_at\""))

        assertEquals(original, adapter.fromJson(json))
    }

    @Test
    fun turnCredentials_decodesWireJson_withMultipleServers() {
        val dto = moshi.adapter(TurnCredentialsDto::class.java).fromJson(
            """
            {"ice_servers":[
               {"urls":["stun:stun.example.com:3478"],"username":"u1","credential":"c1"},
               {"urls":["turn:turn.example.com:3478"],"username":"u2","credential":"c2"}
             ],"ttl_seconds":300,"expires_at":1700000300}
            """.trimIndent(),
        )!!
        assertEquals(2, dto.iceServers.size)
        assertEquals(300L, dto.ttlSeconds)
        assertEquals(1_700_000_300L, dto.expiresAtEpochSeconds)
        assertEquals("u2", dto.iceServers[1].username)
        assertEquals("turn:turn.example.com:3478", dto.iceServers[1].urls[0])
    }
}
