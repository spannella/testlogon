package com.testlogon.android.core.network.projects

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-376 - DTO-level Moshi tests for the AND-374 PROJECTS transport (mirrors the AND-371 TicketDtoJsonTest).
 *
 * Focus on the CORRECTED §5 / §16 contract that the existing AND-374 suite did NOT cover at the Moshi layer:
 * the list continuation key is `cursor` (NOT next_cursor); project timestamps are ISO-8601 STRINGS (NOT epoch);
 * the OAuth start / credential shapes; OPTIONAL-field + empty-collection defaults; EXTRA-key tolerance; and
 * REQUIRED-field enforcement (id / owner / name / created_at / updated_at on ProjectOut; provider /
 * authorization_url / state / expires_at on the start response; provider on the credential). The Moshi is built
 * like NetworkModule.provideMoshi (BigDecimalAdapter + the reflective KotlinJsonAdapterFactory). core-network
 * has no test dependency on core-testing, so the JSON is inline. KDoc avoids the comment-terminator pair.
 */
class ProjectDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    // ---- ProjectOut round-trip: ISO-string timestamps, tags / settings, optional description ----

    @Test
    fun project_roundTrips_isoTimestamps_tagsSettings_extraKeyTolerated() {
        val adapter = moshi.adapter(ProjectOut::class.java)
        val json = """{"id":"prj_1","owner":"usr_9","name":"Demo","description":"d",
            "tags":["q2","launch"],"settings":{"theme":"dark"},
            "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z",
            "extra":"ignored"}"""
        val project = requireNotNull(adapter.fromJson(json))
        assertEquals("prj_1", project.id)
        assertEquals("usr_9", project.owner)
        assertEquals("Demo", project.name)
        assertEquals("d", project.description)
        assertEquals(listOf("q2", "launch"), project.tags)
        assertEquals("dark", project.settings["theme"])
        // timestamps are ISO-8601 STRINGS on this surface (NOT epoch numbers)
        assertEquals("2026-05-30T12:00:00Z", project.createdAt)
        assertEquals("2026-06-01T09:15:00Z", project.updatedAt)

        val decoded = requireNotNull(adapter.fromJson(adapter.toJson(project)))
        assertEquals(project, decoded)
    }

    @Test
    fun project_sparseBody_defaultsOptionalsAndEmptyCollections() {
        val adapter = moshi.adapter(ProjectOut::class.java)
        val project = requireNotNull(
            adapter.fromJson(
                """{"id":"prj_2","owner":"usr_1","name":"No desc",
                    "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}""",
            ),
        )
        assertNull(project.description)
        assertTrue(project.tags.isEmpty())
        assertTrue(project.settings.isEmpty())
    }

    // ---- list envelope: continuation key is `cursor` (NOT next_cursor) ----

    @Test
    fun listEnvelope_decodesItemsAndCursorKey_andEmptyDefaults() {
        val adapter = moshi.adapter(ProjectListEnvelope::class.java)
        val full = requireNotNull(
            adapter.fromJson(
                """{"items":[
                     {"id":"prj_1","owner":"usr_9","name":"Demo",
                      "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z"}
                   ],"cursor":"cur_2"}""",
            ),
        )
        assertEquals(1, full.items.size)
        assertEquals("prj_1", full.items[0].id)
        // the corrected continuation key is `cursor`, NOT next_cursor
        assertEquals("cur_2", full.cursor)

        // empty body: items default to empty list, cursor to null
        val empty = requireNotNull(adapter.fromJson("""{}"""))
        assertTrue(empty.items.isEmpty())
        assertNull(empty.cursor)
    }

    @Test
    fun listEnvelope_ignoresNextCursorKey_cursorStaysNull() {
        // A stray next_cursor (the WRONG key) must NOT populate `cursor`; the reflective adapter tolerates it
        // as an unknown extra key and the real continuation field stays null.
        val adapter = moshi.adapter(ProjectListEnvelope::class.java)
        val envelope = requireNotNull(
            adapter.fromJson(
                """{"items":[{"id":"prj_1","owner":"u","name":"n",
                     "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}],
                   "next_cursor":"WRONG"}""",
            ),
        )
        assertNull(envelope.cursor)
        assertEquals(1, envelope.items.size)
    }

    // ---- detail envelope: { project, files[], cursor }; files decode leniently and are ignored downstream ----

    @Test
    fun detailEnvelope_decodesProject_keepsFilesAsRawMaps_andCursor() {
        val adapter = moshi.adapter(ProjectDetailEnvelope::class.java)
        val envelope = requireNotNull(
            adapter.fromJson(
                """{"project":{"id":"prj_1","owner":"usr_9","name":"Demo",
                     "created_at":"2026-05-30T12:00:00Z","updated_at":"2026-06-01T09:15:00Z"},
                   "files":[{"id":"f1","provider":"google_drive","provider_ref":"gd_1"}],
                   "cursor":"cur_files"}""",
            ),
        )
        assertEquals("prj_1", envelope.project.id)
        assertEquals(1, envelope.files.size)
        // files are decoded as raw maps (AND-336 scope); provider lives on the FILE, not the project
        assertEquals("google_drive", envelope.files[0]["provider"])
        assertEquals("cur_files", envelope.cursor)

        // sparse body: files default to empty, cursor to null
        val sparse = requireNotNull(
            adapter.fromJson(
                """{"project":{"id":"p","owner":"o","name":"n",
                     "created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}}""",
            ),
        )
        assertTrue(sparse.files.isEmpty())
        assertNull(sparse.cursor)
    }

    // ---- provider OAuth start + credential shapes ----

    @Test
    fun startOut_decodesAllFourRequiredFields() {
        val adapter = moshi.adapter(ProviderOAuthStartOut::class.java)
        val start = requireNotNull(
            adapter.fromJson(
                """{"provider":"google_drive",
                     "authorization_url":"https://accounts.google.com/o/oauth2/v2/auth?x=1",
                     "state":"st_1","expires_at":"2026-06-06T12:10:00Z"}""",
            ),
        )
        assertEquals(ProjectProviders.GOOGLE_DRIVE, start.provider)
        assertEquals("https://accounts.google.com/o/oauth2/v2/auth?x=1", start.authorizationUrl)
        assertEquals("st_1", start.state)
        assertEquals("2026-06-06T12:10:00Z", start.expiresAt)
    }

    @Test
    fun credentialOut_decodesScopesMetadata_andSparseDefaults() {
        val adapter = moshi.adapter(ProviderCredentialOut::class.java)
        val full = requireNotNull(
            adapter.fromJson(
                """{"provider":"google_drive","org":"org_1",
                     "scopes":["https://www.googleapis.com/auth/drive.readonly"],
                     "metadata":{"k":"v"},
                     "created_at":"2026-06-06T12:10:00Z","updated_at":"2026-06-06T12:10:00Z"}""",
            ),
        )
        assertEquals("google_drive", full.provider)
        assertEquals("org_1", full.org)
        assertEquals(listOf("https://www.googleapis.com/auth/drive.readonly"), full.scopes)
        assertEquals("v", full.metadata["k"])

        // there is NO account_email / folder_id; sparse body defaults org/scopes/metadata
        val sparse = requireNotNull(adapter.fromJson("""{"provider":"google_drive"}"""))
        assertNull(sparse.org)
        assertTrue(sparse.scopes.isEmpty())
        assertTrue(sparse.metadata.isEmpty())
        assertNull(sparse.createdAt)
    }

    @Test
    fun callbackIn_serializesCodeAndState() {
        val adapter = moshi.adapter(ProviderOAuthCallbackIn::class.java)
        val json = adapter.toJson(ProviderOAuthCallbackIn(code = "4/abc", state = "st_1"))
        val decoded = requireNotNull(adapter.fromJson(json))
        assertEquals("4/abc", decoded.code)
        assertEquals("st_1", decoded.state)
    }

    // ---- required-field enforcement (no default -> JsonDataException) ----

    @Test
    fun project_missingRequiredId_throws() {
        val adapter = moshi.adapter(ProjectOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson(
                """{"owner":"u","name":"n","created_at":"2026-01-01T00:00:00Z",
                    "updated_at":"2026-01-01T00:00:00Z"}""",
            )
        }
    }

    @Test
    fun project_missingRequiredTimestamps_throws() {
        val adapter = moshi.adapter(ProjectOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson("""{"id":"p","owner":"u","name":"n"}""")
        }
    }

    @Test
    fun startOut_missingRequiredAuthorizationUrl_throws() {
        val adapter = moshi.adapter(ProviderOAuthStartOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson("""{"provider":"google_drive","state":"s","expires_at":"2026-01-01T00:00:00Z"}""")
        }
    }

    @Test
    fun credentialOut_missingRequiredProvider_throws() {
        val adapter = moshi.adapter(ProviderCredentialOut::class.java)
        assertThrows(JsonDataException::class.java) {
            adapter.fromJson("""{"org":"org_1"}""")
        }
    }
}
