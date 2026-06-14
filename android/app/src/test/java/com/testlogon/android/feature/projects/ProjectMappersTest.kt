package com.testlogon.android.feature.projects

import com.testlogon.android.core.network.projects.ProjectOut
import com.testlogon.android.core.network.projects.ProviderCredentialOut
import com.testlogon.android.core.network.projects.ProviderOAuthStartOut
import com.testlogon.android.feature.projects.data.toDomain
import com.testlogon.android.feature.projects.data.toDriveConnection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-374 - DTO -> domain mapper tests: ProjectOut maps id/owner/name/description/tags/timestamps verbatim
 * (no status / providers on the wire), the start DTO maps all four fields, and a credential maps to a
 * connected=true DriveConnection carrying the scopes. Absent optionals (null description) survive.
 */
class ProjectMappersTest {

    @Test
    fun projectOut_mapsFields_verbatim() {
        val out = ProjectOut(
            id = "p1",
            owner = "usr_1",
            name = "Spring Campaign",
            description = "Q2 assets",
            tags = listOf("q2", "campaign"),
            settings = mapOf("k" to "v"),
            createdAt = "2026-05-01T10:00:00Z",
            updatedAt = "2026-05-30T12:01:02Z",
        )
        val project = out.toDomain()
        assertEquals("p1", project.id)
        assertEquals("usr_1", project.owner)
        assertEquals("Spring Campaign", project.name)
        assertEquals("Q2 assets", project.description)
        assertEquals(listOf("q2", "campaign"), project.tags)
        assertEquals("2026-05-01T10:00:00Z", project.createdAt)
        assertEquals("2026-05-30T12:01:02Z", project.updatedAt)
    }

    @Test
    fun projectOut_absentDescription_mapsNull() {
        val out = ProjectOut(
            id = "p2",
            owner = "usr_2",
            name = "No desc",
            description = null,
            createdAt = "2026-01-01T00:00:00Z",
            updatedAt = "2026-01-02T00:00:00Z",
        )
        assertNull(out.toDomain().description)
        assertTrue(out.toDomain().tags.isEmpty())
    }

    @Test
    fun startOut_mapsAllFields() {
        val out = ProviderOAuthStartOut(
            provider = "google_drive",
            authorizationUrl = "https://accounts.google.com/x",
            state = "st_9",
            expiresAt = "2026-06-06T12:10:00Z",
        )
        val start = out.toDomain()
        assertEquals("google_drive", start.provider)
        assertEquals("https://accounts.google.com/x", start.authorizationUrl)
        assertEquals("st_9", start.state)
        assertEquals("2026-06-06T12:10:00Z", start.expiresAt)
    }

    @Test
    fun credentialOut_mapsToConnectedWithScopes() {
        val out = ProviderCredentialOut(
            provider = "google_drive",
            scopes = listOf("drive.readonly"),
        )
        val conn = out.toDriveConnection()
        assertTrue(conn.connected)
        assertEquals(listOf("drive.readonly"), conn.scopes)
    }
}
