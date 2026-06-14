package com.testlogon.android.core.data.messaging

import android.content.Context
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-140 / AND-141 — verifies [MessagingDatabase.MIGRATION_5_6] adds the moderation/engagement
 * columns to `messages`, creates the `drafts` table, and preserves existing rows (TC-AND-140-10).
 * Builds a minimal pre-v6 `messages` schema by hand so the test does not depend on exported assets.
 */
@RunWith(AndroidJUnit4::class)
class MessagingMigration5To6Test {

    @Test
    fun migration_5_6_adds_columns_creates_drafts_and_preserves_rows() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "messaging-migration-5-6.db"
        ctx.deleteDatabase(dbName)

        // --- Build a minimal pre-v6 `messages` table (only the columns the migration adds to) + seed. ---
        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(5) {
                override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS messages (" +
                            "messageId TEXT NOT NULL PRIMARY KEY, conversationId TEXT NOT NULL, " +
                            "text TEXT NOT NULL)",
                    )
                }
                override fun onUpgrade(
                    db: androidx.sqlite.db.SupportSQLiteDatabase,
                    oldVersion: Int,
                    newVersion: Int,
                ) = Unit
            })
            .build()
        val helper = factory.create(config)
        helper.writableDatabase.execSQL(
            "INSERT INTO messages (messageId, conversationId, text) VALUES ('m1', 'c1', 'hi')",
        )

        // --- Apply MIGRATION_5_6 directly. ---
        MessagingDatabase.MIGRATION_5_6.migrate(helper.writableDatabase)

        // --- New columns exist on `messages`. ---
        val cols = mutableSetOf<String>()
        helper.writableDatabase.query("PRAGMA table_info(messages)").use { c ->
            val nameIdx = c.getColumnIndex("name")
            while (c.moveToNext()) cols.add(c.getString(nameIdx))
        }
        assertTrue(
            cols.containsAll(listOf("reactionsJson", "isPinned", "lifecycle", "editedAtEpochSeconds", "isHidden")),
        )

        // --- Existing row survives with backfilled defaults. ---
        helper.writableDatabase.query(
            "SELECT text, isPinned, lifecycle, isHidden FROM messages WHERE messageId = 'm1'",
        ).use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("hi", c.getString(0))
            assertEquals(0L, c.getLong(1))
            assertEquals("ACTIVE", c.getString(2))
            assertEquals(0L, c.getLong(3))
        }

        // --- The drafts table was created and is writable. ---
        helper.writableDatabase.execSQL(
            "INSERT INTO drafts (conversationId, text, updatedAtEpochMs, version, remoteId, pendingSync) " +
                "VALUES ('c1', 'draft', 5, 1, NULL, 0)",
        )
        helper.writableDatabase.query("SELECT text FROM drafts WHERE conversationId = 'c1'").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("draft", c.getString(0))
        }

        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
