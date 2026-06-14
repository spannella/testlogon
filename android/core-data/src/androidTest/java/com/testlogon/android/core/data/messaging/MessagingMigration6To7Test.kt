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
 * AND-158 — verifies [MessagingDatabase.MIGRATION_6_7] creates the `group_participant` roster table
 * and that it is writable, while preserving an existing v6 row in another table.
 */
@RunWith(AndroidJUnit4::class)
class MessagingMigration6To7Test {

    @Test
    fun migration_6_7_creates_group_participant_and_preserves_rows() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "messaging-migration-6-7.db"
        ctx.deleteDatabase(dbName)

        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(6) {
                override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS conversations (" +
                            "conversationId TEXT NOT NULL PRIMARY KEY, title TEXT NOT NULL, " +
                            "iconUrl TEXT, lastMessagePreview TEXT, " +
                            "lastActivityEpochSeconds INTEGER NOT NULL, unreadCount INTEGER NOT NULL)",
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
            "INSERT INTO conversations (conversationId, title, iconUrl, lastMessagePreview, " +
                "lastActivityEpochSeconds, unreadCount) VALUES ('c1', 'G', NULL, NULL, 1, 0)",
        )

        MessagingDatabase.MIGRATION_6_7.migrate(helper.writableDatabase)

        // The new roster table exists and is writable.
        helper.writableDatabase.execSQL(
            "INSERT INTO group_participant (conversationId, userId, displayName, avatarUrl, role, " +
                "joinedAtEpochSeconds) VALUES ('c1', 'u1', 'Ann', NULL, 'ADMIN', 0)",
        )
        helper.writableDatabase.query(
            "SELECT role FROM group_participant WHERE conversationId = 'c1' AND userId = 'u1'",
        ).use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("ADMIN", c.getString(0))
        }

        // Pre-existing conversation row survives.
        helper.writableDatabase.query("SELECT title FROM conversations WHERE conversationId = 'c1'").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("G", c.getString(0))
        }

        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
