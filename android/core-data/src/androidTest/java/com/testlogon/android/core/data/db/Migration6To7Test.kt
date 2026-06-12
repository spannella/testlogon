package com.testlogon.android.core.data.db

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-310 — verifies [TestLogonDatabase.MIGRATION_6_7] creates the broadcast_input + broadcast_layout
 * tables additively without disturbing the pre-existing v6 pending_recording table/rows.
 */
@RunWith(AndroidJUnit4::class)
class Migration6To7Test {

    @Test
    fun migration_6_7_creates_broadcast_tables() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "migration-6-7-test.db"
        ctx.deleteDatabase(dbName)

        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(6) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    // Minimal v6 pending_recording table + a seed row (pre-existing data must survive).
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS pending_recording (" +
                            "recording_id TEXT NOT NULL PRIMARY KEY, call_id TEXT NOT NULL, " +
                            "file_path TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0, " +
                            "duration_ms INTEGER NOT NULL DEFAULT 0, phase TEXT NOT NULL, " +
                            "attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0)",
                    )
                    db.execSQL(
                        "INSERT INTO pending_recording (recording_id, call_id, file_path, phase) " +
                            "VALUES ('rec_1','c1','/tmp/rec_1.mp4','PendingUpload')",
                    )
                }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            })
            .build()
        val helper = factory.create(config)

        TestLogonDatabase.MIGRATION_6_7.migrate(helper.writableDatabase)

        // New broadcast_input table exists and accepts inserts (composite PK).
        helper.writableDatabase.execSQL(
            "INSERT INTO broadcast_input (session_id, input_id, input_type, label, is_live, position, " +
                "created_by) VALUES ('bcs_1','in_1','primary','Host',1,0,'host')",
        )
        helper.writableDatabase.query(
            "SELECT input_id FROM broadcast_input WHERE session_id='bcs_1' AND input_id='in_1'",
        ).use { c -> assertTrue(c.moveToFirst()) }

        // New broadcast_layout table exists and accepts inserts.
        helper.writableDatabase.execSQL(
            "INSERT INTO broadcast_layout (session_id, mode, primary_input_id, input_ids) " +
                "VALUES ('bcs_1','single','in_1','in_1')",
        )
        helper.writableDatabase.query(
            "SELECT session_id FROM broadcast_layout WHERE session_id='bcs_1'",
        ).use { c -> assertTrue(c.moveToFirst()) }

        // Pre-existing pending_recording row survives.
        helper.writableDatabase.query(
            "SELECT recording_id FROM pending_recording WHERE recording_id='rec_1'",
        ).use { c -> assertTrue(c.moveToFirst()) }

        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
