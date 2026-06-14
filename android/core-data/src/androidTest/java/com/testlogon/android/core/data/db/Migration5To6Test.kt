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
 * AND-302 — verifies [TestLogonDatabase.MIGRATION_5_6] creates the pending_recording table additively
 * without disturbing the pre-existing v5 vod_download table/rows.
 */
@RunWith(AndroidJUnit4::class)
class Migration5To6Test {

    @Test
    fun migration_5_6_creates_pending_recording_table() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "migration-5-6-test.db"
        ctx.deleteDatabase(dbName)

        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(5) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    // Minimal v5 vod_download table + a seed row (pre-existing data must survive).
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS vod_download (" +
                            "video_id TEXT NOT NULL PRIMARY KEY, status TEXT NOT NULL, " +
                            "percent INTEGER NOT NULL DEFAULT 0, local_uri TEXT, " +
                            "size_bytes INTEGER NOT NULL DEFAULT 0, watermarked INTEGER NOT NULL DEFAULT 0, " +
                            "strategy TEXT NOT NULL DEFAULT 'SERVER_BURNED_IN', " +
                            "identity_id TEXT NOT NULL DEFAULT '', watermark_payload TEXT, error TEXT, " +
                            "completed_at_epoch_ms INTEGER NOT NULL DEFAULT 0, " +
                            "updated_at_epoch_ms INTEGER NOT NULL DEFAULT 0)",
                    )
                    db.execSQL(
                        "INSERT INTO vod_download (video_id, status) VALUES ('v1','COMPLETED')",
                    )
                }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            })
            .build()
        val helper = factory.create(config)

        TestLogonDatabase.MIGRATION_5_6.migrate(helper.writableDatabase)

        // New table exists and accepts inserts.
        helper.writableDatabase.execSQL(
            "INSERT INTO pending_recording (recording_id, call_id, file_path, size_bytes, duration_ms, " +
                "phase, attempts, created_at) VALUES ('rec_1','c1','/tmp/rec_1.mp4',2048,12500,'PendingUpload',0,1)",
        )
        helper.writableDatabase.query("SELECT recording_id FROM pending_recording WHERE recording_id='rec_1'").use { c ->
            assertTrue(c.moveToFirst())
        }
        // Pre-existing vod_download row survives.
        helper.writableDatabase.query("SELECT video_id FROM vod_download WHERE video_id='v1'").use { c ->
            assertTrue(c.moveToFirst())
        }
        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
