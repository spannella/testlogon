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
 * AND-195 — verifies [TestLogonDatabase.MIGRATION_4_5] creates the vod_download table additively
 * without disturbing pre-existing v4 tables/rows.
 */
@RunWith(AndroidJUnit4::class)
class Migration4To5Test {

    @Test
    fun migration_4_5_creates_vod_download_table() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "migration-4-5-test.db"
        ctx.deleteDatabase(dbName)

        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(4) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    // Minimal v4 entitlement table + a seed row (pre-existing data must survive).
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS entitlement (" +
                            "user_sub TEXT NOT NULL, post_id TEXT NOT NULL, " +
                            "unlocked_at_epoch_ms INTEGER NOT NULL, source TEXT NOT NULL, " +
                            "PRIMARY KEY(user_sub, post_id))",
                    )
                    db.execSQL(
                        "INSERT INTO entitlement (user_sub, post_id, unlocked_at_epoch_ms, source) " +
                            "VALUES ('u1','p1',1,'purchase')",
                    )
                }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            })
            .build()
        val helper = factory.create(config)

        TestLogonDatabase.MIGRATION_4_5.migrate(helper.writableDatabase)

        // New table exists and accepts inserts.
        helper.writableDatabase.execSQL(
            "INSERT INTO vod_download (video_id, status, percent, size_bytes, watermarked, strategy, " +
                "identity_id, completed_at_epoch_ms, updated_at_epoch_ms) " +
                "VALUES ('v1','COMPLETED',100,10,1,'SERVER_BURNED_IN','u1',5,5)",
        )
        helper.writableDatabase.query("SELECT video_id FROM vod_download WHERE video_id='v1'").use { c ->
            assertTrue(c.moveToFirst())
        }
        // Pre-existing entitlement row survives.
        helper.writableDatabase.query("SELECT post_id FROM entitlement WHERE post_id='p1'").use { c ->
            assertTrue(c.moveToFirst())
        }
        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
