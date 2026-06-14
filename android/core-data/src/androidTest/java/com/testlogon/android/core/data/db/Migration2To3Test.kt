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
 * AND-175 — verifies [TestLogonDatabase.MIGRATION_2_3] creates the post_suppression table additively
 * without disturbing existing v2 tables/rows.
 */
@RunWith(AndroidJUnit4::class)
class Migration2To3Test {

    @Test
    fun migration_2_3_creates_post_suppression_table() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "migration-2-3-test.db"
        ctx.deleteDatabase(dbName)

        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(2) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    // Minimal v2 schema (cached_sample with v2 columns) + a seed row.
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS cached_sample (" +
                            "id TEXT NOT NULL PRIMARY KEY, payload TEXT NOT NULL, updated_at INTEGER NOT NULL, " +
                            "fetched_at INTEGER NOT NULL DEFAULT 0, last_accessed_at INTEGER NOT NULL DEFAULT 0, " +
                            "user_scope TEXT, approx_bytes INTEGER NOT NULL DEFAULT 0)",
                    )
                    db.execSQL("INSERT INTO cached_sample (id, payload, updated_at) VALUES ('k1','v',1)")
                }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            })
            .build()
        val helper = factory.create(config)

        TestLogonDatabase.MIGRATION_2_3.migrate(helper.writableDatabase)

        // New table exists and accepts inserts.
        helper.writableDatabase.execSQL(
            "INSERT INTO post_suppression (post_id, kind, created_at_epoch_ms, pending) " +
                "VALUES ('p1','HIDDEN',100,0)",
        )
        helper.writableDatabase.query("SELECT post_id FROM post_suppression WHERE post_id='p1'").use { c ->
            assertTrue(c.moveToFirst())
        }
        // Pre-existing row survives.
        helper.writableDatabase.query("SELECT payload FROM cached_sample WHERE id='k1'").use { c ->
            assertTrue(c.moveToFirst())
        }
        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
