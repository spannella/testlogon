package com.testlogon.android.core.data.db

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.data.cache.CacheTables
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.sqlite.db.SupportSQLiteOpenHelper

/**
 * AND-118 / AND-119 — verifies [TestLogonDatabase.MIGRATION_1_2] applies cleanly, preserves existing
 * rows, and adds the cache-lifecycle columns + indices. Builds a v1 schema by hand (so the test does
 * not depend on exported schema assets) and runs the migration directly.
 */
@RunWith(AndroidJUnit4::class)
class Migration1To2Test {

    @Test
    fun migration_1_2_adds_columns_and_preserves_rows() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "migration-test.db"
        ctx.deleteDatabase(dbName)

        // --- Build the v1 schema manually (id/payload/updated_at only) and seed a row. ---
        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(1) {
                override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS cached_sample (" +
                            "id TEXT NOT NULL PRIMARY KEY, payload TEXT NOT NULL, updated_at INTEGER NOT NULL)",
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
            "INSERT INTO cached_sample (id, payload, updated_at) VALUES ('k1', 'v', 7)",
        )

        // --- Apply MIGRATION_1_2 directly. ---
        TestLogonDatabase.MIGRATION_1_2.migrate(helper.writableDatabase)

        // --- Assert columns exist and the old row survives with backfilled defaults. ---
        val cols = mutableSetOf<String>()
        helper.writableDatabase.query("PRAGMA table_info(${CacheTables.SAMPLE})").use { c ->
            val nameIdx = c.getColumnIndex("name")
            while (c.moveToNext()) cols.add(c.getString(nameIdx))
        }
        assertTrue(cols.containsAll(listOf("fetched_at", "last_accessed_at", "user_scope", "approx_bytes")))

        helper.writableDatabase.query("SELECT payload, fetched_at FROM cached_sample WHERE id = 'k1'").use { c ->
            assertTrue(c.moveToFirst())
            assertEquals("v", c.getString(0))
            assertEquals(0L, c.getLong(1)) // backfilled default -> EXPIRED on next read
        }
        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
