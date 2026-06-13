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
 * AND-348 — verifies [TestLogonDatabase.MIGRATION_7_8] creates the session_draft table additively
 * without disturbing the pre-existing v7 broadcast_layout table/rows.
 */
@RunWith(AndroidJUnit4::class)
class Migration7To8Test {

    @Test
    fun migration_7_8_creates_session_draft_table() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val dbName = "migration-7-8-test.db"
        ctx.deleteDatabase(dbName)

        val factory = FrameworkSQLiteOpenHelperFactory()
        val config = SupportSQLiteOpenHelper.Configuration.builder(ctx)
            .name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(7) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    // Minimal v7 broadcast_layout table + a seed row (pre-existing data must survive).
                    db.execSQL(
                        "CREATE TABLE IF NOT EXISTS broadcast_layout (" +
                            "session_id TEXT NOT NULL PRIMARY KEY, mode TEXT NOT NULL, " +
                            "primary_input_id TEXT, input_ids TEXT NOT NULL DEFAULT '')",
                    )
                    db.execSQL(
                        "INSERT INTO broadcast_layout (session_id, mode, primary_input_id, input_ids) " +
                            "VALUES ('bcs_1','single','in_1','in_1')",
                    )
                }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            })
            .build()
        val helper = factory.create(config)

        TestLogonDatabase.MIGRATION_7_8.migrate(helper.writableDatabase)

        // New session_draft table exists and accepts inserts (slug PK; nullable cursor columns).
        helper.writableDatabase.execSQL(
            "INSERT INTO session_draft (slug, session_id, questionnaire_id, version_id, answers_json, " +
                "dirty, updated_at) VALUES ('slug-a','rs_1','q1','v1','{}',1,5)",
        )
        helper.writableDatabase.query(
            "SELECT slug FROM session_draft WHERE slug='slug-a'",
        ).use { c -> assertTrue(c.moveToFirst()) }

        // A row with NULL cursor columns is accepted (current_section_index / current_question_id nullable).
        helper.writableDatabase.execSQL(
            "INSERT INTO session_draft (slug, session_id, questionnaire_id, version_id, answers_json, " +
                "current_section_index, current_question_id, dirty, updated_at) " +
                "VALUES ('slug-b','rs_2','q1','v1','{}',NULL,NULL,0,0)",
        )
        helper.writableDatabase.query(
            "SELECT slug FROM session_draft WHERE slug='slug-b'",
        ).use { c -> assertTrue(c.moveToFirst()) }

        // Pre-existing broadcast_layout row survives.
        helper.writableDatabase.query(
            "SELECT session_id FROM broadcast_layout WHERE session_id='bcs_1'",
        ).use { c -> assertTrue(c.moveToFirst()) }

        helper.close()
        ctx.deleteDatabase(dbName)
    }
}
