package com.testlogon.android.core.data.messaging

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.testlogon.android.core.data.BuildConfig
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-115 — Room database for the messaging offline cache (conversations + messages) and the
 * optimistic send outbox.
 *
 * Debug builds use destructive migration so the schema can evolve freely during development;
 * release builds require real migrations (none yet — version 1).
 */
@Database(
    entities = [
        ConversationEntity::class,
        MessageEntity::class,
        OutboxMessageEntity::class,
    ],
    version = 3,
    exportSchema = true,
)
abstract class MessagingDatabase : RoomDatabase() {
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun outboxDao(): OutboxDao

    companion object {
        /**
         * AND-130 / AND-131 — adds the additive media columns to `messages`. All new columns are
         * nullable or carry a default, so legacy rows migrate without data loss.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text'")
                db.execSQL("ALTER TABLE messages ADD COLUMN imageUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN imageWidth INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN imageHeight INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN videoId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN videoTitle TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN videoThumbnailUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN videoDurationSeconds INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN videoHlsManifestUrl TEXT")
                db.execSQL(
                    "ALTER TABLE messages ADD COLUMN videoDrmEnabled INTEGER NOT NULL DEFAULT 0",
                )
                db.execSQL(
                    "ALTER TABLE outbox_messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text'",
                )
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN imageLocalUri TEXT")
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN uploadPercent INTEGER")
            }
        }

        /**
         * AND-132 / AND-133 — adds the additive file + voice columns to `messages` and
         * `outbox_messages`. All new columns are nullable or carry a default, so v2 rows migrate
         * without data loss.
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // messages — file/file_share
                db.execSQL("ALTER TABLE messages ADD COLUMN fileName TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN fileSizeBytes INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN fileMimeType TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN fileIsShare INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN consumptionPolicy TEXT NOT NULL DEFAULT 'none'")
                // messages — voice
                db.execSQL("ALTER TABLE messages ADD COLUMN voiceAudioUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN voiceDurationSeconds REAL")
                db.execSQL("ALTER TABLE messages ADD COLUMN voiceWaveformJson TEXT")
                // outbox — optimistic file/voice rows
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN attachmentLocalUri TEXT")
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN fileName TEXT")
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN fileSizeBytes INTEGER")
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN fileMimeType TEXT")
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN voiceDurationSeconds REAL")
                db.execSQL("ALTER TABLE outbox_messages ADD COLUMN voiceWaveformJson TEXT")
            }
        }
    }
}

@Module
@InstallIn(SingletonComponent::class)
object MessagingDatabaseModule {

    @Provides
    @Singleton
    fun provideMessagingDatabase(@ApplicationContext context: Context): MessagingDatabase {
        val builder = Room.databaseBuilder(
            context,
            MessagingDatabase::class.java,
            "messaging.db",
        )
        builder.addMigrations(MessagingDatabase.MIGRATION_1_2, MessagingDatabase.MIGRATION_2_3)
        if (BuildConfig.DEBUG) builder.fallbackToDestructiveMigration()
        return builder.build()
    }

    @Provides
    fun provideConversationDao(db: MessagingDatabase): ConversationDao = db.conversationDao()

    @Provides
    fun provideMessageDao(db: MessagingDatabase): MessageDao = db.messageDao()

    @Provides
    fun provideOutboxDao(db: MessagingDatabase): OutboxDao = db.outboxDao()
}
