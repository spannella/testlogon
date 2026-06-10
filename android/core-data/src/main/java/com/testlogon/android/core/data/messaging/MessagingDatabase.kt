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
        CustomEmojiEntity::class,
        MeetingPollEntity::class,
        MeetingPollSlotEntity::class,
    ],
    version = 5,
    exportSchema = true,
)
abstract class MessagingDatabase : RoomDatabase() {
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun outboxDao(): OutboxDao
    abstract fun customEmojiDao(): CustomEmojiDao
    abstract fun meetingPollDao(): MeetingPollDao

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

        /**
         * AND-134 / AND-135 / AND-136 — adds the additive voicemail + gif + sticker + meeting-poll
         * columns to `messages`. All new columns are nullable or carry a default, so v3 rows migrate
         * without data loss. (No new outbox columns: voicemail reuses the AND-133 voice outbox
         * shape; gif/sticker send synchronously without an optimistic upload row.)
         */
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // messages — voicemail (AND-134)
                db.execSQL("ALTER TABLE messages ADD COLUMN voicemailMediaUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN voicemailIsVideo INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN voicemailCallId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN voicemailCallState TEXT")
                // messages — gif (AND-135)
                db.execSQL("ALTER TABLE messages ADD COLUMN gifUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN gifAltText TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN gifWidth INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN gifHeight INTEGER")
                // messages — sticker (AND-135)
                db.execSQL("ALTER TABLE messages ADD COLUMN stickerUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN stickerAltText TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN stickerId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN stickerCollectionId TEXT")
                // messages — meeting poll envelope (AND-136)
                db.execSQL("ALTER TABLE messages ADD COLUMN pollId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN pollTitle TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN pollCreatorId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN pollStatus TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN pollConfirmedSlotId TEXT")
                // New cache tables (AND-135 custom emoji, AND-136 meeting polls).
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS custom_emoji (" +
                        "shortcode TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, " +
                        "imageUrl TEXT NOT NULL, animated INTEGER NOT NULL, fetchedAt INTEGER NOT NULL)",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS meeting_polls (" +
                        "pollId TEXT NOT NULL PRIMARY KEY, conversationId TEXT NOT NULL, " +
                        "title TEXT NOT NULL, durationMinutes INTEGER NOT NULL, " +
                        "creatorId TEXT NOT NULL, status TEXT NOT NULL, confirmedSlotId TEXT)",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS meeting_poll_slots (" +
                        "slotId TEXT NOT NULL PRIMARY KEY, pollId TEXT NOT NULL, " +
                        "position INTEGER NOT NULL, startUtc TEXT NOT NULL, endUtc TEXT NOT NULL, " +
                        "yesCount INTEGER NOT NULL, maybeCount INTEGER NOT NULL, " +
                        "noCount INTEGER NOT NULL, myVote TEXT)",
                )
            }
        }

        /**
         * AND-137 / AND-138 / AND-139 — adds the additive countdown, calendar-event/share, and
         * monetization columns to `messages`. All new columns are nullable or carry a default, so v4
         * rows migrate without data loss. (No new outbox columns: countdown sends through the text
         * outbox path; unlock/tip are non-optimistic writes with no outbox row.)
         */
        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // messages — countdown (AND-137)
                db.execSQL("ALTER TABLE messages ADD COLUMN countdownTitle TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN countdownTargetEpochSeconds INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN countdownEventType TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN countdownEventId TEXT")
                // messages — calendar event (AND-138)
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventCalendarId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventName TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventStartUtc TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventEndUtc TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventAllDay INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventAllDayDate TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventTimezone TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventDescription TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calEventOwner TEXT")
                // messages — calendar share (AND-138)
                db.execSQL("ALTER TABLE messages ADD COLUMN calShareCalendarId TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calShareName TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calShareOwner TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calSharePermission TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN calShareBookingUrl TEXT")
                // messages — monetization (AND-139)
                db.execSQL("ALTER TABLE messages ADD COLUMN monetizationType TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN monetizationUnlocked INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN lockPriceCents INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN lockCurrency TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN lockTeaser TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN revealedText TEXT")
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
        builder.addMigrations(
            MessagingDatabase.MIGRATION_1_2,
            MessagingDatabase.MIGRATION_2_3,
            MessagingDatabase.MIGRATION_3_4,
            MessagingDatabase.MIGRATION_4_5,
        )
        if (BuildConfig.DEBUG) builder.fallbackToDestructiveMigration()
        return builder.build()
    }

    @Provides
    fun provideConversationDao(db: MessagingDatabase): ConversationDao = db.conversationDao()

    @Provides
    fun provideMessageDao(db: MessagingDatabase): MessageDao = db.messageDao()

    @Provides
    fun provideOutboxDao(db: MessagingDatabase): OutboxDao = db.outboxDao()

    @Provides
    fun provideCustomEmojiDao(db: MessagingDatabase): CustomEmojiDao = db.customEmojiDao()

    @Provides
    fun provideMeetingPollDao(db: MessagingDatabase): MeetingPollDao = db.meetingPollDao()
}
