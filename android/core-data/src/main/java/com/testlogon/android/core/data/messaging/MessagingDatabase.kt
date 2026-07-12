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
        DraftEntity::class,
        ParticipantEntity::class,
    ],
    version = 17,
    exportSchema = true,
)
abstract class MessagingDatabase : RoomDatabase() {
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun outboxDao(): OutboxDao
    abstract fun customEmojiDao(): CustomEmojiDao
    abstract fun meetingPollDao(): MeetingPollDao
    abstract fun draftDao(): DraftDao
    abstract fun participantDao(): ParticipantDao

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

        /**
         * AND-140 / AND-141 — adds the additive moderation/engagement columns to `messages`
         * (reactions / pins / edits / lifecycle / hide) and creates the AND-141 `drafts` table. All
         * new message columns are nullable or carry a default, so v5 rows migrate without data loss.
         */
        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // messages — reactions / pins / edits / lifecycle / hide (AND-140)
                db.execSQL("ALTER TABLE messages ADD COLUMN reactionsJson TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN isPinned INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'ACTIVE'")
                db.execSQL("ALTER TABLE messages ADD COLUMN editedAtEpochSeconds INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN isHidden INTEGER NOT NULL DEFAULT 0")
                // New drafts table (AND-141)
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS drafts (" +
                        "conversationId TEXT NOT NULL PRIMARY KEY, text TEXT NOT NULL, " +
                        "updatedAtEpochMs INTEGER NOT NULL, version INTEGER NOT NULL, " +
                        "remoteId TEXT, pendingSync INTEGER NOT NULL)",
                )
            }
        }

        /**
         * AND-158 — creates the `group_participant` roster cache table. Additive (a new table only),
         * so v6 rows migrate without data loss. Composite PK (conversationId, userId).
         */
        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS group_participant (" +
                        "conversationId TEXT NOT NULL, userId TEXT NOT NULL, " +
                        "displayName TEXT, avatarUrl TEXT, role TEXT NOT NULL, " +
                        "joinedAtEpochSeconds INTEGER NOT NULL, " +
                        "PRIMARY KEY(conversationId, userId))",
                )
            }
        }

        /** Adds the reply-to link to `messages` (additive, nullable). */
        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN replyToMessageId TEXT")
            }
        }

        /** AND-147 — persist delivery/read receipt counts so the Sent/Delivered/Read indicator survives a reload. */
        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN deliveredToCount INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN readByCount INTEGER NOT NULL DEFAULT 0")
            }
        }

        /** Persist self-destruct expiry so expired messages render redacted after a reload. */
        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN expiresAtEpochSeconds INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN serverExpired INTEGER NOT NULL DEFAULT 0")
            }
        }

        /**
         * MSG — persist find_datetime detail, lottery lock_state + outcome, and the client-side
         * encryption envelope + is_encrypted flag so these media types survive the receiver's Room
         * round-trip (they were previously dropped, rendering as plain text / empty bubbles).
         */
        val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN fadtFromDate TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN fadtToDate TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN fadtStartHour INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN fadtEndHour INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN fadtSlotDurationMinutes INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN lotteryLockState TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN lotterySelectedText TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN isEncrypted INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN encVersion INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN encAlg TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN encKdf TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN encIterations INTEGER")
                db.execSQL("ALTER TABLE messages ADD COLUMN encSaltB64 TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN encIvB64 TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN encCiphertextB64 TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN viewOnce INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE messages ADD COLUMN consumed INTEGER NOT NULL DEFAULT 0")
            }
        }

        /**
         * C6 — persist gallery (multi-image) images so a kind="gallery" message survives the Room
         * round-trip (previously dropped -> rendered as an empty/text bubble after the DB read).
         */
        val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN galleryImagesJson TEXT")
            }
        }

        // MV2 — persist the playable object url for uploaded video clips so a reconciled/cached
        // video bubble keeps its in-app playback source across restarts.
        val MIGRATION_12_13 = object : Migration(12, 13) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN fileUrl TEXT")
            }
        }

        // #13 — persist the revealed lottery option media (image/video) url so an unlocked lottery
        // bubble keeps its revealed thumbnail across a Room round-trip / app restart.
        val MIGRATION_13_14 = object : Migration(13, 14) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN revealedMediaUrl TEXT")
                db.execSQL("ALTER TABLE messages ADD COLUMN revealedMediaIsVideo INTEGER NOT NULL DEFAULT 0")
            }
        }

        // #24 - persist the FULL revealed lottery media list (image+video) so a multi-media reveal
        // survives a Room round-trip / app restart (revealedMediaUrl kept as the first element).
        val MIGRATION_14_15 = object : Migration(14, 15) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN revealedMediaJson TEXT")
            }
        }

        // #15 (B-LOTSENDER) — persist the SENDER's lottery sender-view (full config + per-recipient
        // results) so the sender's own detail survives a Room round-trip / app restart.
        val MIGRATION_15_16 = object : Migration(15, 16) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN lotterySenderViewJson TEXT")
            }
        }

        // Arbitrary text-option poll: persist the poll snapshot JSON for kind="poll" messages.
        val MIGRATION_16_17 = object : Migration(16, 17) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE messages ADD COLUMN pollJson TEXT")
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
            MessagingDatabase.MIGRATION_5_6,
            MessagingDatabase.MIGRATION_6_7,
            MessagingDatabase.MIGRATION_7_8,
            MessagingDatabase.MIGRATION_8_9,
            MessagingDatabase.MIGRATION_9_10,
            MessagingDatabase.MIGRATION_10_11,
            MessagingDatabase.MIGRATION_11_12,
            MessagingDatabase.MIGRATION_12_13,
            MessagingDatabase.MIGRATION_13_14,
            MessagingDatabase.MIGRATION_14_15,
            MessagingDatabase.MIGRATION_15_16,
            MessagingDatabase.MIGRATION_16_17,
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

    @Provides
    fun provideDraftDao(db: MessagingDatabase): DraftDao = db.draftDao()

    @Provides
    fun provideParticipantDao(db: MessagingDatabase): ParticipantDao = db.participantDao()
}
