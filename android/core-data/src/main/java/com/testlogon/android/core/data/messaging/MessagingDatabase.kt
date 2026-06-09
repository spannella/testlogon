package com.testlogon.android.core.data.messaging

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
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
    version = 1,
    exportSchema = true,
)
abstract class MessagingDatabase : RoomDatabase() {
    abstract fun conversationDao(): ConversationDao
    abstract fun messageDao(): MessageDao
    abstract fun outboxDao(): OutboxDao
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
