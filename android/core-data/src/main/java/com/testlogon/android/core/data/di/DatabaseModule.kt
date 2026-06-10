package com.testlogon.android.core.data.di

import android.content.Context
import androidx.room.Room
import com.testlogon.android.core.data.BuildConfig
import com.testlogon.android.core.data.cache.CacheMaintenanceDao
import com.testlogon.android.core.data.db.TestLogonDatabase
import com.testlogon.android.core.data.db.sample.SampleDao
import com.testlogon.android.core.data.feed.BookmarkStateDao
import com.testlogon.android.core.data.feed.PostSuppressionDao
import com.testlogon.android.core.data.paywall.EntitlementDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * AND-115 — Hilt provisioning for the Room cache.
 *
 * The database is a process [Singleton] bound to the application context. Real migrations
 * ([TestLogonDatabase.ALL_MIGRATIONS]) are always registered; `fallbackToDestructiveMigration()`
 * is enabled ONLY in debug builds (cache data is reconstructable, so destructive recovery is
 * acceptable while iterating, but release builds must never silently drop data — a missing
 * migration throws instead).
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext ctx: Context): TestLogonDatabase =
        Room.databaseBuilder(ctx, TestLogonDatabase::class.java, TestLogonDatabase.NAME)
            .addMigrations(*TestLogonDatabase.ALL_MIGRATIONS)
            .apply { if (BuildConfig.DEBUG) fallbackToDestructiveMigration() }
            .build()

    @Provides
    fun provideSampleDao(db: TestLogonDatabase): SampleDao = db.sampleDao()

    @Provides
    fun provideCacheMaintenanceDao(db: TestLogonDatabase): CacheMaintenanceDao =
        db.cacheMaintenanceDao()

    @Provides
    fun providePostSuppressionDao(db: TestLogonDatabase): PostSuppressionDao =
        db.postSuppressionDao()

    @Provides
    fun provideBookmarkStateDao(db: TestLogonDatabase): BookmarkStateDao =
        db.bookmarkStateDao()

    @Provides
    fun provideEntitlementDao(db: TestLogonDatabase): EntitlementDao =
        db.entitlementDao()
}
