package com.testlogon.android.data.bookmarks

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-092 — provides the [BookmarksApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object BookmarksApiModule {

    @Provides
    @Singleton
    fun provideBookmarksApi(retrofit: Retrofit): BookmarksApi =
        retrofit.create(BookmarksApi::class.java)
}

/** AND-092 — binds the bookmarks repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class BookmarksDataModule {

    @Binds
    @Singleton
    abstract fun bindBookmarksRepository(impl: BookmarksRepositoryImpl): BookmarksRepository

    /** AND-176 — feed bookmark toggle repository (optimistic, Room-backed). */
    @Binds
    @Singleton
    abstract fun bindFeedBookmarkRepository(impl: FeedBookmarkRepositoryImpl): FeedBookmarkRepository
}
