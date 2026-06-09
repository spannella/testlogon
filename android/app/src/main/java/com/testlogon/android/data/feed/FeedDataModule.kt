package com.testlogon.android.data.feed

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-097 — provides the [FeedApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object FeedApiModule {

    @Provides
    @Singleton
    fun provideFeedApi(retrofit: Retrofit): FeedApi =
        retrofit.create(FeedApi::class.java)
}

/** AND-097 — binds the feed repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class FeedDataModule {

    @Binds
    @Singleton
    abstract fun bindFeedRepository(impl: FeedRepositoryImpl): FeedRepository
}
