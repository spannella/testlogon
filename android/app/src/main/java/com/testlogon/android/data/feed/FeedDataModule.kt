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

    /** AND-173 / AND-174 / AND-175 — feed content-engagement API on the shared Retrofit. */
    @Provides
    @Singleton
    fun provideEngagementApi(retrofit: Retrofit): EngagementApi =
        retrofit.create(EngagementApi::class.java)
}

/** AND-097 / AND-173 / AND-174 / AND-175 — binds the feed + engagement repositories. */
@Module
@InstallIn(SingletonComponent::class)
abstract class FeedDataModule {

    @Binds
    @Singleton
    abstract fun bindFeedRepository(impl: FeedRepositoryImpl): FeedRepository

    @Binds
    @Singleton
    abstract fun bindPostEngagementRepository(impl: PostEngagementRepositoryImpl): PostEngagementRepository

    @Binds
    @Singleton
    abstract fun bindCommentsRepository(impl: CommentsRepositoryImpl): CommentsRepository

    @Binds
    @Singleton
    abstract fun bindPostActionsRepository(impl: PostActionsRepositoryImpl): PostActionsRepository
}
