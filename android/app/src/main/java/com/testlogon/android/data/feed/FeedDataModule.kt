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

    /** Post-compose (create a newsfeed post) API on the shared Retrofit. */
    @Provides
    @Singleton
    fun providePostComposeApi(retrofit: Retrofit): PostComposeApi =
        retrofit.create(PostComposeApi::class.java)

    /** AND-173 / AND-174 / AND-175 — feed content-engagement API on the shared Retrofit. */
    @Provides
    @Singleton
    fun provideEngagementApi(retrofit: Retrofit): EngagementApi =
        retrofit.create(EngagementApi::class.java)

    /** AND-179 — poll vote API on the shared Retrofit. */
    @Provides
    @Singleton
    fun providePollApi(retrofit: Retrofit): PollApi =
        retrofit.create(PollApi::class.java)

    /** SOCIAL-002 — public reposting API on the shared Retrofit. */
    @Provides
    @Singleton
    fun provideRepostApi(retrofit: Retrofit): RepostApi =
        retrofit.create(RepostApi::class.java)

    /** Arbitrary text-option poll vote and close client (ui polls routes) shared across surfaces. */
    @Provides
    @Singleton
    fun provideArbitraryPollApi(retrofit: Retrofit): com.testlogon.android.data.poll.ArbitraryPollApi =
        retrofit.create(com.testlogon.android.data.poll.ArbitraryPollApi::class.java)

    /** FD1 — current-user identity (GET /ui/me) for the "Your posts" author filter. */
    @Provides
    @Singleton
    fun provideCurrentUserApi(retrofit: Retrofit): CurrentUserApi =
        retrofit.create(CurrentUserApi::class.java)
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

    /** SOCIAL-002 — repost / un-repost repository. */
    @Binds
    @Singleton
    abstract fun bindRepostRepository(impl: RepostRepositoryImpl): RepostRepository

    /** AND-179 — poll vote repository. */
    @Binds
    @Singleton
    abstract fun bindPollRepository(impl: PollRepositoryImpl): PollRepository

    /** #24 — image-upload seam used by the comments VM (delegates to the post-compose repo). */
    @Binds
    @Singleton
    abstract fun bindCommentImageUploader(impl: PostComposeRepository): CommentImageUploader
}
