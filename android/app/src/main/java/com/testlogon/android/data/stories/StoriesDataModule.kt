package com.testlogon.android.data.stories

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-199 / AND-200 — provides the dedicated [StoriesApi] on the shared Retrofit and binds the stories
 * repositories. Kept separate from the feed / messaging modules so this feature never touches their
 * wiring. The reply repository reuses the already-provided MessagingApi for the DM send path.
 */
@Module
@InstallIn(SingletonComponent::class)
object StoriesApiModule {

    @Provides
    @Singleton
    fun provideStoriesApi(retrofit: Retrofit): StoriesApi =
        retrofit.create(StoriesApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class StoriesDataModule {

    @Binds
    @Singleton
    abstract fun bindStoriesRepository(impl: StoriesRepositoryImpl): StoriesRepository

    @Binds
    @Singleton
    abstract fun bindStoryReplyRepository(impl: StoryReplyRepositoryImpl): StoryReplyRepository
}
