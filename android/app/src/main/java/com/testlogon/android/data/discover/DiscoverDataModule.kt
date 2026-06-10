package com.testlogon.android.data.discover

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-182..AND-185 — provides the dedicated [DiscoverApi] / [SearchApi] on the shared Retrofit and
 * binds the discover / tag / recommendations / search repositories. Kept separate from the messaging +
 * feed modules so this feature never touches their wiring.
 */
@Module
@InstallIn(SingletonComponent::class)
object DiscoverApiModule {

    @Provides
    @Singleton
    fun provideDiscoverApi(retrofit: Retrofit): DiscoverApi =
        retrofit.create(DiscoverApi::class.java)

    @Provides
    @Singleton
    fun provideSearchApi(retrofit: Retrofit): SearchApi =
        retrofit.create(SearchApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class DiscoverDataModule {

    @Binds
    @Singleton
    abstract fun bindDiscoverRepository(impl: DiscoverRepositoryImpl): DiscoverRepository

    @Binds
    @Singleton
    abstract fun bindTagRepository(impl: TagRepositoryImpl): TagRepository

    @Binds
    @Singleton
    abstract fun bindRecommendationsRepository(impl: RecommendationsRepositoryImpl): RecommendationsRepository

    @Binds
    @Singleton
    abstract fun bindSearchRepository(impl: SearchRepositoryImpl): SearchRepository

    @Binds
    @Singleton
    abstract fun bindSearchHistoryRepository(impl: SearchHistoryRepositoryImpl): SearchHistoryRepository
}
