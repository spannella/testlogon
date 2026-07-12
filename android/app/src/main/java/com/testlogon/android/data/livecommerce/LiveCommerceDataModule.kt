package com.testlogon.android.data.livecommerce

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * LIVECOM L5 — provides the [LiveCommerceApi] on the shared Retrofit and binds the repository. Kept
 * separate from cart/catalog wiring so the live-commerce contract owns its own module.
 */
@Module
@InstallIn(SingletonComponent::class)
object LiveCommerceApiModule {

    @Provides
    @Singleton
    fun provideLiveCommerceApi(retrofit: Retrofit): LiveCommerceApi =
        retrofit.create(LiveCommerceApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class LiveCommerceDataModule {

    @Binds
    @Singleton
    abstract fun bindLiveCommerceRepository(impl: LiveCommerceRepositoryImpl): LiveCommerceRepository
}
