package com.testlogon.android.data.wishlist

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * ECOM — provides the [WishlistApi] on the shared Retrofit and binds the singleton wishlist repository
 * (shared saved-set across product-detail, catalog cells and the Wishlist screen).
 */
@Module
@InstallIn(SingletonComponent::class)
object WishlistApiModule {

    @Provides
    @Singleton
    fun provideWishlistApi(retrofit: Retrofit): WishlistApi =
        retrofit.create(WishlistApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class WishlistDataModule {

    @Binds
    @Singleton
    abstract fun bindWishlistRepository(impl: WishlistRepositoryImpl): WishlistRepository
}
