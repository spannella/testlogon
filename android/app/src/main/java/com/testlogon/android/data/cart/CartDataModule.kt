package com.testlogon.android.data.cart

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-206 — provides the [CartApi] on the shared Retrofit and binds the cart repository. Kept separate
 * from the catalog wiring so each feature owns its own contract.
 */
@Module
@InstallIn(SingletonComponent::class)
object CartApiModule {

    @Provides
    @Singleton
    fun provideCartApi(retrofit: Retrofit): CartApi =
        retrofit.create(CartApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CartDataModule {

    @Binds
    @Singleton
    abstract fun bindCartRepository(impl: CartRepositoryImpl): CartRepository
}
