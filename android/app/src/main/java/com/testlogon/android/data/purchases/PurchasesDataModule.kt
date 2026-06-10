package com.testlogon.android.data.purchases

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-218 — provides the [PurchasesApi] on the shared Retrofit and binds the purchases repository.
 * No new OkHttpClient / Retrofit / Moshi is constructed; no per-method cookie/CSRF headers are declared.
 */
@Module
@InstallIn(SingletonComponent::class)
object PurchasesApiModule {

    @Provides
    @Singleton
    fun providePurchasesApi(retrofit: Retrofit): PurchasesApi =
        retrofit.create(PurchasesApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PurchasesDataModule {

    @Binds
    @Singleton
    abstract fun bindPurchasesRepository(impl: PurchasesRepositoryImpl): PurchasesRepository
}
