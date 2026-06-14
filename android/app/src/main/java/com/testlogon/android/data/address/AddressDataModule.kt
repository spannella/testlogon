package com.testlogon.android.data.address

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-214 — provides the [AddressApi] on the shared Retrofit and binds the address repository.
 */
@Module
@InstallIn(SingletonComponent::class)
object AddressApiModule {

    @Provides
    @Singleton
    fun provideAddressApi(retrofit: Retrofit): AddressApi =
        retrofit.create(AddressApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class AddressDataModule {

    @Binds
    @Singleton
    abstract fun bindAddressRepository(impl: AddressRepositoryImpl): AddressRepository
}
