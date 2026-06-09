package com.testlogon.android.data.locale

import androidx.core.os.ConfigurationCompat
import android.content.Context
import com.testlogon.android.core.model.locale.LocaleTag
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-113 — provides the locale Retrofit API on the shared Retrofit + the device-locale source. */
@Module
@InstallIn(SingletonComponent::class)
object LocaleApiModule {

    @Provides
    @Singleton
    fun provideLocaleApi(retrofit: Retrofit): LocaleApi =
        retrofit.create(LocaleApi::class.java)

    /**
     * Reads the device's primary language from the application Configuration. Uses
     * [ConfigurationCompat] so the locale list is read correctly on minSdk 24.
     */
    @Provides
    @Singleton
    fun provideDeviceLocaleProvider(
        @ApplicationContext context: Context,
    ): DeviceLocaleProvider = DeviceLocaleProvider {
        val locales = ConfigurationCompat.getLocales(context.resources.configuration)
        locales.get(0)?.toLanguageTag()?.let { LocaleTag(it) }
    }
}

/** AND-113 — binds the locale repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class LocaleDataModule {

    @Binds
    @Singleton
    abstract fun bindLocaleRepository(impl: LocaleRepositoryImpl): LocaleRepository
}
