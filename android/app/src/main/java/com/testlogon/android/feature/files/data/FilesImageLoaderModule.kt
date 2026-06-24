package com.testlogon.android.feature.files.data

import android.content.Context
import coil.ImageLoader
import coil.decode.ImageDecoderDecoder
import coil.decode.GifDecoder
import coil.map.Mapper
import coil.request.Options
import com.testlogon.android.BuildConfig
import dagger.Module
import dagger.Provides
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import javax.inject.Qualifier
import javax.inject.Singleton

/**
 * #6 (file preview / thumbnails) - an AUTHENTICATED Coil [ImageLoader] for the file manager.
 *
 * The app-wide Coil loader ([com.testlogon.android.TestLogonApp.newImageLoader]) uses Coil's DEFAULT
 * OkHttp client, which carries NO session cookies / Bearer / CSRF. The file-manager image endpoints
 * (`GET /v1/fs/thumbnail`, `GET /v1/fs/preview`, `GET /v1/fs/download`) are cookie-authed
 * (`Depends(_current_user)`), so the default loader gets a 401 and renders nothing.
 *
 * This loader is built on the project's authenticated [OkHttpClient] (the unqualified binding from
 * core-network's NetworkModule - cookie jar + CSRF + Bearer + 401-refresh), so file thumbnails and
 * previews fetch with the user's session. It keeps the SAME server-relative url mapper as the global
 * loader so a path like `/v1/fs/thumbnail?path=...` resolves against `API_BASE_URL`.
 */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class FilesAuthedImageLoader

@Module
@InstallIn(SingletonComponent::class)
object FilesImageLoaderModule {

    @Provides
    @Singleton
    @FilesAuthedImageLoader
    fun provideFilesImageLoader(
        @ApplicationContext context: Context,
        authedClient: OkHttpClient,
    ): ImageLoader = ImageLoader.Builder(context)
        .okHttpClient(authedClient)
        .components {
            add(RelativeUrlMapper(BuildConfig.API_BASE_URL))
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                add(ImageDecoderDecoder.Factory())
            } else {
                add(GifDecoder.Factory())
            }
        }
        .build()

    /** Maps a server-relative url ("/path") to an absolute one under [base]; null (no-op) otherwise. */
    private class RelativeUrlMapper(private val base: String) : Mapper<String, String> {
        override fun map(data: String, options: Options): String? =
            if (data.startsWith("/")) base.trimEnd('/') + data else null
    }
}

/**
 * #6 - lets a @Composable (FilesRoute) read the [FilesAuthedImageLoader] without a ViewModel hop
 * (Coil's `model =` AsyncImage needs the loader instance, and the route already uses hiltViewModel for
 * its VMs). Resolved via [dagger.hilt.android.EntryPointAccessors] from the application component.
 */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface FilesImageLoaderEntryPoint {
    @FilesAuthedImageLoader
    fun filesImageLoader(): ImageLoader
}
