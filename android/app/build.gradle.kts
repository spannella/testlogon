plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
    alias(libs.plugins.google.services)
}

android {
    namespace = "com.testlogon.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.testlogon.android"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "com.testlogon.android.HiltTestRunner"
        vectorDrawables { useSupportLibrary = true }

        // AND-006 — backend base URL exposed as a compile-time constant.
        // NOTE: product flavors (dev/staging/prod) are intentionally NOT used here; renaming the
        // variants would break `assembleDebug`/`testDebugUnitTest` and our CI scripts. The
        // dev/staging/prod selection is done at RUNTIME via SettingsStore (which seeds from this
        // value and supports an in-app override). Flavors are deferred — see android/README.md.
        // Third arg is literal generated source, so the String needs its own escaped quotes.
        buildConfigField("String", "API_BASE_URL", "\"https://tl-api.bitbazaar.cc/\"")

        // AND-161 — configured helpdesk group id (web uses VITE_HELPDESK_GROUP_ID, default
        // "e2e-helpdesk"). Required `group_id` query param for the helpdesk queue. See AND-161 OQ-5;
        // swap to remote/per-env config when the production group-id scheme is finalized.
        buildConfigField("String", "HELPDESK_GROUP_ID", "\"e2e-helpdesk\"")
        // Diagnostic: when true, forces ICE to use ONLY TURN relay candidates (skips host/srflx).
        // Defaults false (normal ICE — direct path with TURN as fallback); useful on restrictive networks.
        buildConfigField("boolean", "WEBRTC_FORCE_RELAY", "false")
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Core modules
    implementation(project(":core-model"))
    implementation(project(":core-network"))
    implementation(project(":core-data"))
    implementation(project(":core-ui"))
    testImplementation(project(":core-testing"))

    // AndroidX core / lifecycle
    implementation(libs.androidx.core.ktx)
    // AND-114 — per-app locales (AppCompatDelegate.setApplicationLocales) backported to minSdk 24.
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    // AND-145 — ProcessLifecycleOwner for the foreground-bound presence heartbeat.
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    // Coroutines (StateFlow / Flow operators used by the auth router)
    implementation(libs.coroutines.android)

    // Networking (auth DTOs + AuthApi live in the app module's data.auth package)
    implementation(libs.okhttp) // okhttp3.HttpUrl for BaseUrlValidator (AND-041)
    implementation(libs.retrofit)
    implementation(libs.retrofit.moshi)
    implementation(libs.moshi)
    ksp(libs.moshi.codegen)

    // Persistence for the auth state store
    implementation(libs.datastore.preferences)

    // AND-105/106/107/109 — Firebase Cloud Messaging (push).
    // The Firebase BoM aligns the messaging SDK version. The com.google.gms.google-services
    // Gradle plugin is deliberately NOT applied here (see libs.versions.toml): there is no
    // google-services.json in the repo and applying the plugin fails the build. The SDK
    // compiles/links fine without it; runtime init is gated in TestLogonApp.
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)

    // AND-106/109 — WorkManager for deferred push (de)registration retries.
    implementation(libs.androidx.work.runtime)

    // Compose
    implementation(platform(libs.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling)

    // Navigation
    implementation(libs.navigation.compose)
    implementation(libs.hilt.navigation.compose)

    // AND-074 / AND-130: Coil for avatar/cover/message images.
    implementation(libs.coil.compose)

    // ID1: ZXing core (pure-JVM, no Play Services) to render the MFA TOTP otpauth QR client-side.
    implementation(libs.zxing.core)

    // AND-135: animated-GIF / animated-WebP decoder for GIF & custom-emoji messages. Registered on
    // the app ImageLoader (ImageDecoderDecoder on API 28+, GifDecoder on API 24-27).
    implementation(libs.coil.gif)

    // MV2: Coil video-frame decoder so an uploaded video-clip bubble shows a poster (first frame)
    // fetched via the same RelativeUrlMapper-resolved object url.
    implementation(libs.coil.video)

    // AND-131: Media3 / ExoPlayer (+ HLS) for inline video-share playback. The player is created
    // per-screen and lifecycle-scoped (never an eager singleton @Provides).
    implementation(libs.media3.exoplayer)
    implementation(libs.media3.exoplayer.hls)
    implementation(libs.media3.ui)
    // AND-167: OkHttp-backed Media3 DataSource so HLS manifest/segment loads reuse the shared
    // core-network OkHttpClient (cookie jar + ~20s timeouts) instead of DefaultHttpDataSource.
    implementation(libs.media3.datasource.okhttp)

    // AND-085/AND-089: Paging 3 for the notification center list + unread badge.
    implementation(libs.paging.runtime)
    implementation(libs.paging.compose)

    // AND-062: WebAuthn / passkeys via AndroidX Credential Manager.
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play.services.auth)

    // AND-063: SSO / SAML browser handoff via Chrome Custom Tabs.
    implementation(libs.androidx.browser)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.security.crypto)

    // Hilt
    implementation(libs.hilt.android)
    implementation(libs.livekit.android) // WebRTC media engine (livekit.org.webrtc via livekit-webrtc) + LiveKit SDK (sets up audio room #104); ONLY org.webrtc-lineage provider
    ksp(libs.hilt.compiler)

    // Test
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.moshi)
    testImplementation(libs.retrofit)
    testImplementation(libs.retrofit.moshi)
    // AND-062: a JVM-side android.content.Context mock for passkey repository tests.
    testImplementation(libs.mockito.core)
    // AND-090: Paging 3 test harness (TestPager / asSnapshot) for the notifications suite.
    testImplementation(libs.paging.testing)
    // AND-106/109/110: WorkManager TestListenableWorkerBuilder for the push worker tests.
    testImplementation(libs.androidx.work.testing)

    // UI / navigation tests
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.androidx.test.ext)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.core)
    // Force the AndroidX Test 1.7.0 / Espresso 3.7.0 stack (the version compose-ui-test pulls
    // transitively, 3.6.1, calls the hidden InputManager.getInstance() removed in Android 16/API 36).
    androidTestImplementation(libs.espresso.core)
    androidTestImplementation(libs.compose.ui.test.junit4)
    androidTestImplementation(libs.navigation.testing)
    androidTestImplementation(libs.hilt.android.testing)
    kspAndroidTest(libs.hilt.compiler)
    debugImplementation(libs.compose.ui.test.manifest)
}

hilt {
    enableAggregatingTask = false
}
