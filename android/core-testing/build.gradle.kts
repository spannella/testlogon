plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.testlogon.android.core.testing"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core-model"))

    // AND-046: the harness ships in `main` so it is visible to `testImplementation` dependents.
    // Exposed as `api(...)` so any module that adds `testImplementation(project(":core-testing"))`
    // inherits MockWebServer + Retrofit/Moshi/OkHttp without bespoke wiring.
    api(libs.okhttp)
    api(libs.okhttp.mockwebserver)
    api(libs.retrofit)
    api(libs.retrofit.moshi)
    api(libs.moshi)
    api(libs.junit)
    api(libs.coroutines.test)
}
