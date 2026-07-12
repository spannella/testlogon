pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // LiveKit (io.livekit:livekit-android, #103/#104) pulls com.github.davidliu:audioswitch,
        // a JitPack-hosted git-hash artifact not on Maven Central. Scoped to that exact group so JitPack
        // never shadows Google/Central coordinates.
        maven("https://jitpack.io") {
            content { includeGroup("com.github.davidliu") }
        }
    }
}

rootProject.name = "testlogon-android"

include(":app")
include(":core-network")
include(":core-model")
include(":core-ui")
include(":core-data")
include(":core-testing")
