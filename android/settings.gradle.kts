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
    }
}

rootProject.name = "testlogon-android"

include(":app")
include(":core-network")
include(":core-model")
include(":core-ui")
include(":core-data")
include(":core-testing")
