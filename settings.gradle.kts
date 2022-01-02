rootProject.name = "kage"

include("lib")

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

enableFeaturePreview("VERSION_CATALOGS")

pluginManagement {
  val kotlinVersion = "1.6.10"
  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
  plugins {
    id("org.jetbrains.kotlin.jvm") version "$kotlinVersion"
    id("com.diffplug.spotless") version "6.1.0"
    id("ru.vyarus.animalsniffer") version "1.5.4" apply false
  }
}

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
  repositories { mavenCentral() }
}
