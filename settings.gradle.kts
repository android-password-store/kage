/**
 * Copyright 2021 The kage Authors. All rights reserved.
 * Use of this source code is governed by either an
 * Apache 2.0 or MIT license at your discretion, that can
 * be found in the LICENSE-APACHE or LICENSE-MIT files
 * respectively.
 */
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

enableFeaturePreview("VERSION_CATALOGS")

rootProject.name = "kage"

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
