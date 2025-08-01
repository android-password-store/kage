/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "kage"

pluginManagement {
  repositories {
    exclusiveContent {
      forRepository(::gradlePluginPortal)
      filter {
        listOf(
            "ru.vyarus.animalsniffer",
            "org.jetbrains.kotlin.jvm",
            "com.diffplug.spotless",
            "com.github.ben-manes.versions",
            "info.solidsoft.pitest",
          )
          .forEach { plugin -> includeModule(plugin, "${plugin}.gradle.plugin") }
        includeModule("com.github.ben-manes", "gradle-versions-plugin")
        includeModule("info.solidsoft.gradle.pitest", "gradle-pitest-plugin")
      }
    }
    mavenCentral()
  }
}

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
  repositories { mavenCentral() }
}
