/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

rootProject.name = "kage"

include(":examples:cli", ":benchmarks")

pluginManagement {
  repositories {
    exclusiveContent {
      forRepository(::gradlePluginPortal)
      filter {
        listOf(
            "ru.vyarus.animalsniffer",
            "me.champeau.jmh",
            "org.jetbrains.kotlin.jvm",
            "com.commonsware.kovergate",
            "com.diffplug.spotless",
            "info.solidsoft.pitest",
            "me.champeau.jmh",
          )
          .forEach { plugin -> includeModule(plugin, "${plugin}.gradle.plugin") }
        includeModule("info.solidsoft.gradle.pitest", "gradle-pitest-plugin")
        includeModule("me.champeau.jmh", "jmh-gradle-plugin")
        includeModule("com.commonsware.kovergate", "kovergate")
        includeModule("me.champeau.jmh", "jmh-gradle-plugin")
      }
    }
    mavenCentral()
  }
}

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
  repositories { mavenCentral() }
}

// Substitute JMH with the CodSpeed fork when the submodule is checked out, so that benchmark
// results can be reported to CodSpeed. Without it, the upstream JMH artifacts are used.
if (file("third-party/codspeed-jvm/jmh-fork/settings.gradle.kts").exists()) {
  includeBuild("third-party/codspeed-jvm/jmh-fork") {
    dependencySubstitution {
      substitute(module("org.openjdk.jmh:jmh-core")).using(project(":jmh-core"))
      substitute(module("org.openjdk.jmh:jmh-generator-annprocess"))
        .using(project(":jmh-generator-annprocess"))
      substitute(module("org.openjdk.jmh:jmh-generator-bytecode"))
        .using(project(":jmh-generator-bytecode"))
    }
  }
}
