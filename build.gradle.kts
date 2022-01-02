/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
import com.diffplug.gradle.spotless.SpotlessExtension
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
  kotlin("jvm")
  id("org.jetbrains.dokka")
  id("com.diffplug.spotless")
  id("ru.vyarus.animalsniffer")
}

kotlin { explicitApi() }

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
  kotlinOptions { moduleName = "kage" }
}

configure<SpotlessExtension> {
  kotlin {
    ktfmt().googleStyle()
    target("**/*.kt")
    targetExclude("**/build/")
    licenseHeaderFile("spotless.license", "package")
  }
  kotlinGradle {
    ktfmt().googleStyle()
    target("**/*.kts")
    licenseHeaderFile("spotless.license", "package |import|enableFeaturePreview")
  }
}

sourceSets { named("main") { java.srcDirs("src/kotlin") } }

dependencies {
  signature("net.sf.androidscents.signature:android-api-level-23:6.0_r3")
  implementation("at.favre.lib:hkdf:1.1.0")
  testImplementation(libs.kotlintest.junit)
}

tasks.withType<Test>().configureEach {
  maxParallelForks = Runtime.getRuntime().availableProcessors() * 2
  testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
  outputs.upToDateWhen { false }
}
