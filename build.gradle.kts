/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

// Workaround for false-positive IDE errors
// From https://youtrack.jetbrains.com/issue/KTIJ-19369#focus=Comments-27-5181027.0-0
@Suppress("DSL_SCOPE_VIOLATION")
plugins {
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.dokka)
  alias(libs.plugins.spotless)
  alias(libs.plugins.animalsniffer)
  alias(libs.plugins.versions)
  alias(libs.plugins.vcu)
}

fun isNonStable(version: String): Boolean {
  val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { version.toUpperCase().contains(it) }
  val regex = "^[0-9,.v-]+(-r)?$".toRegex()
  val isStable = stableKeyword || regex.matches(version)
  return isStable.not()
}

tasks.withType<KotlinCompile> { kotlinOptions { moduleName = "kage" } }

tasks.withType<DependencyUpdatesTask> {
  rejectVersionIf { isNonStable(candidate.version) && !isNonStable(currentVersion) }
  checkForGradleUpdate = false
  checkBuildEnvironmentConstraints = true
}

kotlin { explicitApi() }

spotless {
  val KTFMT_VERSION = "0.41"
  kotlin {
    ktfmt(KTFMT_VERSION).googleStyle()
    target("**/*.kt")
    targetExclude("**/build/")
    licenseHeaderFile("spotless.license", "package")
  }
  kotlinGradle {
    ktfmt(KTFMT_VERSION).googleStyle()
    target("**/*.kts")
    licenseHeaderFile("spotless.license", "package |import|enableFeaturePreview")
  }
}

tasks.check { finalizedBy(tasks.dokkaHtml) }

sourceSets { named("main") { java.srcDirs("src/kotlin") } }

dependencies {
  signature(libs.animalsniffer.signature.android)
  implementation(libs.bouncycastle.bcprov)
  implementation(libs.hkdf)
  implementation(libs.kotlinResult)
  testImplementation(libs.kotlintest.junit)
}

tasks.withType<Test>().configureEach {
  maxParallelForks = Runtime.getRuntime().availableProcessors() * 2
  testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
  outputs.upToDateWhen { false }
}
