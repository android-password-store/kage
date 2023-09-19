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
  alias(libs.plugins.animalsniffer)
  alias(libs.plugins.dokka)
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.kover)
  alias(libs.plugins.mavenPublish)
  alias(libs.plugins.spotless)
  alias(libs.plugins.versions)
  alias(libs.plugins.vcu)
}

group = requireNotNull(project.findProperty("GROUP"))

version = requireNotNull(project.findProperty("VERSION_NAME"))

fun isNonStable(version: String): Boolean {
  val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { version.toUpperCase().contains(it) }
  val regex = "^[0-9,.v-]+(-r)?$".toRegex()
  val isStable = stableKeyword || regex.matches(version)
  return isStable.not()
}

kotlin { explicitApi() }

java {
  sourceCompatibility = JavaVersion.VERSION_11
  targetCompatibility = JavaVersion.VERSION_11
}

tasks.withType<KotlinCompile>().configureEach {
  kotlinOptions {
    moduleName = "kage"
    jvmTarget = JavaVersion.VERSION_11.toString()
  }
}

tasks.withType<DependencyUpdatesTask> {
  rejectVersionIf { isNonStable(candidate.version) && !isNonStable(currentVersion) }
  checkForGradleUpdate = false
  checkBuildEnvironmentConstraints = true
}

spotless {
  val KTFMT_VERSION = "0.46"
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

sourceSets { named("main") { java.srcDirs("src/kotlin") } }

dependencies {
  signature(libs.animalsniffer.signature.android)
  implementation(libs.bouncycastle.bcprov)
  implementation(libs.hkdf)
  implementation(libs.kotlinresult)
  testImplementation(libs.junit.jupiter)
  testImplementation(libs.truth) { exclude(group = "junit", module = "junit") }
  testRuntimeOnly(libs.junit.legacy) {
    // See https://github.com/google/truth/issues/333
    because("Truth needs it")
  }
}

tasks.withType<Test>().configureEach {
  maxParallelForks = Runtime.getRuntime().availableProcessors() * 2
  testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
  useJUnitPlatform()
}
