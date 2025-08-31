/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  alias(libs.plugins.animalsniffer)
  alias(libs.plugins.dokka)
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.kover)
  alias(libs.plugins.mavenPublish)
  alias(libs.plugins.pitest)
  alias(libs.plugins.spotless)
  alias(libs.plugins.versions)
  alias(libs.plugins.vcu)
}

group = requireNotNull(project.findProperty("GROUP"))

version = requireNotNull(project.findProperty("VERSION_NAME"))

kotlin {
  explicitApi()
  @OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)
  abiValidation { enabled = true }
}

java {
  sourceCompatibility = JavaVersion.VERSION_11
  targetCompatibility = JavaVersion.VERSION_11
}

mavenPublishing {
  publishToMavenCentral(automaticRelease = true)
  signAllPublications()
  @Suppress("UnstableApiUsage") pomFromGradleProperties()
  configure(KotlinJvm(javadocJar = JavadocJar.Dokka("dokkaGenerate"), sourcesJar = true))
}

pitest {
  junit5PluginVersion.set("1.2.3")
  pitestVersion.set("1.20.1")
  avoidCallsTo.set(setOf("kotlin.jvm.internal"))
  mutators.set(setOf("STRONGER"))
  targetClasses.set(setOf("kage.*"))
  targetTests.set(setOf("kage.*"))
  threads.set(Runtime.getRuntime().availableProcessors())
  outputFormats.set(setOf("XML", "HTML"))
  // This is the current level we hit as of introducing pitest. It should never
  // be allowed to regress.
  mutationThreshold.set(73)
  coverageThreshold.set(90)
}

tasks.named("check") { dependsOn("pitest") }

tasks.withType<KotlinCompile>().configureEach {
  compilerOptions {
    moduleName = "kage"
    jvmTarget = JvmTarget.JVM_11
  }
}

tasks.withType<DependencyUpdatesTask>().configureEach {
  fun isNonStable(version: String): Boolean {
    val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { version.uppercase().contains(it) }
    val regex = "^[0-9,.v-]+(-r)?$".toRegex()
    val isStable = stableKeyword || regex.matches(version)
    return isStable.not()
  }
  rejectVersionIf { isNonStable(candidate.version) && !isNonStable(currentVersion) }
  checkForGradleUpdate = false
  checkBuildEnvironmentConstraints = true
}

spotless {
  val ktfmtVersion = "0.58"
  kotlin {
    ktfmt(ktfmtVersion).googleStyle()
    target("**/*.kt")
    targetExclude("**/build/")
    licenseHeaderFile("spotless.license", "package")
  }
  kotlinGradle {
    ktfmt(ktfmtVersion).googleStyle()
    target("**/*.kts")
    licenseHeaderFile("spotless.license", "package |import|enableFeaturePreview")
  }
}

sourceSets { named("main") { java.srcDirs("src/kotlin") } }

dependencies {
  signature(variantOf(libs.animalsniffer.signature.android) { artifactType("signature") })
  implementation(platform(libs.junit.bom))
  implementation(libs.bouncycastle.bcprov)
  implementation(libs.hkdf)
  implementation(libs.kotlinresult)
  pitest(libs.pitest.kotlin)
  testImplementation(libs.junit.jupiter)
  testImplementation(libs.junit.jupiter.api)
  testRuntimeOnly(libs.junit.jupiter.engine)
  testRuntimeOnly(libs.junit.platform.launcher)
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
