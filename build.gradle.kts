/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
import org.gradle.api.tasks.testing.logging.TestLogEvent

@Suppress("DSL_SCOPE_VIOLATION")
plugins {
  alias(libs.plugins.kotlin.jvm)
  alias(libs.plugins.dokka)
  alias(libs.plugins.spotless)
  alias(libs.plugins.animalsniffer)
}

kotlin { explicitApi() }

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
  kotlinOptions { moduleName = "kage" }
}

spotless {
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

tasks.check { finalizedBy(tasks.dokkaHtml) }

sourceSets { named("main") { java.srcDirs("src/kotlin") } }

dependencies {
  signature(libs.animalsniffer.signature.android)
  implementation(libs.hkdf)
  testImplementation(libs.kotlintest.junit)
}

tasks.withType<Test>().configureEach {
  maxParallelForks = Runtime.getRuntime().availableProcessors() * 2
  testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
  outputs.upToDateWhen { false }
}
