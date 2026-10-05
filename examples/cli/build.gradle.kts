/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
  alias(libs.plugins.kotlin.jvm)
  application
}

kotlin {
  compilerOptions { jvmTarget = JvmTarget.JVM_17 }
}

java {
  sourceCompatibility = JavaVersion.VERSION_17
  targetCompatibility = JavaVersion.VERSION_17
}

application {
  mainClass.set("kage.cli.MainKt")
  applicationName = "age"
}

dependencies {
  implementation(project(":"))
  implementation("com.github.ajalt.clikt:clikt:5.1.0")
  testImplementation(platform(libs.junit.bom))
  testImplementation(libs.junit.jupiter)
  testRuntimeOnly(libs.junit.jupiter.engine)
}

tasks.test { useJUnitPlatform() }
