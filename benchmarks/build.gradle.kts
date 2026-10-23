/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
plugins {
  java
  alias(libs.plugins.jmh)
}

java {
  sourceCompatibility = JavaVersion.VERSION_17
  targetCompatibility = JavaVersion.VERSION_17
}

dependencies { jmhImplementation(project(":")) }

// Package only the selected upstream vectors, not test classes or the rest of the CCTV corpus.
sourceSets.named("jmh") {
  resources {
    srcDir(rootProject.layout.projectDirectory.dir("src/test/resources"))
    include(
      "CCTV/age/testdata/x25519",
      "CCTV/age/testdata/armor_x25519",
      "CCTV/age/testdata/hybrid",
      "CCTV/age/testdata/scrypt",
      "CCTV/age/testdata/stream_empty_payload",
      "CCTV/age/testdata/stream_last_chunk_full",
      "CCTV/age/testdata/stream_two_chunks",
      "CCTV/age/testdata/stream_257_chunks",
    )
  }
}

jmh {
  jmhVersion.set(libs.versions.jmh.get())
  includeTests.set(false)
  benchmarkMode.set(listOf("thrpt"))
  timeUnit.set("s")
  threads.set(1)
  fork.set(1)
  warmupIterations.set(2)
  warmup.set("1s")
  iterations.set(3)
  timeOnIteration.set("1s")
  jvmArgs.set(listOf("-Xms1g", "-Xmx1g"))
  // Reset heap state between iterations so GC pauses do not land in measurement windows.
  forceGC.set(true)
  failOnError.set(true)
  resultFormat.set("JSON")
  providers.gradleProperty("jmhInclude").orNull?.let { includes.set(listOf(it)) }
  providers.gradleProperty("jmhFixture").orNull?.let {
    benchmarkParameters.put(
      "fixtureName",
      objects.listProperty(String::class.java).value(listOf(it)),
    )
  }
}
