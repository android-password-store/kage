/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import java.io.File
import java.nio.file.Files
import kage.kage.test.utils.TestSuite
import kotlin.test.Test
import kotlin.test.fail

class UpstreamTestSuite {
  private val testFixtureRoot = File("src/test/resources/CCTV/age/testdata")

  @Test
  fun test() {
    Files.newDirectoryStream(testFixtureRoot.toPath()).forEach { path ->
      val contents = path.toFile().readBytes()
      try {
        TestSuite.parse(contents)
      } catch (e: Exception) {
        fail("failed to parse ${path.fileName}", e)
      }
    }
  }
}
