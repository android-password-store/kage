/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import java.nio.file.Files
import java.nio.file.Paths
import kage.kage.test.utils.TestSuite
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow

class UpstreamTestSuite {
  private val testFixtureRoot = Paths.get("src", "test", "resources", "CCTV", "age", "testdata")

  @Test
  fun test() {
    Files.newDirectoryStream(testFixtureRoot).forEach { path ->
      val contents = path.toFile().readBytes()
      assertDoesNotThrow("failed to parse ${path.fileName}") { TestSuite.parse(contents) }
    }
  }
}
